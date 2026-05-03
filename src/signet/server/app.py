"""SignetApp — the FastAPI application that ties everything together.

The proxy serves three endpoints:

* ``GET /health`` — liveness probe.
* ``GET /version`` — build identifier.
* ``POST /v1/chat/completions`` — the protected forwarding endpoint.

The chat-completions handler runs the configured pipeline at the
appropriate hook timings:

1. Build :class:`RequestContext` from the inbound request.
2. Call ``pipeline.pre_request(ctx)``. If non-allow → refuse with
   the appropriate HTTP status.
3. Forward the (possibly redacted) body to the upstream. Stream or
   non-stream per the request's ``stream`` field.
4. For streaming responses, on each upstream chunk:
   - Update :class:`ResponseContext`.
   - Call ``pipeline.inspect_response_chunk(rctx, chunk)``. If non-allow
     → abort the stream and emit a trailer event.
   - Otherwise yield the chunk to the caller.
5. After the response completes, call ``pipeline.post_complete(rctx)``
   to run RECORD-stage checks.
6. Write an audit entry; sign and emit ``X-Signet-Receipt``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from signet import __version__
from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.core.audit import AuditEntry, Decision
from signet.core.context import RequestContext, ResponseContext
from signet.core.owner import Owner
from signet.core.pipeline import Pipeline
from signet.server.config import ServerConfig
from signet.server.receipt import HmacReceiptSigner, ReceiptSigner
from signet.server.session import HEADER_NAME as SESSION_HEADER
from signet.server.session import InMemorySessionStore, SessionStore

logger = logging.getLogger("signet.server")


class SignetApp:
    """Build and own the FastAPI application.

    Construct with a :class:`ServerConfig` and a :class:`Pipeline`.
    Optionally pass a custom :class:`SessionStore`; otherwise an
    in-memory store is used.

    Use :attr:`app` to mount or run the underlying FastAPI instance.
    """

    def __init__(
        self,
        *,
        config: ServerConfig,
        pipeline: Pipeline,
        session_store: SessionStore | None = None,
        receipt_signer: ReceiptSigner | None = None,
    ) -> None:
        self.config = config
        self.pipeline = pipeline
        self.session_store: SessionStore = session_store or InMemorySessionStore()

        self._keyring = self._build_keyring(config)
        self._chain = self._build_chain(config, self._keyring)
        # ``receipt_signer`` lets callers swap in their own (e.g. ed25519)
        # without touching SignetApp internals. Default is the built-in
        # HMAC-SHA256 signer over the same key as the audit chain.
        if not config.emit_receipts:
            self._receipt_signer: ReceiptSigner | None = None
        else:
            self._receipt_signer = receipt_signer or HmacReceiptSigner(self._keyring)

        self.app = FastAPI(
            title="signet",
            version=__version__,
            description="Capability-based safety gate for LLM agents.",
            lifespan=self._lifespan,
        )
        self._register_routes()

    @staticmethod
    def _build_keyring(config: ServerConfig) -> KeyRing:
        if config.hmac_secret is not None:
            return KeyRing(active=Key(key_id=config.hmac_key_id, secret=config.hmac_secret))
        if config.allow_ephemeral_key:
            logger.warning(
                "no HMAC secret configured; generating an ephemeral key. "
                "Audit chain will not verify across restarts. "
                "Set SIGNET_HMAC_SECRET (hex) for production."
            )
            return KeyRing(active=Key.generate(config.hmac_key_id))
        raise ValueError(
            "ServerConfig.hmac_secret is required (or set allow_ephemeral_key=True for dev)"
        )

    @staticmethod
    def _build_chain(config: ServerConfig, keyring: KeyRing) -> HmacChain | None:
        if config.audit_log_path is None:
            return None
        backend = JsonlBackend(config.audit_log_path)
        return HmacChain(backend=backend, keyring=keyring)

    @asynccontextmanager
    async def _lifespan(self, _: FastAPI) -> AsyncIterator[None]:
        """Open + close the upstream HTTP client across the app lifetime."""
        # Idempotent: if _http already exists (e.g. TestClient triggered
        # this twice, or _ensure_http was called first), reuse it.
        self._ensure_http()
        try:
            yield
        finally:
            await self._http.aclose()
            del self._http

    def _ensure_http(self) -> httpx.AsyncClient:
        """Lazily create the upstream HTTP client. Used inside handlers so
        TestClient doesn't have to drive the lifespan to get a working app
        (FastAPI's TestClient supports lifespan but not every embedding
        does)."""
        existing: httpx.AsyncClient | None = getattr(self, "_http", None)
        if existing is not None:
            return existing
        timeout = httpx.Timeout(self.config.request_timeout_s, connect=10.0)
        client = httpx.AsyncClient(timeout=timeout)
        self._http = client
        return client

    def _register_routes(self) -> None:
        @self.app.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "ok"}

        @self.app.get("/version")
        async def version() -> dict[str, str]:
            return {"version": __version__, "service": "signet"}

        @self.app.post("/v1/chat/completions")
        async def chat_completions(request: Request) -> Response:
            return await self._handle_chat(request)

        # Explicit refusal for OpenAI endpoints we do NOT yet gate.
        # Without this, requests would 404 with FastAPI's generic body
        # and callers would assume the proxy is broken. Spelling it out
        # is honest about scope.
        @self.app.api_route(
            "/v1/{path:path}",
            methods=["POST", "GET", "PUT", "DELETE", "PATCH"],
        )
        async def unsupported_v1(path: str) -> Response:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "endpoint not implemented in signet v0.1",
                    "endpoint": f"/v1/{path}",
                    "note": (
                        "v0.1 only gates POST /v1/chat/completions. "
                        "Other OpenAI endpoints (embeddings, completions, "
                        "audio, images) are roadmapped."
                    ),
                },
            )

    async def _handle_chat(self, request: Request) -> Response:
        # 1. Read body with explicit size cap. Reject before parsing so a
        # 10 GB junk POST cannot OOM the proxy.
        try:
            raw = await self._read_capped_body(request)
        except _BodyTooLarge as exc:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "request body exceeds max-bytes",
                    "limit_bytes": exc.limit,
                },
            )

        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError as e:
            return JSONResponse(
                status_code=400,
                content={"error": f"invalid JSON in request body: {e}"},
            )

        # Build RequestContext. Owner starts unresolved; the
        # OwnerResolutionCheck (or LoopbackTrustCheck before it) populates it.
        headers = dict(request.headers.items())
        client_ip = request.client.host if request.client else None
        session_id = headers.get(SESSION_HEADER) or headers.get(SESSION_HEADER.lower())

        ctx = RequestContext(
            owner=Owner.unresolved(),
            headers=headers,
            body=body,
            path="/v1/chat/completions",
            client_ip=client_ip,
            session_id=session_id,
        )

        # 2. ADMISSION pipeline. Outcomes:
        #   ALLOW    → forward
        #   REDACT   → forward with replacement_content swapped into body
        #   BLOCK    → 403/429 to caller, audit row with decision=BLOCK
        #   ESCALATE → 202 Accepted; audit row with decision=ESCALATE.
        #              The caller's responsibility is to poll/wait for a
        #              human approval that this proxy does not orchestrate;
        #              orchestration belongs in a higher-level system.
        try:
            result = await self.pipeline.pre_request(ctx)
        except Exception as exc:
            self._record_exception(ctx, exc, check_name="pipeline.admission")
            logger.exception("pipeline.pre_request crashed")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "signet pipeline crashed during admission",
                    "exception": type(exc).__name__,
                },
            )

        if result.is_block:
            entry = self._record_decision(ctx, result=result, check_name="pipeline.admission")
            return self._refusal(result, entry)
        if result.is_escalate:
            entry = self._record_decision(ctx, result=result, check_name="pipeline.admission")
            return self._escalation(result, entry)
        if result.is_redact:
            ctx.body = self._apply_redaction(ctx.body, result.replacement_content)

        # 3. Forward (stream-aware)
        is_stream = bool(body.get("stream", False))
        try:
            if is_stream:
                return await self._forward_stream(ctx)
            return await self._forward_unary(ctx)
        except Exception as exc:
            self._record_exception(ctx, exc, check_name="pipeline.forward")
            logger.exception("upstream forward crashed")
            return JSONResponse(
                status_code=502,
                content={
                    "error": "upstream forward failed",
                    "exception": type(exc).__name__,
                },
            )

    async def _read_capped_body(self, request: Request) -> bytes:
        """Stream the request body, refusing once it exceeds the cap.

        Trusting the ``Content-Length`` header is not sufficient — a
        chunked-transfer client can send unbounded data without a length.
        We accumulate and check after each chunk.
        """
        limit = self.config.max_request_body_bytes
        chunks: list[bytes] = []
        total = 0
        async for piece in request.stream():
            total += len(piece)
            if total > limit:
                raise _BodyTooLarge(limit)
            chunks.append(piece)
        return b"".join(chunks)

    @staticmethod
    def _apply_redaction(body: dict[str, Any], replacement: str | None) -> dict[str, Any]:
        """Swap the last user-message content for ``replacement``.

        Best-effort: REDACT is intended for input-side checks
        (``RegexContentCheck``) where the offending pattern lives in the
        most recent user message. If your check needs to redact in a
        different shape, return BLOCK and let the caller re-issue with
        the correction; OSS does not pretend to know your full message
        graph.
        """
        if replacement is None:
            return body
        out = dict(body)
        messages = list(body.get("messages", ()))
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if isinstance(msg, dict) and msg.get("role") == "user":
                new_msg = dict(msg)
                new_msg["content"] = replacement
                messages[i] = new_msg
                break
        out["messages"] = messages
        return out

    async def _forward_unary(self, ctx: RequestContext) -> Response:
        client = self._ensure_http()
        upstream_resp = await client.post(
            f"{self.config.upstream_url.rstrip('/')}/chat/completions",
            json=ctx.body,
            headers=self._upstream_headers(ctx),
        )
        try:
            data = upstream_resp.json()
        except json.JSONDecodeError:
            return Response(
                status_code=502,
                content=upstream_resp.content,
                media_type=upstream_resp.headers.get("content-type", "text/plain"),
            )

        # Build a ResponseContext from the upstream usage + content
        rctx = ResponseContext(request=ctx)
        rctx.usage = data.get("usage", {})
        rctx.finish_reason = (
            data.get("choices", [{}])[0].get("finish_reason") if data.get("choices") else None
        )
        # Accumulate the text for any post-complete checks that scan it
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        if isinstance(msg.get("content"), str):
            rctx.accumulated_text = msg["content"]
        rctx.chunk_count = 1

        await self.pipeline.post_complete(rctx)

        entry = self._record_decision(
            ctx,
            result=None,  # post-complete already ran; record an aggregate allow
            check_name="pipeline.complete",
            metadata={"finish_reason": rctx.finish_reason, "tokens": rctx.usage},
        )
        headers = {}
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(content=data, status_code=upstream_resp.status_code, headers=headers)

    async def _forward_stream(self, ctx: RequestContext) -> StreamingResponse:
        rctx = ResponseContext(request=ctx)

        async def event_stream() -> AsyncIterator[bytes]:
            client = self._ensure_http()
            async with client.stream(
                "POST",
                f"{self.config.upstream_url.rstrip('/')}/chat/completions",
                json=ctx.body,
                headers=self._upstream_headers(ctx),
            ) as upstream:
                async for raw_chunk in upstream.aiter_bytes():
                    rctx.chunk_count += 1
                    chunk_text = raw_chunk.decode("utf-8", errors="replace")
                    # Best-effort accumulator for SSE 'data:' frames
                    rctx.accumulated_text += _extract_sse_content(chunk_text)

                    inspection = await self.pipeline.inspect_response_chunk(rctx, chunk_text)
                    if not inspection.is_allow:
                        # Abort the stream with a trailer event
                        yield (
                            b"data: "
                            + json.dumps(
                                {
                                    "signet_aborted": True,
                                    "reason": inspection.reason,
                                    "check": inspection.metadata.get("_check_name"),
                                }
                            ).encode("utf-8")
                            + b"\n\n"
                        )
                        yield b"data: [DONE]\n\n"
                        rctx.finish_reason = "abort"
                        await self.pipeline.post_complete(rctx)
                        self._record_decision(
                            ctx,
                            result=inspection,
                            check_name="pipeline.inspection",
                        )
                        return

                    yield raw_chunk

            rctx.finish_reason = rctx.finish_reason or "stop"
            await self.pipeline.post_complete(rctx)
            self._record_decision(ctx, result=None, check_name="pipeline.complete")

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    def _upstream_headers(self, ctx: RequestContext) -> dict[str, str]:
        """Headers to forward to the upstream. Strip signet-only headers."""
        out: dict[str, str] = {}
        for h in self.config.extra_forward_headers:
            if (v := ctx.headers.get(h)) or (v := ctx.headers.get(h.lower())):
                out[h] = v
        if self.config.upstream_api_key and "Authorization" not in out:
            out["Authorization"] = f"Bearer {self.config.upstream_api_key}"
        out["Content-Type"] = "application/json"
        return out

    def _refusal(self, result: Any, entry: AuditEntry | None) -> Response:
        """Translate a BLOCK CheckResult into the appropriate HTTP error."""
        body = {
            "error": "signet refused this request",
            "reason": result.reason,
            "check": result.metadata.get("_check_name"),
            "stage": result.metadata.get("_stage"),
        }
        if "retry_after_seconds" in result.metadata:
            body["retry_after_seconds"] = result.metadata["retry_after_seconds"]

        status = 403
        if "rate limit" in result.reason.lower():
            status = 429

        headers = {}
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(status_code=status, content=body, headers=headers)

    def _escalation(self, result: Any, entry: AuditEntry | None) -> Response:
        """Translate an ESCALATE CheckResult into ``202 Accepted``.

        202 is the right status: the gate received the request, did not
        forward it, and is awaiting an out-of-band approval that signet
        does not orchestrate. The caller (or a higher-level system) is
        responsible for the approval workflow and resubmitting.
        """
        body = {
            "status": "escalated",
            "reason": result.reason,
            "check": result.metadata.get("_check_name"),
            "stage": result.metadata.get("_stage"),
            "audit_entry_id": entry.entry_id if entry is not None else None,
        }
        headers = {}
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(status_code=202, content=body, headers=headers)

    def _record_decision(
        self,
        ctx: RequestContext,
        *,
        result: Any,
        check_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry | None:
        """Persist one audit row.

        Maps the four CheckResult outcomes to the four Decision values
        one-to-one — earlier versions collapsed REDACT/ESCALATE into
        BLOCK, which lost information needed for incident review.
        """
        if self._chain is None:
            return None
        decision = _result_to_decision(result)
        reason = result.reason if result is not None else "request completed"
        meta = dict(metadata or {})
        if result is not None:
            meta.update(result.metadata)
        entry = AuditEntry(
            owner=ctx.owner,
            check_name=check_name,
            decision=decision,
            reason=reason,
            metadata=meta,
        )
        return self._chain.append(entry)

    def _record_exception(
        self,
        ctx: RequestContext,
        exc: BaseException,
        *,
        check_name: str,
    ) -> AuditEntry | None:
        """Persist a synthetic audit row when the pipeline crashes.

        Audit consumers downstream rely on every request producing at
        least one row; an unhandled exception leaving the chain silent
        is itself a security-relevant gap.
        """
        if self._chain is None:
            return None
        entry = AuditEntry(
            owner=ctx.owner,
            check_name=check_name,
            decision=Decision.BLOCK,
            reason=f"pipeline raised {type(exc).__name__}: {exc}",
            metadata={
                "_exception_class": type(exc).__name__,
                "_exception_message": str(exc),
            },
        )
        return self._chain.append(entry)


class _BodyTooLarge(Exception):
    """Raised when the inbound request body exceeds the configured cap."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"request body exceeds {limit} bytes")
        self.limit = limit


def _result_to_decision(result: Any) -> Decision:
    """Map a CheckResult-or-None to the corresponding Decision."""
    if result is None or result.is_allow:
        return Decision.ALLOW
    if result.is_block:
        return Decision.BLOCK
    if result.is_redact:
        return Decision.REDACT
    if result.is_escalate:
        return Decision.ESCALATE
    return Decision.BLOCK  # fail closed if a future Decision is added without a mapping


def _extract_sse_content(chunk_text: str) -> str:
    """Pull the content text out of OpenAI-shaped SSE 'data:' frames.

    Best-effort. Used only to feed checks like ScopeDriftCheck that
    scan accumulated output text. Non-content frames return empty string.
    """
    out: list[str] = []
    for line in chunk_text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:") :].strip()
        if payload in ("[DONE]", ""):
            continue
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            continue
        for choice in obj.get("choices", []):
            delta = choice.get("delta", {})
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                out.append(delta["content"])
    return "".join(out)
