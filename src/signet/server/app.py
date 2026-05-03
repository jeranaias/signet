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

import hashlib
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

        @self.app.post("/v1/completions")
        async def completions(request: Request) -> Response:
            return await self._handle_completions(request)

        @self.app.post("/v1/embeddings")
        async def embeddings(request: Request) -> Response:
            return await self._handle_embeddings(request)

        # Explicit refusal for OpenAI endpoints we do NOT yet gate.
        # /v1/audio/* and /v1/images/* are deferred because their
        # request shapes (binary uploads, multi-part forms) don't fit
        # the JSON-body assumptions baked into the pipeline's check
        # surface. Adding them is roadmap for v0.2 and they will need
        # their own check protocols (vision-aware checks, audio
        # transcript checks, etc.).
        @self.app.api_route(
            "/v1/{path:path}",
            methods=["POST", "GET", "PUT", "DELETE", "PATCH"],
        )
        async def unsupported_v1(path: str) -> Response:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "endpoint not implemented in signet v0.1.3",
                    "endpoint": f"/v1/{path}",
                    "note": (
                        "v0.1.3 gates /v1/chat/completions, /v1/completions, "
                        "and /v1/embeddings. /v1/audio/* and /v1/images/* are "
                        "roadmapped — their non-JSON request shapes need "
                        "their own check protocols and aren't a copy-paste "
                        "addition."
                    ),
                },
            )

    async def _admit(self, request: Request, *, path: str) -> Response | RequestContext:
        """Shared body-read + JSON-parse + admission-pipeline preamble.

        Returns either a Response (caller should return immediately
        because admission refused/escalated/errored) or the populated
        RequestContext to proceed with forwarding.
        """
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

        if not raw:
            return JSONResponse(
                status_code=400,
                content={"error": "empty request body"},
            )

        try:
            body = json.loads(raw)
        except json.JSONDecodeError as e:
            return JSONResponse(
                status_code=400,
                content={"error": f"invalid JSON in request body: {e}"},
            )

        headers = dict(request.headers.items())
        client_ip = request.client.host if request.client else None
        session_id = headers.get(SESSION_HEADER) or headers.get(SESSION_HEADER.lower())
        request_fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest() if raw else ""

        ctx = RequestContext(
            owner=Owner.unresolved(),
            headers=headers,
            body=body,
            path=path,
            client_ip=client_ip,
            session_id=session_id,
        )
        ctx.scratch["_request_fingerprint"] = request_fingerprint

        if session_id:
            session = self.session_store.get_or_create(session_id)
            session.touch()
            self.session_store.save(session)
            ctx.scratch["_session"] = session

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

        return ctx

    async def _handle_chat(self, request: Request) -> Response:
        admitted = await self._admit(request, path="/v1/chat/completions")
        if isinstance(admitted, Response):
            return admitted
        ctx = admitted

        is_stream = bool(ctx.body.get("stream", False))
        try:
            if is_stream:
                return await self._forward_stream(ctx, "/chat/completions")
            return await self._forward_unary(ctx, "/chat/completions")
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

    async def _handle_completions(self, request: Request) -> Response:
        """Legacy /v1/completions endpoint (text completion, pre-chat).

        Same pipeline shape as chat completions. The response body
        differs (``choices[].text`` instead of ``choices[].message``);
        ScopeDriftCheck and similar text-scanning checks read from
        ``ResponseContext.accumulated_text`` and work uniformly.
        """
        admitted = await self._admit(request, path="/v1/completions")
        if isinstance(admitted, Response):
            return admitted
        ctx = admitted

        is_stream = bool(ctx.body.get("stream", False))
        try:
            if is_stream:
                return await self._forward_stream(ctx, "/completions")
            return await self._forward_unary(
                ctx, "/completions", content_path=("choices", 0, "text")
            )
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

    async def _handle_embeddings(self, request: Request) -> Response:
        """Embeddings endpoint — non-streaming, no INSPECTION text content.

        ADMISSION runs (owner, classification, rate limit, regex on
        input strings) and RECORD runs (token-budget reconciliation
        from upstream usage). INSPECTION-stage checks that scan
        accumulated output text are skipped — embeddings have no text
        output to scan. Tool-call-inspector (COMMITMENT) is also
        skipped — embeddings don't emit tool calls.
        """
        admitted = await self._admit(request, path="/v1/embeddings")
        if isinstance(admitted, Response):
            return admitted
        ctx = admitted

        try:
            return await self._forward_unary(
                ctx, "/embeddings", content_path=None, skip_inspection_text=True
            )
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
        """Swap the last user-message text content for ``replacement``.

        Best-effort: REDACT is intended for input-side checks
        (``RegexContentCheck``) where the offending pattern lives in the
        most recent user message. If your check needs to redact in a
        different shape, return BLOCK and let the caller re-issue with
        the correction; OSS does not pretend to know your full message
        graph.

        Multimodal handling: when the last user message uses the
        OpenAI vision shape (``content`` is a list of ``{"type": ...}``
        parts), only the **text** parts are replaced. Image and audio
        parts pass through untouched — dropping them would silently
        change request semantics far beyond what a redact decision
        promises.
        """
        if replacement is None:
            return body
        out = dict(body)
        messages = list(body.get("messages", ()))
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if not (isinstance(msg, dict) and msg.get("role") == "user"):
                continue
            new_msg = dict(msg)
            content = msg.get("content")
            if isinstance(content, str):
                new_msg["content"] = replacement
            elif isinstance(content, list):
                # Vision-style: keep non-text parts (images, audio) intact
                new_parts: list[Any] = []
                replaced_any = False
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        if not replaced_any:
                            new_parts.append({"type": "text", "text": replacement})
                            replaced_any = True
                        # Subsequent text parts are dropped — the single
                        # replacement covers all redacted text.
                    else:
                        new_parts.append(part)
                if not replaced_any:
                    # No text parts existed; prepend the replacement so the
                    # redaction is at least represented in the message.
                    new_parts.insert(0, {"type": "text", "text": replacement})
                new_msg["content"] = new_parts
            else:
                # Unknown content shape — replace wholesale rather than
                # leave the offending pattern in place.
                new_msg["content"] = replacement
            messages[i] = new_msg
            break
        out["messages"] = messages
        return out

    async def _forward_unary(
        self,
        ctx: RequestContext,
        upstream_path: str = "/chat/completions",
        *,
        content_path: tuple[Any, ...] | None = ("choices", 0, "message", "content"),
        skip_inspection_text: bool = False,
    ) -> Response:
        """Forward a non-streaming request to the upstream.

        ``upstream_path`` is appended to ``ServerConfig.upstream_url``.
        ``content_path`` walks the upstream response to find the text
        that RECORD-stage checks should see in
        ``ResponseContext.accumulated_text``. Default targets the
        chat-completions shape; pass ``("choices", 0, "text")`` for
        legacy /completions. Pass ``None`` (with
        ``skip_inspection_text=True``) for endpoints with no text
        output (embeddings).
        """
        client = self._ensure_http()
        upstream_resp = await client.post(
            f"{self.config.upstream_url.rstrip('/')}{upstream_path}",
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

        rctx = ResponseContext(request=ctx)
        rctx.usage = data.get("usage", {})
        rctx.finish_reason = (
            data.get("choices", [{}])[0].get("finish_reason") if data.get("choices") else None
        )
        if not skip_inspection_text and content_path is not None:
            text = _walk_path(data, content_path)
            if isinstance(text, str):
                rctx.extend_text(text)
        rctx.chunk_count = 1

        record_results = await self.pipeline.post_complete(rctx)

        # Each non-allow RECORD result becomes its own audit row so the
        # specific check name and metadata survive into the chain.
        # The aggregate "request completed" row is always written so
        # consumers can pivot from request → entries via fingerprint.
        for record_result in record_results:
            if not record_result.is_allow:
                self._record_decision(
                    ctx,
                    result=record_result,
                    check_name=record_result.metadata.get("_check_name", "pipeline.record"),
                )

        entry = self._record_decision(
            ctx,
            result=None,
            check_name="pipeline.complete",
            metadata={
                "finish_reason": rctx.finish_reason,
                "tokens": rctx.usage,
                "accumulated_text_truncated": rctx.accumulated_text_truncated,
            },
        )
        headers = self._upstream_attribution_headers(upstream_resp.status_code)
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(content=data, status_code=upstream_resp.status_code, headers=headers)

    async def _forward_stream(
        self,
        ctx: RequestContext,
        upstream_path: str = "/chat/completions",
    ) -> StreamingResponse:
        rctx = ResponseContext(request=ctx)

        async def event_stream() -> AsyncIterator[bytes]:
            client = self._ensure_http()
            completed_normally = False
            inspection_aborted = False
            try:
                async with client.stream(
                    "POST",
                    f"{self.config.upstream_url.rstrip('/')}{upstream_path}",
                    json=ctx.body,
                    headers=self._upstream_headers(ctx),
                ) as upstream:
                    async for raw_chunk in upstream.aiter_bytes():
                        rctx.chunk_count += 1
                        chunk_text = raw_chunk.decode("utf-8", errors="replace")
                        # extend_text enforces the per-response cap so a
                        # multi-megabyte stream cannot OOM the proxy.
                        rctx.extend_text(_extract_sse_content(chunk_text))

                        inspection = await self.pipeline.inspect_response_chunk(rctx, chunk_text)
                        if not inspection.is_allow:
                            # Abort the stream with a trailer event.
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
                            self._record_decision(
                                ctx,
                                result=inspection,
                                check_name="pipeline.inspection",
                            )
                            inspection_aborted = True
                            return

                        yield raw_chunk

                rctx.finish_reason = rctx.finish_reason or "stop"
                completed_normally = True
            finally:
                # Two reasons we land here without completed_normally:
                # 1. The caller disconnected mid-stream and the
                #    StreamingResponse cancelled the generator.
                # 2. The upstream raised after we already started
                #    yielding (the outer 502 path is too late —
                #    bytes were already on the wire).
                # In both cases we still want exactly one terminal row
                # in the chain so audit consumers can see the request
                # ended and how. inspection_aborted already wrote its
                # own row — don't double-count. Avoid `return` in
                # finally (would swallow in-flight exceptions); guard
                # the body instead.
                if not inspection_aborted:
                    if not completed_normally:
                        rctx.finish_reason = rctx.finish_reason or "client_disconnect"
                    # Run RECORD checks even on disconnect — they may flag
                    # cumulative drift, partial-output PII, etc.
                    try:
                        record_results = await self.pipeline.post_complete(rctx)
                    except Exception:
                        logger.exception("pipeline.post_complete crashed")
                        record_results = []
                    for record_result in record_results:
                        if not record_result.is_allow:
                            self._record_decision(
                                ctx,
                                result=record_result,
                                check_name=record_result.metadata.get(
                                    "_check_name", "pipeline.record"
                                ),
                            )
                    self._record_decision(
                        ctx,
                        result=None,
                        check_name="pipeline.complete",
                        metadata={
                            "finish_reason": rctx.finish_reason,
                            "accumulated_text_truncated": rctx.accumulated_text_truncated,
                            "chunk_count": rctx.chunk_count,
                        },
                    )

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            # Receipt and per-row chain entries can't be set on a
            # streaming response (no entry exists yet), but the upstream
            # attribution headers can fire at handshake time so callers
            # see them before they parse a single chunk.
            headers=self._upstream_attribution_headers(None),
        )

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

    def _upstream_attribution_headers(self, upstream_status: int | None) -> dict[str, str]:
        """Headers that let callers tell upstream errors from signet errors.

        Set on every forwarded response. ``X-Signet-Upstream`` carries
        either the configured label or the upstream URL host.
        ``X-Signet-Upstream-Status`` carries the upstream's HTTP status
        when known so a 500 the user sees can be unambiguously
        attributed to the upstream rather than to the gate.
        """
        from urllib.parse import urlparse

        label = self.config.upstream_label or urlparse(self.config.upstream_url).netloc
        out: dict[str, str] = {"X-Signet-Upstream": label}
        if upstream_status is not None:
            out["X-Signet-Upstream-Status"] = str(upstream_status)
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

        # Refusals never reach the upstream, so X-Signet-Upstream-Status
        # is omitted; X-Signet-Upstream still fires so consumers can
        # confirm the gate-of-record.
        headers = self._upstream_attribution_headers(None)
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
        headers = self._upstream_attribution_headers(None)
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
            request_fingerprint=ctx.scratch.get("_request_fingerprint", ""),
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
            request_fingerprint=ctx.scratch.get("_request_fingerprint", ""),
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


def _walk_path(data: Any, path: tuple[Any, ...]) -> Any:
    """Walk a (key, key, ...) path through nested dict/list, returning ``None``
    if any step is missing or the wrong type. Used by :meth:`_forward_unary`
    to extract the response text from upstreams of different shapes
    (chat → choices[0].message.content, completions → choices[0].text)."""
    cur = data
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and 0 <= key < len(cur):
            cur = cur[key]
        else:
            return None
        if cur is None:
            return None
    return cur


def _extract_sse_content(chunk_text: str) -> str:
    """Pull the content text out of OpenAI-shaped SSE 'data:' frames.

    Best-effort. Used only to feed checks like ScopeDriftCheck that
    scan accumulated output text. Non-content frames return empty string.

    Per the WHATWG EventSource spec, multiple consecutive ``data:``
    lines within a single event get joined with ``\\n`` before being
    delivered. OpenAI ships one event per data line so this almost
    never matters in practice, but other OpenAI-compatible upstreams
    (LiteLLM, vLLM with prompt-streaming) do emit multi-line events.
    Coalesce them so INSPECTION sees the full text.
    """
    out: list[str] = []
    pending: list[str] = []  # data: lines for the current event

    def _flush_event() -> None:
        if not pending:
            return
        payload = "\n".join(pending)
        pending.clear()
        if payload in ("[DONE]", ""):
            return
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            return
        for choice in obj.get("choices", []):
            delta = choice.get("delta", {})
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                out.append(delta["content"])

    for raw_line in chunk_text.splitlines():
        # Per spec, a blank line dispatches the pending event.
        if raw_line.strip() == "":
            _flush_event()
            continue
        if not raw_line.startswith("data:"):
            continue
        # Per spec: strip a single leading space after the colon, not
        # arbitrary whitespace; preserve any further leading whitespace
        # in the payload.
        payload_line = raw_line[len("data:") :]
        if payload_line.startswith(" "):
            payload_line = payload_line[1:]
        pending.append(payload_line)
    _flush_event()
    return "".join(out)
