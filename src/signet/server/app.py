"""SignetApp — the FastAPI application that ties everything together.

The proxy serves these endpoints:

* ``GET /health`` (alias ``/healthz``) — liveness probe with operational
  metadata: signet version, uptime, audit-chain head HMAC tail,
  configured pipeline check count.
* ``GET /readyz`` — readiness probe; HEADs the configured upstream with
  a 1-second timeout. 503 when upstream is unreachable so k8s sheds
  traffic. Distinct from ``/health`` so liveness restarts don't fire on
  an upstream blip.
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
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import JSONResponse, StreamingResponse

from signet import __version__
from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.core.audit import AuditEntry, Decision
from signet.core.context import RequestContext, ResponseContext, get_header_ci
from signet.core.owner import Owner
from signet.core.pipeline import Pipeline
from signet.server.config import ServerConfig
from signet.server.metrics import Metrics
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
        metrics: Metrics | None = None,
    ) -> None:
        self.config = config
        self.pipeline = pipeline
        self.session_store: SessionStore = session_store or InMemorySessionStore()
        self.metrics: Metrics = metrics or Metrics()
        # Wire the per-check duration histogram in. The Pipeline keeps
        # ``metrics`` optional so it stays usable in CLI / test contexts
        # without an HTTP server; here we attach the SignetApp's
        # registry so /metrics exposes the same observations the proxy
        # is making. Only override an unset observer so callers who
        # passed in their own remain in control.
        if getattr(self.pipeline, "_metrics", None) is None:
            self.pipeline._metrics = self.metrics

        self._keyring = self._build_keyring(config)
        self._chain = self._build_chain(config, self._keyring)
        # ``receipt_signer`` lets callers swap in their own (e.g. ed25519)
        # without touching SignetApp internals. Default is the built-in
        # HMAC-SHA256 signer over the same key as the audit chain.
        if not config.emit_receipts:
            self._receipt_signer: ReceiptSigner | None = None
        else:
            self._receipt_signer = receipt_signer or HmacReceiptSigner(self._keyring)

        # Wall-clock start time, used by /health to report uptime. Set
        # at construction so the value is meaningful even when the app
        # is mounted into a parent FastAPI without going through our
        # lifespan handler.
        import time as _time

        self._started_at = _time.time()

        self.app = FastAPI(
            title="signet",
            version=__version__,
            description="Capability-based safety gate for LLM agents.",
            lifespan=self._lifespan,
        )
        self._register_cors()
        self._register_routes()

    def _register_cors(self) -> None:
        """Add CORSMiddleware when ``cors_allowed_origins`` is set.

        Skipped when the tuple is empty (default), so non-browser
        deployments incur zero CORS overhead.
        """
        origins = self.config.cors_allowed_origins
        if not origins:
            return
        from fastapi.middleware.cors import CORSMiddleware

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=list(origins),
            allow_methods=list(self.config.cors_allowed_methods),
            allow_headers=list(self.config.cors_allowed_headers),
            allow_credentials=self.config.cors_allow_credentials,
            expose_headers=[
                self.config.receipt_header_name,
                "X-Signet-Upstream",
                "X-Signet-Upstream-Status",
            ],
        )

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
        """Open + close the upstream HTTP client across the app lifetime.

        Graceful shutdown: on lifespan exit (SIGTERM, etc.), wait up
        to ``ServerConfig.shutdown_grace_seconds`` for in-flight
        streams to drain before tearing down the upstream client.
        Streams that haven't completed by the deadline are abandoned;
        their audit rows are still written by the streaming generator's
        finally block.
        """
        # Idempotent: if _http already exists (e.g. TestClient triggered
        # this twice, or _ensure_http was called first), reuse it.
        self._ensure_http()
        # Track in-flight streaming requests so shutdown can drain.
        self._in_flight_streams = 0
        try:
            yield
        finally:
            grace = self.config.shutdown_grace_seconds
            if grace > 0 and self._in_flight_streams > 0:
                logger.info(
                    "shutdown: waiting up to %.1fs for %d in-flight streams to drain",
                    grace,
                    self._in_flight_streams,
                )
                import asyncio
                import time as _time

                deadline = _time.monotonic() + grace
                while self._in_flight_streams > 0 and _time.monotonic() < deadline:
                    await asyncio.sleep(0.1)
                if self._in_flight_streams > 0:
                    logger.warning(
                        "shutdown: %d streams still in flight after grace period; abandoning",
                        self._in_flight_streams,
                    )
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
        async def _health_payload() -> dict[str, Any]:
            """Build the /health body. Lightweight, no I/O."""
            import time as _time

            uptime = max(0.0, _time.time() - self._started_at)
            payload: dict[str, Any] = {
                "status": "ok",
                "service": "signet",
                "version": __version__,
                "uptime_seconds": round(uptime, 3),
                "pipeline_check_count": len(self.pipeline.checks),
                # Shadow flag is always emitted (True or False) so
                # operators tail /health and confirm at-a-glance whether
                # the gate is enforcing or piloting. Three-state
                # disambiguation isn't needed here: shadow is a boolean
                # config knob, not a runtime-derived value.
                "shadow": bool(self.config.shadow),
            }
            # Audit-chain head: last 8 hex of the most recent entry's
            # HMAC, so monitoring can detect "alive but not writing"
            # without dumping the secret. The field has three distinct
            # states so monitors can disambiguate operator intent from
            # transient runtime state:
            #
            # * ``"disabled"`` — no chain configured (``audit_log_path``
            #   was not set). Operator chose to run without an audit
            #   chain; not an alert condition.
            # * ``None`` — chain is configured but currently empty. May
            #   be a startup race (no requests yet) or a failed write;
            #   monitors can flag prolonged ``None`` as suspect.
            # * ``"<8-hex-tail>"`` — chain has at least one entry. Tail
            #   advances as the chain grows; a stalled tail under load
            #   means the chain stopped writing.
            if self._chain is None:
                payload["audit_chain_head_hmac"] = "disabled"
            else:
                head = self._chain._read_prev_hmac()
                payload["audit_chain_head_hmac"] = head[-8:] if head else None
            return payload

        @self.app.get("/health")
        async def health() -> dict[str, Any]:
            """Liveness + lightweight operational metadata.

            See module docstring for the full payload shape. Always
            returns 200; kubernetes will restart the pod if this stops
            answering at all.
            """
            return await _health_payload()

        @self.app.get("/healthz")
        async def healthz() -> dict[str, Any]:
            """Alias of ``/health`` matching the k8s/cloud-native idiom."""
            return await _health_payload()

        @self.app.get("/readyz")
        async def readyz() -> Response:
            """Readiness probe: probes the configured upstream.

            Returns 200 when the upstream answers within 1s, 503 with a
            structured body otherwise. k8s should wire this to the
            readiness probe so traffic is shed when the upstream is
            unreachable but the pod itself is healthy. Distinct from
            ``/health`` so a flaky upstream doesn't trigger a liveness
            restart loop.
            """
            client = self._ensure_http()
            url = self.config.upstream_url.rstrip("/") + "/models"
            try:
                resp = await client.get(url, timeout=1.0)
            except httpx.HTTPError as exc:
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "not_ready",
                        "reason": f"upstream unreachable: {type(exc).__name__}",
                        "upstream": self.config.upstream_label or self.config.upstream_url,
                    },
                )
            if resp.status_code >= 500:
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "not_ready",
                        "reason": f"upstream returned {resp.status_code}",
                        "upstream": self.config.upstream_label or self.config.upstream_url,
                        "upstream_status": resp.status_code,
                    },
                )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ready",
                    "upstream_status": resp.status_code,
                },
            )

        @self.app.get("/version")
        async def version() -> dict[str, str]:
            return {"version": __version__, "service": "signet"}

        @self.app.get("/metrics")
        async def metrics() -> Response:
            """Prometheus exposition-format counters.

            See :mod:`signet.server.metrics` for the counter set.
            Output is plain text; scrape with the standard Prometheus
            scrape config or any Prometheus-compatible collector
            (Grafana Agent, VictoriaMetrics, OpenTelemetry collector
            with the prometheus receiver, etc.).
            """
            return Response(
                content=self.metrics.render_prometheus(),
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )

        @self.app.post("/v1/chat/completions")
        async def chat_completions(request: Request) -> Response:
            return await self._handle_chat(request)

        @self.app.post("/v1/completions")
        async def completions(request: Request) -> Response:
            return await self._handle_completions(request)

        @self.app.post("/v1/embeddings")
        async def embeddings(request: Request) -> Response:
            return await self._handle_embeddings(request)

        # WebSocket pass-through for the OpenAI realtime API. ADMISSION
        # runs once at connect time. COMMITMENT runs on every function-
        # call event during the session. RECORD writes session-start +
        # periodic flush + session-end audit rows. INSPECTION runs on
        # text chunks; audio frames pass through with metadata-only
        # audit rows (no transcription in 0.1.6). See
        # :mod:`signet.server.realtime` and ``docs/realtime.md`` for
        # the full state machine and wire contract.
        if self.config.realtime_enabled:

            @self.app.websocket("/v1/realtime")
            async def realtime_websocket(websocket: WebSocket) -> None:
                await self._handle_realtime(websocket)

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

        Shadow-mode boundary: when ``self.config.shadow`` is True, a
        non-allow ADMISSION result does NOT short-circuit to
        ``_refusal``/``_escalation``. Instead the audit row is still
        written (with ``metadata.shadow=True``), the
        ``signet_shadow_would_have_blocked_total`` counter increments,
        a set of ``X-Signet-Shadow-*`` headers is stashed on
        ``ctx.scratch["_shadow_headers"]``, and the request continues
        to the upstream as if it had been allowed. The forward path
        merges those headers into the eventual response. The audit
        chain remains the source of truth for what the gate would
        have done; shadow mode only neutralizes the response layer.
        Use this to pilot signet against production traffic before
        flipping enforcement on.
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
        # Starlette typically lowercases header names but proxies may not;
        # use get_header_ci so any case variant resolves.
        session_id = get_header_ci(headers, SESSION_HEADER) or None
        request_fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest() if raw else ""

        ctx = RequestContext(
            owner=Owner.unresolved(),
            headers=headers,
            body=body,
            path=path,
            method=request.method,
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
            if self.config.shadow:
                self._stash_shadow_headers(ctx, result, entry, decision="block")
                return ctx
            return self._refusal(result, entry)
        if result.is_escalate:
            entry = self._record_decision(ctx, result=result, check_name="pipeline.admission")
            if self.config.shadow:
                self._stash_shadow_headers(ctx, result, entry, decision="escalate")
                return ctx
            return self._escalation(result, entry)
        if result.is_redact:
            if self.config.shadow:
                # Shadow neutralizes redact too: body passes through
                # unmodified so behavior is genuinely unchanged. The
                # audit row already recorded what *would* have been
                # redacted (the pipeline annotates result.metadata).
                # Surface the would-be redaction via headers and the
                # shadow counter so dashboards see the volume.
                entry = self._record_decision(
                    ctx, result=result, check_name="pipeline.admission"
                )
                self._stash_shadow_headers(ctx, result, entry, decision="redact")
            else:
                ctx.body = self._apply_redaction(ctx.body, result.replacement_content)

        return ctx

    async def _handle_chat(self, request: Request) -> Response:
        self.metrics.inc("signet_requests_total", {"path": "/v1/chat/completions"})
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
        self.metrics.inc("signet_requests_total", {"path": "/v1/completions"})
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

    async def _handle_realtime(self, websocket: WebSocket) -> None:
        """Drive the OpenAI realtime API WebSocket session.

        The route handler is intentionally a thin shim: the
        per-connection state machine lives in
        :class:`signet.server.realtime.RealtimeHandler` so the
        WebSocket logic does not bloat this module. The handler
        receives a back-reference to ``self`` so it can reuse the
        shared helpers (``_record_decision``, ``_stash_shadow_headers``,
        ``_record_exception``, the pipeline, the keyring) — no
        parallel implementation, single source of truth on audit row
        shape and shadow handling.
        """
        from signet.server.realtime import RealtimeHandler

        self.metrics.inc("signet_requests_total", {"path": "/v1/realtime"})
        handler = RealtimeHandler(self, websocket)
        await handler.run()

    async def _handle_embeddings(self, request: Request) -> Response:
        """Embeddings endpoint — non-streaming, no INSPECTION text content.

        ADMISSION runs (owner, classification, rate limit, regex on
        input strings) and RECORD runs (token-budget reconciliation
        from upstream usage). INSPECTION-stage checks that scan
        accumulated output text are skipped — embeddings have no text
        output to scan. Tool-call-inspector (COMMITMENT) is also
        skipped — embeddings don't emit tool calls.
        """
        self.metrics.inc("signet_requests_total", {"path": "/v1/embeddings"})
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
        # Merge any X-Signet-Shadow-* headers stashed by _admit (or by
        # a RECORD-stage shadow neutralization above). They describe the
        # would-be refusal so callers can see what shadow caught even
        # though the response body is the upstream's.
        shadow_headers = ctx.scratch.get("_shadow_headers")
        if shadow_headers:
            headers.update(shadow_headers)
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
            upstream_aborted = False
            # Bump in-flight counter so graceful shutdown waits for us.
            # getattr handles the embedded-app case where _lifespan
            # never ran (e.g. mounting SignetApp.app inside a parent
            # FastAPI app that owns its own lifespan).
            if not hasattr(self, "_in_flight_streams"):
                self._in_flight_streams = 0
            self._in_flight_streams += 1
            try:
                async with client.stream(
                    "POST",
                    f"{self.config.upstream_url.rstrip('/')}{upstream_path}",
                    json=ctx.body,
                    headers=self._upstream_headers(ctx),
                ) as upstream:
                    # Upstream-status guard: a 5xx (or any non-2xx) means
                    # the upstream is broken mid-handshake or about to
                    # ship an error body. Emit a structured abort frame
                    # so the SDK sees a parseable terminal frame rather
                    # than an opaque error body or a hung stream. We
                    # deliberately don't try to forward the upstream's
                    # error body — different upstreams shape errors
                    # differently and a half-mixed stream is harder for
                    # SDKs to handle than a clean signet-abort.
                    if upstream.status_code >= 400:
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_error"
                        async for frame in self._emit_upstream_error_abort(
                            ctx,
                            rctx,
                            upstream_status=upstream.status_code,
                            reason_detail=f"upstream returned {upstream.status_code}",
                        ):
                            yield frame
                        return

                    try:
                        async for raw_chunk in upstream.aiter_bytes():
                            rctx.chunk_count += 1
                            chunk_text = raw_chunk.decode("utf-8", errors="replace")
                            # extend_text enforces the per-response cap so a
                            # multi-megabyte stream cannot OOM the proxy.
                            rctx.extend_text(_extract_sse_content(chunk_text))

                            inspection = await self.pipeline.inspect_response_chunk(
                                rctx, chunk_text
                            )
                            if not inspection.is_allow:
                                if self.config.shadow:
                                    # Shadow mode: do NOT abort. Record the
                                    # would-have-blocked decision in the
                                    # audit chain (with shadow=True) and let
                                    # the chunk pass through. Streaming
                                    # responses cannot retroactively add
                                    # response headers (they were sent at
                                    # handshake), so the per-block
                                    # X-Signet-Shadow-* headers cannot reach
                                    # the caller for INSPECTION-stage
                                    # decisions; the audit chain remains the
                                    # source of truth and operators correlate
                                    # via the timestamps + request
                                    # fingerprint. The handshake-time header
                                    # ``X-Signet-Shadow-Inspection-Active:
                                    # 1`` tells callers shadow inspection is
                                    # running so they should consult the
                                    # chain for any neutralized decisions.
                                    self._record_decision(
                                        ctx,
                                        result=inspection,
                                        check_name="pipeline.inspection",
                                    )
                                    ctx.scratch["_shadow_inspection_count"] = (
                                        ctx.scratch.get("_shadow_inspection_count", 0) + 1
                                    )
                                    yield raw_chunk
                                    continue
                                # Non-shadow INSPECTION block: do NOT
                                # forward the offending chunk. Record
                                # the decision first so we have an
                                # entry_id to put in correlation_id.
                                rctx.finish_reason = "abort"
                                entry = self._record_decision(
                                    ctx,
                                    result=inspection,
                                    check_name="pipeline.inspection",
                                    metadata={
                                        # chunks_delivered = how many
                                        # passed through to the client
                                        # before this one. The blocking
                                        # chunk itself is counted in
                                        # rctx.chunk_count (we bumped
                                        # before inspecting) but is NOT
                                        # delivered.
                                        "chunks_delivered": rctx.chunk_count - 1,
                                        "chunk_count_at_abort": rctx.chunk_count,
                                        "abort_stage": "inspection",
                                    },
                                )
                                for frame in self._build_abort_frames(
                                    reason=inspection.reason,
                                    stage="inspection",
                                    check_name=inspection.metadata.get("_check_name"),
                                    entry=entry,
                                ):
                                    yield frame
                                inspection_aborted = True
                                return

                            yield raw_chunk
                    except (httpx.RemoteProtocolError, httpx.ReadError) as exc:
                        # Upstream tore down the stream or shipped
                        # malformed bytes after the headers. We have
                        # already streamed some chunks to the client (or
                        # at least committed to a 200), so emit an
                        # abort frame so the SDK sees a clean terminal
                        # event instead of a hung connection.
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_protocol_violation"
                        async for frame in self._emit_upstream_error_abort(
                            ctx,
                            rctx,
                            upstream_status=upstream.status_code,
                            reason_detail=(
                                f"upstream protocol violation: "
                                f"{type(exc).__name__}: {exc}"
                            ),
                        ):
                            yield frame
                        return

                rctx.finish_reason = rctx.finish_reason or "stop"
                completed_normally = True
            finally:
                # Three reasons we land here without completed_normally:
                # 1. The caller disconnected mid-stream and the
                #    StreamingResponse cancelled the generator.
                # 2. The upstream raised after we already started
                #    yielding (the outer 502 path is too late —
                #    bytes were already on the wire).
                # 3. The upstream returned a 5xx or shipped malformed
                #    SSE; we already emitted a structured abort frame
                #    and recorded the row in
                #    ``_emit_upstream_error_abort``.
                # In all cases we still want exactly one terminal row
                # in the chain so audit consumers can see the request
                # ended and how. inspection_aborted/upstream_aborted
                # already wrote their own rows — don't double-count.
                # Avoid `return` in finally (would swallow in-flight
                # exceptions); guard the body instead.
                if not inspection_aborted and not upstream_aborted:
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
                # Decrement in-flight counter outside the inspection
                # branch so it always fires whether we completed
                # normally, were aborted, or the caller disconnected.
                self._in_flight_streams = max(0, self._in_flight_streams - 1)

        # Receipt and per-row chain entries can't be set on a streaming
        # response (no entry exists yet), but the upstream attribution
        # headers + any X-Signet-Shadow-* headers stashed by _admit fire
        # at handshake time so callers see them before they parse a
        # single chunk.
        #
        # Limitation: INSPECTION-stage shadow decisions detected during
        # the stream cannot retroactively add response headers (HTTP
        # response headers ship before the stream body). For streaming
        # callers, the audit chain is the source of truth on neutralized
        # mid-stream decisions. The handshake-time header
        # ``X-Signet-Shadow-Inspection-Active: 1`` advertises that shadow
        # is running so callers know to consult the chain.
        stream_headers = self._upstream_attribution_headers(None)
        shadow_headers = ctx.scratch.get("_shadow_headers")
        if shadow_headers:
            stream_headers.update(shadow_headers)
        if self.config.shadow:
            stream_headers["X-Signet-Shadow-Inspection-Active"] = "1"
        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers=stream_headers,
        )

    def _build_abort_frames(
        self,
        *,
        reason: str,
        stage: str,
        check_name: str | None,
        entry: AuditEntry | None,
    ) -> list[bytes]:
        """Build the structured SSE abort-frame pair.

        Wire format (see ``docs/streaming.md``)::

            data: {"signet_abort": true,
                   "reason": "<reason>",
                   "correlation_id": "<entry_id>",
                   "stage": "<stage>",
                   "check": "<check_name>"}\\n\\n
            data: [DONE]\\n\\n

        Strict-redaction rule: when
        ``self.config.strict_error_redaction`` is on, ``reason`` is
        coarsened to the literal string ``"refused"`` and the ``check``
        field is omitted entirely — same coarsening
        :meth:`_refusal` applies to 4xx response bodies. Operators
        recover the full detail from the audit row via
        ``correlation_id``. ``correlation_id`` and ``stage`` always
        survive coarsening because they're structural (incident
        response can't pivot without them) rather than
        policy-revealing.
        """
        if self.config.strict_error_redaction:
            payload: dict[str, Any] = {
                "signet_abort": True,
                "reason": "refused",
                "stage": stage,
            }
        else:
            payload = {
                "signet_abort": True,
                "reason": reason,
                "stage": stage,
            }
            if check_name:
                payload["check"] = str(check_name)
        if entry is not None:
            payload["correlation_id"] = entry.entry_id
        else:
            # Audit chain disabled (no audit_log_path). Surface this so
            # the SDK can distinguish "no chain" from "chain entry
            # write failed".
            payload["correlation_id"] = None
        return [
            b"data: " + json.dumps(payload).encode("utf-8") + b"\n\n",
            b"data: [DONE]\n\n",
        ]

    async def _emit_upstream_error_abort(
        self,
        ctx: RequestContext,
        rctx: ResponseContext,
        *,
        upstream_status: int,
        reason_detail: str,
    ) -> AsyncIterator[bytes]:
        """Yield the abort-frame pair for an upstream malformation/5xx.

        Records a synthetic audit row tagged with the upstream status
        and the verbatim error detail, then yields the structured
        SSE abort frame followed by ``data: [DONE]``. The audit row's
        ``check_name`` is ``"pipeline.upstream"`` so dashboards can
        distinguish proxy-side aborts (INSPECTION block) from
        upstream-failure aborts.

        Frame ``reason`` is the stable token
        ``"upstream_protocol_violation"`` so SDKs can match against it
        without parsing the trailing detail string. Detail is logged in
        the audit row for incident review, not in the wire frame.
        """
        # Build a synthetic CheckResult-shape so _record_decision
        # treats this as a non-allow with stage metadata; we want
        # signet_pipeline_decisions_total to fire so dashboards see
        # upstream-induced aborts in the same panel as INSPECTION
        # blocks.
        from signet.core.check import CheckResult

        synthetic = CheckResult.block(
            reason_detail,
            _check_name="pipeline.upstream",
            _stage="inspection",
            upstream_status=upstream_status,
        )
        entry = self._record_decision(
            ctx,
            result=synthetic,
            check_name="pipeline.upstream",
            metadata={
                "chunks_delivered": rctx.chunk_count,
                "chunk_count_at_abort": rctx.chunk_count,
                "abort_stage": "upstream",
                "upstream_status": upstream_status,
            },
        )
        for frame in self._build_abort_frames(
            reason="upstream_protocol_violation",
            stage="inspection",
            # No firing check — the upstream itself failed. Strict
            # mode would omit this anyway; verbose-mode SDKs see
            # check absent rather than misleading.
            check_name=None,
            entry=entry,
        ):
            yield frame

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
        """Translate a BLOCK CheckResult into the appropriate HTTP error.

        Body shape depends on :attr:`ServerConfig.strict_error_redaction`:

        * **Strict (default)**: ``{"error": "refused",
          "correlation_id": "<entry_id>"}``. The check name, reason,
          stage, and rule are intentionally absent — full detail lives
          in the audit chain. Incident response uses the correlation
          ID to look up the row.
        * **Verbose** (``--no-strict-error-redaction`` / ``--dev``):
          full detail, the historical v0.1.4 shape — useful when
          integrating with signet for the first time.
        """
        status = 403
        if "rate limit" in result.reason.lower():
            status = 429

        if self.config.strict_error_redaction:
            body: dict[str, Any] = {
                "error": "refused",
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            # Retry-After is operational, not security-relevant — keep
            # it in the strict body so well-behaved clients can back off.
            if "retry_after_seconds" in result.metadata:
                body["retry_after_seconds"] = result.metadata["retry_after_seconds"]
        else:
            body = {
                "error": "signet refused this request",
                "reason": result.reason,
                "check": result.metadata.get("_check_name"),
                "stage": result.metadata.get("_stage"),
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            if "retry_after_seconds" in result.metadata:
                body["retry_after_seconds"] = result.metadata["retry_after_seconds"]

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

        Body shape obeys :attr:`ServerConfig.strict_error_redaction`,
        same as :meth:`_refusal`.
        """
        if self.config.strict_error_redaction:
            body: dict[str, Any] = {
                "status": "escalated",
                "correlation_id": entry.entry_id if entry is not None else None,
            }
        else:
            body = {
                "status": "escalated",
                "reason": result.reason,
                "check": result.metadata.get("_check_name"),
                "stage": result.metadata.get("_stage"),
                "audit_entry_id": entry.entry_id if entry is not None else None,
                "correlation_id": entry.entry_id if entry is not None else None,
            }
        headers = self._upstream_attribution_headers(None)
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(status_code=202, content=body, headers=headers)

    def _stash_shadow_headers(
        self,
        ctx: RequestContext,
        result: Any,
        entry: AuditEntry | None,
        *,
        decision: str,
    ) -> None:
        """Build the ``X-Signet-Shadow-*`` header set and stash it on ctx.

        Called from the admit + inspection paths whenever a non-allow
        decision is neutralized by shadow mode. The forward path
        (:meth:`_forward_unary` / :meth:`_forward_stream`) merges the
        stashed headers into the eventual response.

        Headers emitted:

        * ``X-Signet-Shadow-Decision`` — block / escalate / redact.
        * ``X-Signet-Shadow-Reason`` — coarsened to ``"refused"`` when
          ``strict_error_redaction`` is on (matches the redaction rule
          that ``_refusal``/``_escalation`` apply to body content); the
          full reason otherwise.
        * ``X-Signet-Shadow-Stage`` — admission / inspection /
          commitment / record (read from the result metadata).
        * ``X-Signet-Shadow-Check`` — the firing check name
          (``_check_name`` from the result metadata, omitted in strict
          mode for the same reason ``_refusal`` redacts it from the
          body).
        * ``X-Signet-Correlation-Id`` — the audit entry ID. Operators
          pivot from response → audit row via this ID.
        """
        headers: dict[str, str] = ctx.scratch.setdefault("_shadow_headers", {})
        headers["X-Signet-Shadow-Decision"] = decision
        if self.config.strict_error_redaction:
            headers["X-Signet-Shadow-Reason"] = "refused"
        else:
            headers["X-Signet-Shadow-Reason"] = result.reason
            check_name = result.metadata.get("_check_name")
            if check_name:
                headers["X-Signet-Shadow-Check"] = str(check_name)
        stage = result.metadata.get("_stage")
        if stage:
            headers["X-Signet-Shadow-Stage"] = str(stage)
        if entry is not None:
            headers["X-Signet-Correlation-Id"] = entry.entry_id

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

        Shadow mode: when ``self.config.shadow`` is True and
        ``result`` is a non-allow CheckResult, ``meta["shadow"] = True``
        is stamped on the audit row and the
        ``signet_shadow_would_have_blocked_total`` counter increments
        with the same {check, stage, decision} label set as
        ``signet_pipeline_decisions_total`` so dashboards can join the
        two. The decision recorded in the chain remains the original
        (block / escalate / redact) — shadow only changes what the
        response layer does, never what the chain says.
        """
        decision = _result_to_decision(result)
        # Always tally pipeline decisions, even when no audit chain
        # is configured (developer mode, ephemeral runs).
        self.metrics.inc(
            "signet_pipeline_decisions_total",
            {"check": check_name, "decision": decision.value},
        )
        is_shadowed = (
            self.config.shadow
            and result is not None
            and not result.is_allow
        )
        if is_shadowed:
            stage = ""
            try:
                stage = str(result.metadata.get("_stage", ""))
            except AttributeError:  # pragma: no cover — defensive
                stage = ""
            self.metrics.inc(
                "signet_shadow_would_have_blocked_total",
                {
                    "check": check_name,
                    "stage": stage,
                    "decision": decision.value,
                },
            )
        if self._chain is None:
            return None
        reason = result.reason if result is not None else "request completed"
        meta = dict(metadata or {})
        if result is not None:
            meta.update(result.metadata)
        if is_shadowed:
            meta["shadow"] = True
        entry = AuditEntry(
            owner=ctx.owner,
            check_name=check_name,
            decision=decision,
            reason=reason,
            metadata=meta,
            request_fingerprint=ctx.scratch.get("_request_fingerprint", ""),
        )
        appended = self._chain.append(entry)
        self.metrics.inc("signet_audit_chain_appends_total")
        # If anchor backend is configured and reported a failure on
        # this entry, count it so operators can alert on anchor SLO.
        from signet.audit.anchor import ANCHOR_FIELD

        anchor_meta = appended.metadata.get(ANCHOR_FIELD, {})
        if isinstance(anchor_meta, dict) and anchor_meta.get("success") is False:
            self.metrics.inc(
                "signet_audit_anchor_failures_total",
                {"backend": str(anchor_meta.get("backend", "unknown"))},
            )
        return appended

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
