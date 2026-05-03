# Authentication in front of signet

signet records *caller-asserted* attribution: every audit row says
"the caller said the owner was X." It does not verify a JWT, OIDC
token, or mTLS client cert on its own — that is intentionally outside
the gate's responsibility (different layer, different blast radius,
different lifecycle).

For deployments where the audit row needs to say "X *cryptographically
authorized* this action" rather than "the caller said X did," put a
real authentication layer in front of signet. This page documents the
three patterns we've seen work in production. Pick whichever matches
your existing identity infrastructure.

In all three patterns, the goal is the same: by the time signet
receives the request, the `X-Commit-Owner` (or `X-Agent-Id`,
`X-Policy-Name`) header reflects an *authenticated* identity, set by
a component the caller cannot tamper with.

---

## Pattern 1: nginx + mTLS (zero-touch for internal services)

Best fit when callers are services in your own infrastructure that
can present an X.509 client certificate signed by your internal CA.

**nginx config** (terminates TLS, validates the client cert, injects
the verified subject as a header that signet trusts):

```nginx
server {
    listen 443 ssl;
    server_name signet-gate.internal;

    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # Require client certificates signed by your internal CA
    ssl_client_certificate /etc/nginx/certs/internal-ca.crt;
    ssl_verify_client      on;
    ssl_verify_depth       2;

    location / {
        # Strip any client-supplied X-Commit-Owner — we ONLY trust
        # what we set from the verified cert subject.
        proxy_set_header X-Commit-Owner "";

        # The verified cert's CN becomes the commit owner.
        # human:<cn> for human-issued certs, agent:<cn> for service certs
        # (distinguish via cert SAN or by separating CAs).
        proxy_set_header X-Commit-Owner "human:$ssl_client_s_dn_cn";

        # Forward everything else, untouched
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # signet runs unprotected on loopback; nginx is the auth boundary
        proxy_pass http://127.0.0.1:8443;
    }
}
```

**signet config**: bind to `127.0.0.1` only so nothing can reach signet
without going through nginx first. Run with the standard pipeline; do
NOT add `LoopbackTrustCheck` (that would let any process on the host
bypass nginx).

```bash
signet serve \
    --upstream http://internal-llm:8000/v1 \
    --host 127.0.0.1 \
    --port 8443 \
    --config pipeline.py \
    --hmac-secret "$SIGNET_HMAC_SECRET" \
    --audit-log /var/log/signet/audit.jsonl
```

**Audit row now reads**: `owner_type=human, owner_id=<verified CN>` —
not a caller assertion, but the result of an mTLS handshake nginx
performed.

---

## Pattern 2: FastAPI middleware + JWT validation (HTTP API gateway)

Best fit when you have a JWT issuer (Auth0, Cognito, Keycloak, your
own) and want to embed signet inside an existing FastAPI/Starlette
application rather than running it as a separate proxy.

```python
"""auth_middleware.py — verify a JWT and write the verified subject
into X-Commit-Owner before signet's pipeline sees the request."""

from __future__ import annotations

import jwt  # pip install pyjwt[crypto]
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from signet.server.app import SignetApp
from signet.server.config import ServerConfig
from signet.core.pipeline import Pipeline
from signet.checks import OwnerResolutionCheck, RateLimitCheck


# Replace with your IdP's JWKS endpoint or static public key
ISSUER_PUBLIC_KEY_PEM = open("/etc/signet/idp-public.pem").read()
ISSUER = "https://your-idp.example.com/"
AUDIENCE = "signet-gate"


class JwtToOwnerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Strip any X-Commit-Owner the caller might have sent — we
        # only trust headers we set from the verified token.
        scrubbed = [
            (k, v) for k, v in request.headers.raw
            if k.lower() not in (b"x-commit-owner", b"x-agent-id", b"x-policy-name")
        ]

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")

        try:
            claims = jwt.decode(
                auth[len("Bearer ") :],
                ISSUER_PUBLIC_KEY_PEM,
                algorithms=["RS256", "ES256"],
                issuer=ISSUER,
                audience=AUDIENCE,
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}")

        # Map JWT subject to a signet owner. Convention: 'human:<sub>'
        # for human-mapped tokens, 'agent:<client_id>' for service-to-
        # service tokens (distinguished via a 'principal_type' claim
        # your IdP sets, or by inspecting the audience/scope claims).
        principal_type = claims.get("principal_type", "human")
        principal_id = claims.get("sub", "")
        scrubbed.append((b"x-commit-owner", f"{principal_type}:{principal_id}".encode()))
        request.scope["headers"] = scrubbed

        return await call_next(request)


# Build signet, add the middleware in front of it
config = ServerConfig(upstream_url="http://internal-llm:8000/v1")
pipeline = Pipeline(checks=[
    OwnerResolutionCheck(require_owner=True),
    RateLimitCheck(capacity=60, refill_per_second=1.0),
])
signet = SignetApp(config=config, pipeline=pipeline)
signet.app.add_middleware(JwtToOwnerMiddleware)

# signet.app is now ready to mount in your existing FastAPI app
# or run via uvicorn directly
```

The middleware runs *before* signet's pipeline, so by the time
`OwnerResolutionCheck` reads `X-Commit-Owner`, the value reflects a
verified JWT subject.

---

## Pattern 3: oauth2-proxy + OIDC (full SSO in front)

Best fit when you have an OIDC IdP (Google Workspace, Okta, Azure AD,
Keycloak) and want users to authenticate through their normal SSO
session rather than presenting bearer tokens explicitly.

[oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) sits in
front of signet, handles the full OIDC flow against your IdP, and
forwards verified user identity as headers.

**oauth2-proxy config** (`oauth2-proxy.cfg`):

```ini
provider = "oidc"
client_id = "signet-gate"
client_secret = "${OAUTH_CLIENT_SECRET}"
oidc_issuer_url = "https://your-idp.example.com/"
cookie_secret = "${OAUTH_COOKIE_SECRET}"

# After successful auth, forward these headers to the upstream (signet)
pass_user_headers = true
set_xauthrequest = true   # sets X-Auth-Request-User, X-Auth-Request-Email

# signet expects the owner on X-Commit-Owner; we'll need a tiny
# header rewrite layer in front of signet (one nginx server block
# can do this, see below).

upstreams = ["http://127.0.0.1:8443/"]
http_address = "0.0.0.0:443"
```

**Header rewrite** (a one-liner nginx in between oauth2-proxy and
signet, or built into oauth2-proxy via the `header_value_replace`
config option in newer versions):

```nginx
location / {
    # Rewrite oauth2-proxy's X-Auth-Request-Email into signet's
    # X-Commit-Owner format
    set $owner "human:$http_x_auth_request_email";
    proxy_set_header X-Commit-Owner $owner;
    proxy_set_header X-Auth-Request-Email "";  # don't leak
    proxy_pass http://127.0.0.1:8443;
}
```

**signet config**: same as Pattern 1 — bind to loopback only, run a
strict pipeline, no `LoopbackTrustCheck`.

---

## After the auth layer is wired

The audit row that previously said:

```json
{"owner_type": "human", "owner_id": "alice@example.com",
 "reason": "owner resolved: human:alice@example.com",
 "metadata": {"source": "human:alice@example.com"}}
```

now means *alice authenticated against your IdP, the IdP issued a
token your auth layer cryptographically verified, and the verified
subject was passed to signet to record.* The audit row's text is the
same; the trust behind it is now real.

Pair this with [signet's anchor backends](../architecture.md) for
external tamper-evidence and you have a complete chain: authenticated
identity → policy decision → cryptographically anchored audit row.

## What this still doesn't solve

- **Token theft.** If alice's bearer token is stolen, every audit row
  written under it is incorrectly attributed. That's a token-lifecycle
  problem (short TTLs, refresh rotation, IdP-side revocation), not
  signet's. Same for stolen mTLS keys.
- **Insider threats by the auth-layer operator.** Whoever owns
  oauth2-proxy / nginx can set whatever owner header they like. signet
  trusts the auth layer; the auth layer is now part of the TCB.
- **Cross-tenant isolation in shared deployments.** If multiple
  tenants share one signet instance, you need a tenant-scoping check
  that verifies the JWT's tenant claim matches the request scope. That
  is custom-policy territory — write it as a plugin against the
  `Check` protocol.

For deployments where these residual concerns matter (regulated
industries, high-value tool authority), engagement with a vendor
maintaining the full identity → audit → anchor → compliance pipeline
(Thornveil or your preferred provider) is appropriate.
