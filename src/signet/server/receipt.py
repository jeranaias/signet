"""ReceiptSigner — emit X-Signet-Receipt headers callers can verify offline.

Every response signet returns carries a *decision receipt* — a short
signed summary of what the gate did with the request. Callers can:

1. Hand the receipt to an auditor as proof the gate ran.
2. Verify the receipt against the signing key, confirming the response
   did pass through a known signet instance.
3. Reconstruct the receipt later from the audit log to prove
   non-tampering.

Receipt format (HTTP header value):

    signet=v1; alg=<alg>; entry=<entry_id>; key=<key_id>; sig=<hex_sig>

* ``v1`` — wire version. Bump if the canonicalization or fields change.
* ``alg`` — signing algorithm. ``hmac-sha256`` (the only built-in)
  ships in v0.1. The field exists explicitly so adding asymmetric
  signers later cannot trigger a downgrade attack against verifiers
  that pinned the algorithm.
* ``entry`` — audit row UUID this receipt covers.
* ``key`` — opaque signing-key ID; the verifier uses it to look up the
  key on its own keyring.
* ``sig`` — hex signature over the canonical entry payload.

Symmetry caveat — the built-in :class:`HmacReceiptSigner` uses a
**symmetric** primitive (HMAC-SHA256). Any party capable of *verifying*
a receipt holds the secret needed to *forge* one. That is fine when the
verifier is the same trust domain as the proxy (your own auditor). It
is **not** fine when you want to hand receipts to outside parties
(customers, regulators) and have them be unforgeable by anyone but the
proxy. Asymmetric signers (ed25519) are roadmapped for v0.2; until then,
either keep verification inside your trust boundary or implement
:class:`ReceiptSigner` against a primitive of your choice and pass it
to :class:`signet.server.app.SignetApp`.

This module is signing-only; verification logic lives in
:meth:`HmacReceiptSigner.verify` for symmetry but the canonical chain
verifier in :mod:`signet.audit.verifier` is the recommended path for
any audit walk longer than one entry.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Protocol

from signet.audit.chain import _serialize_for_signing
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry

#: Wire version embedded in every receipt header.
RECEIPT_VERSION = "v1"

#: Algorithm tag for the built-in HMAC-SHA256 signer.
ALG_HMAC_SHA256 = "hmac-sha256"

#: Header value template. Order is fixed so receipts are byte-stable
#: across runs given the same inputs. Parsers must be tolerant to extra
#: ``;``-separated fields a future version might add.
_HEADER_FORMAT = "signet={ver}; alg={alg}; entry={entry}; key={key}; sig={sig}"

#: Canonical header name the proxy sets. Configurable in ServerConfig.
DEFAULT_HEADER_NAME = "X-Signet-Receipt"


class ReceiptSigner(Protocol):
    """Protocol every receipt signer implements.

    Implement this if you want to use an asymmetric primitive (ed25519,
    RSA-PSS) instead of the built-in HMAC. ``alg`` must be a stable,
    distinct identifier — verifiers reject receipts whose ``alg`` does
    not match what they expect.
    """

    @property
    def alg(self) -> str: ...

    def sign(self, entry: AuditEntry) -> str: ...

    def verify(self, header_value: str, entry: AuditEntry) -> bool: ...


class HmacReceiptSigner:
    """HMAC-SHA256 signer.

    Construct with the same :class:`KeyRing` used by the audit chain.
    The signer always uses the ring's *active* key; verifiers can hold
    a ring with multiple legacy keys to verify older receipts after a
    rotation.

    See module docstring for the symmetric-primitive caveat.
    """

    alg = ALG_HMAC_SHA256

    def __init__(self, keyring: KeyRing) -> None:
        self._keyring = keyring

    def sign(self, entry: AuditEntry) -> str:
        """Return a header value for the given audit entry.

        Pass an entry that has already been written to the audit chain
        so verifiers can correlate the receipt with chain state.
        """
        active = self._keyring.active
        payload = _serialize_for_signing(entry)
        sig = hmac.new(active.secret, payload, hashlib.sha256).hexdigest()
        return _HEADER_FORMAT.format(
            ver=RECEIPT_VERSION,
            alg=self.alg,
            entry=entry.entry_id,
            key=active.key_id,
            sig=sig,
        )

    def verify(self, header_value: str, entry: AuditEntry) -> bool:
        """Return ``True`` iff the receipt matches ``entry`` under
        this signer's algorithm and a key on the ring.

        Rejects (returns False) when:

        * the header is malformed or version != v1
        * the header's ``alg`` is not ``hmac-sha256``
        * the entry-id mismatches
        * the key-id is unknown to the ring
        * the signature does not match (constant-time compare)
        """
        parsed = parse_header(header_value)
        if parsed is None:
            return False
        if parsed.get("alg") != self.alg:
            return False
        if parsed["entry"] != entry.entry_id:
            return False
        key = self._keyring.get(parsed["key"])
        if key is None:
            return False
        payload = _serialize_for_signing(entry)
        expected = hmac.new(key.secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, parsed["sig"])


def parse_header(value: str) -> dict[str, str] | None:
    """Best-effort parse of an ``X-Signet-Receipt`` header value.

    Accepts the canonical
    ``signet=v1; alg=<alg>; entry=...; key=...; sig=...`` shape and
    tolerates extra ``;``-separated fields the future may add.

    Backward compatibility: receipts emitted before the ``alg`` field
    existed (pre-v0.1.0 dev builds) are accepted and reported as
    ``alg = "hmac-sha256"`` — that was the only algorithm that ever
    shipped without an explicit tag. Reject if you want strict.

    Returns ``None`` when required fields are absent or the version
    is not v1.
    """
    fields: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        fields[k.strip()] = v.strip()
    if fields.get("signet") != RECEIPT_VERSION:
        return None
    if not all(k in fields for k in ("entry", "key", "sig")):
        return None
    fields.setdefault("alg", ALG_HMAC_SHA256)
    return fields
