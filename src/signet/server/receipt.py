"""ReceiptSigner — emit X-Signet-Receipt headers callers can verify offline.

Every response signet returns carries a *decision receipt* — a short,
HMAC-signed summary of what the gate did with the request. Callers can:

1. Hand the receipt to an auditor as proof the gate ran.
2. Verify the receipt against signet's public key list, confirming
   the response did pass through a known signet instance with a known
   policy version.
3. Reconstruct the receipt later from the HMAC-chained audit log to
   prove non-tampering.

Receipt format (HTTP header value):

    signet=v1; entry=<entry_id>; key=<key_id>; sig=<hex_hmac>

The entry_id is the audit row UUID. The signature covers the full
:class:`signet.core.audit.AuditEntry` payload using the same key as
the audit chain itself, so verifying the receipt is equivalent to
re-running :class:`signet.audit.verifier.ChainVerifier` against just
that one entry.

This module is signing-only; verification logic lives in
:meth:`ReceiptSigner.verify` for symmetry but the canonical chain
verifier in :mod:`signet.audit.verifier` is the recommended path for
any audit walk longer than one entry.
"""

from __future__ import annotations

import hashlib
import hmac

from signet.audit.chain import _serialize_for_signing
from signet.audit.keyring import KeyRing
from signet.core.audit import AuditEntry

#: Header value template; keep the parser tolerant to extra fields so we
#: can grow the format without breaking existing verifiers.
_HEADER_FORMAT = "signet=v1; entry={entry}; key={key}; sig={sig}"

#: Canonical header name the proxy sets. Configurable in ServerConfig.
DEFAULT_HEADER_NAME = "X-Signet-Receipt"


class ReceiptSigner:
    """Signs and verifies single-entry decision receipts.

    Construct with the same :class:`KeyRing` used by the audit chain.
    The signer always uses the ring's *active* key; verifiers can hold
    a ring with multiple legacy keys to verify older receipts after a
    rotation.
    """

    def __init__(self, keyring: KeyRing) -> None:
        self._keyring = keyring

    def sign(self, entry: AuditEntry) -> str:
        """Return a header value for the given audit entry.

        The entry's HMAC is recomputed against the ring's active key.
        Pass an entry that has already been written to the audit chain
        so verifiers can correlate the receipt with chain state.
        """
        active = self._keyring.active
        payload = _serialize_for_signing(entry)
        sig = hmac.new(active.secret, payload, hashlib.sha256).hexdigest()
        return _HEADER_FORMAT.format(entry=entry.entry_id, key=active.key_id, sig=sig)

    def verify(self, header_value: str, entry: AuditEntry) -> bool:
        """Return ``True`` iff the receipt header matches ``entry``.

        Looks up the key by ID from the ring; if the key isn't known
        the receipt cannot be verified and ``False`` is returned.
        """
        parsed = parse_header(header_value)
        if parsed is None:
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

    Accepts the canonical ``signet=v1; entry=...; key=...; sig=...``
    shape and tolerates extra ``;``-separated fields the future may
    add. Returns ``None`` when required fields are absent or the
    version is not v1.
    """
    fields: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        fields[k.strip()] = v.strip()
    if fields.get("signet") != "v1":
        return None
    if not all(k in fields for k in ("entry", "key", "sig")):
        return None
    return fields
