"""Anchor backends -- externalize tamper-evidence to a third party.

The HMAC chain alone is tamper-*evident* but not tamper-*proof*: an
attacker with file-write access AND the HMAC secret can replace the
chain end-to-end and the verifier sees nothing. Anchor backends
mitigate that by submitting each new entry's HMAC to an external
service that returns a receipt the operator cannot retroactively forge.

v0.1.3 ships:

* :class:`NoopAnchor` (default) -- backward-compatible, no anchoring.
* :class:`Rfc3161Anchor` -- submits to any free RFC 3161 Time Stamp
  Authority (FreeTSA, DigiCert public TSA, etc.). Returns a CMS-signed
  TimeStampToken binding the HMAC to the TSA's authoritative timestamp.
  Independently verifiable against the TSA's public certificate.
  Requires no extra dependencies and no API key.

Roadmap:

* :class:`RekorAnchor` -- sigstore.dev transparency log. Adapter is
  drafted but the public Rekor instance requires signing material the
  OSS reference does not yet supply on its own. Pair with an
  :class:`Ed25519ReceiptSigner` once the integration lands in v0.1.4,
  or run a private Rekor instance and subclass :class:`Rfc3161Anchor`
  to point at a custom backend in the meantime.
* Batched anchoring for high-volume deployments (one anchor per N
  entries via Merkle root).

Anchoring is synchronous within :meth:`HmacChain.append`. The anchor
receipt is embedded in the entry's metadata under ``_anchor`` BEFORE
the HMAC is computed, so the chain HMAC binds the anchor receipt to
the entry. This means a slow or unreachable anchor service blocks
audit writes -- configure a tight timeout (default 5s) and pick a
sensible failure mode:

* ``require_success=False`` (default): on failure, the entry is still
  written with ``_anchor.success=False`` and the reason. Operations do
  not stall when the anchor service is down. The chain remains
  internally verifiable; just lacks the external proof for that entry.
* ``require_success=True``: failures raise. Use when unanchored
  entries are unacceptable.

Verification: :class:`signet.audit.verifier.ChainVerifier` checks
anchor receipts when configured with the matching anchor backend's
verify path. An entry whose anchor receipt does not verify externally
counts as a chain break.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

logger = logging.getLogger("signet.audit.anchor")

#: Metadata key on AuditEntry where the anchor receipt is embedded.
ANCHOR_FIELD = "_anchor"


@dataclass(frozen=True, slots=True)
class AnchorReceipt:
    """The result of anchoring one HMAC against an external service.

    Attributes:
        backend: Backend identifier (``"rfc3161"``, ``"noop"``, or your
            custom adapter's name).
        anchor_id: Backend-specific entry identifier when applicable.
        anchor_url: Where a third party can independently verify this
            receipt. ``None`` for offline / private anchors.
        receipt: Raw backend-specific receipt payload base64-encoded
            for JSON-safe storage in audit metadata.
        ts_ns: Wall-clock timestamp at receipt issuance.
        success: ``True`` if anchoring succeeded; ``False`` for entries
            written with ``require_success=False`` after a failure.
        error: Reason string when ``success`` is ``False``.
    """

    backend: str
    anchor_id: str = ""
    anchor_url: str | None = None
    receipt: str = ""
    ts_ns: int = 0
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation for embedding in AuditEntry.metadata."""
        out: dict[str, Any] = {
            "backend": self.backend,
            "success": self.success,
        }
        if self.anchor_id:
            out["anchor_id"] = self.anchor_id
        if self.anchor_url:
            out["anchor_url"] = self.anchor_url
        if self.receipt:
            out["receipt"] = self.receipt
        if self.ts_ns:
            out["ts_ns"] = self.ts_ns
        if self.error:
            out["error"] = self.error
        return out


class AnchorBackend(Protocol):
    """Protocol every anchor backend implements."""

    def anchor_hmac(self, hmac_hex: str) -> AnchorReceipt:
        """Submit ``hmac_hex`` to the external anchor and return a receipt.

        Implementations should respect their own timeout and return an
        :class:`AnchorReceipt` with ``success=False`` rather than
        raising -- :meth:`HmacChain.append` translates that into a
        warning-tagged entry. Implementations MAY raise if the chain's
        ``require_anchor=True`` fail-loud mode is desired.
        """
        ...

    @property
    def name(self) -> str:
        """Backend identifier embedded in receipts."""
        ...


@dataclass
class NoopAnchor:
    """Default backend -- does nothing, returns a success receipt with no proof.

    Backward-compatible behavior for v0.1.0/0.1.1/0.1.2 chains. Use
    when external anchoring is not needed or feasible (air-gapped
    deployments, dev environments).
    """

    name: str = "noop"

    def anchor_hmac(self, hmac_hex: str) -> AnchorReceipt:
        return AnchorReceipt(backend=self.name, success=True)


@dataclass
class Rfc3161Anchor:
    """Submit each HMAC to a free RFC 3161 Time Stamp Authority.

    RFC 3161 TSAs return a TimeStampToken (TST) -- a CMS-signed
    structure binding the input hash to the TSA's authoritative
    timestamp. The TST is independently verifiable against the TSA's
    public certificate without contacting the TSA again.

    Default TSA URL is FreeTSA (https://freetsa.org/tsr) -- a no-cost,
    no-account public TSA suitable for low-volume use. For production
    or compliance-critical deployments, point at an enterprise TSA
    you have a contract with.

    Requires no extra dependencies beyond ``httpx``. The TST is
    base64-encoded into the receipt for JSON-safe storage.

    Verification path: callers can extract ``receipt`` field, base64-
    decode it, and verify against the TSA's public certificate using
    any RFC 3161-aware library (``rfc3161-client``, ``cryptography``
    once it adds CMS support, OpenSSL ``ts -verify``).
    """

    tsa_url: str = "https://freetsa.org/tsr"
    timeout_s: float = 5.0
    name: str = "rfc3161"

    def anchor_hmac(self, hmac_hex: str) -> AnchorReceipt:
        # Build a TimeStampReq (RFC 3161 §2.4.1) with hand-rolled DER
        # so we don't pull in asn1crypto / pyasn1 as a hard dependency.
        # Production deployments wanting richer TSA interaction should
        # subclass and use a proper ASN.1 library.
        try:
            tsr = self._build_tsr(bytes.fromhex(hmac_hex))
        except Exception as exc:
            return AnchorReceipt(
                backend=self.name,
                success=False,
                error=f"failed to build TimeStampReq: {type(exc).__name__}: {exc}",
                anchor_url=self.tsa_url,
                ts_ns=_now_ns(),
            )

        try:
            resp = httpx.post(
                self.tsa_url,
                content=tsr,
                headers={"Content-Type": "application/timestamp-query"},
                timeout=self.timeout_s,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return AnchorReceipt(
                backend=self.name,
                success=False,
                error=f"TSA request failed: {type(exc).__name__}: {exc}",
                anchor_url=self.tsa_url,
                ts_ns=_now_ns(),
            )

        return AnchorReceipt(
            backend=self.name,
            success=True,
            anchor_url=self.tsa_url,
            receipt=base64.b64encode(resp.content).decode(),
            ts_ns=_now_ns(),
        )

    @staticmethod
    def _build_tsr(digest: bytes) -> bytes:
        """Construct a minimal RFC 3161 TimeStampReq for a SHA-256 digest.

        TimeStampReq ::= SEQUENCE {
            version                 INTEGER  { v1(1) },
            messageImprint          MessageImprint,
            reqPolicy               OBJECT IDENTIFIER OPTIONAL,
            nonce                   INTEGER OPTIONAL,
            certReq                 BOOLEAN DEFAULT FALSE,
            extensions              [0] IMPLICIT Extensions OPTIONAL
        }
        """
        if len(digest) != 32:
            raise ValueError(f"sha256 digest must be 32 bytes, got {len(digest)}")
        # OID 2.16.840.1.101.3.4.2.1 = SHA-256
        sha256_oid = bytes.fromhex("0609608648016503040201")
        algorithm_identifier = b"\x30" + _len(len(sha256_oid) + 2) + sha256_oid + b"\x05\x00"
        digest_octets = b"\x04" + _len(len(digest)) + digest
        message_imprint = (
            b"\x30"
            + _len(len(algorithm_identifier) + len(digest_octets))
            + algorithm_identifier
            + digest_octets
        )
        version = b"\x02\x01\x01"  # INTEGER 1
        cert_req = b"\x01\x01\xff"  # BOOLEAN TRUE
        body = version + message_imprint + cert_req
        return b"\x30" + _len(len(body)) + body


def _len(n: int) -> bytes:
    """Encode a length in DER form (short or long form)."""
    if n < 0x80:
        return bytes([n])
    octets: list[int] = []
    while n > 0:
        octets.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(octets)]) + bytes(octets)


def _now_ns() -> int:
    import time

    return time.time_ns()


__all__ = [
    "ANCHOR_FIELD",
    "AnchorBackend",
    "AnchorReceipt",
    "NoopAnchor",
    "Rfc3161Anchor",
]
