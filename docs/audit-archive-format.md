# Audit archive format (v1)

This document specifies the on-disk binary format used by
`signet.audit.compactor.compact_audit_log` to archive ranges of an
HMAC-chained audit log, and the verification flow that reads them.

The format is **version 1**, introduced in signet 0.1.6. Every archive
file declares its format version in the first line; future versions
will be additive (new sentinels appended to the file) so a v1 reader
encountering a v2 archive can refuse cleanly.

## Why compact?

JSONL audit chains grow without bound. A high-traffic deployment
producing 100 entries per second writes ~8.6 million entries per day —
a single audit file approaches gigabyte size within a week. Operators
need a way to **archive old ranges** while preserving the integrity
guarantees of the chain.

The compaction protocol replaces a contiguous prefix of the live log
with a single **compaction marker** entry that carries a Merkle root
over the archived entries. The archive file holds the entries
themselves plus the Merkle tree. The live log + every archive together
verify as one logical chain.

## Operator contract: quiesce before compaction

> **Audit chain compaction in 0.1.6 requires the chain to be quiesced
> before compaction. Calling `compact_audit_log` on a chain with
> concurrent writers WILL corrupt the chain. The chain quiesce
> contract is operator responsibility — typically by stopping the
> uvicorn workers, running compaction, then restarting. Concurrent
> compaction is on the 0.1.7 roadmap.**

There is no runtime guard against concurrent writes in this version.
The `quiesce_required=True` parameter is a marker for the contract
that the call site has read and accepts; it does not currently fence
writers. Treat it as a tripwire for future code review.

## What's in scope for 0.1.6

* The compactor preserves chain integrity. The live log + archives
  together verify as one logical chain via
  `signet.audit.verifier.verify_with_archives`.
* Archives are **byte-stable**: two compactors run on the same input
  produce identical archive bytes. This makes the archive a safe
  thing to ship to a transparency log or an external auditor.
* The Merkle root over the archived entries is exposed on the marker
  and on the archive header.

## What's deferred to 0.1.7+

* Concurrent-write safety. The chain must be quiesced.
* Encryption-at-rest of archives. Archives are plaintext gzip-JSONL
  today; layer your operating system's filesystem encryption underneath
  if you need confidentiality for the archived range.
* Partial-compaction recovery. A crash mid-compaction may leave a
  written archive without a marker, or a marker without a rewritten
  live log. Recovery requires manual operator intervention; see the
  recovery playbook section below.
* Sub-range incremental verification. The full-chain verifier walks
  every archive in full on every call. For deployments with many
  archives, batched verification (verify only archives newer than X)
  is on the roadmap.
* Anchoring the Merkle root to an external transparency log. The
  marker is HMAC-chained but the **root itself** is not yet handed
  to `AnchorBackend`. That's a one-line change once the
  semantics are settled, deferred to the same release that lands
  per-anchor verifiability of marker entries end-to-end.

## File layout

```
SIGNET-ARCHIVE-V<format_version>\n
<header JSON, single line>\n
MERKLE-START\n
<merkle tree binary>\n
MERKLE-END\n
ENTRIES-START\n
<gzip-compressed JSONL of entries>
ENTRIES-END\n
```

All sentinels are ASCII bytes, terminated by a single `\n`. The
`MERKLE-START` and `ENTRIES-START` sentinels are followed directly by
their payloads with no extra whitespace; the matching `-END` sentinels
are preceded by a single `\n` (so e.g. an `ENTRIES-END` sentinel is
the literal byte sequence `\nENTRIES-END\n`). The decoder finds payload
boundaries by searching for the end sentinel — no length prefix is
needed at the file level because each section is unambiguous in
context.

### Header line (JSON)

The header is a canonical JSON object on a single line, with these
keys (sort-keyed, no whitespace, UTF-8):

| Key                         | Type    | Meaning                                                 |
| --------------------------- | ------- | ------------------------------------------------------- |
| `archive_format_version`    | int     | The format version. v0.1.6 emits `1`.                   |
| `signet_version`            | string  | `signet.__version__` of the writer.                     |
| `range_start`               | string  | ISO 8601 UTC of the OLDEST archived entry's `ts_ns`.    |
| `range_end`                 | string  | ISO 8601 UTC of the NEWEST archived entry's `ts_ns`.    |
| `entry_count`               | int     | Number of entries in this archive.                      |
| `merkle_root`               | string  | Hex SHA-256 Merkle root over the entries' HMAC fields.  |

Recording `signet_version` is operationally useful: when forensics
later asks "which build wrote this archive", the file answers itself.

### Merkle tree binary

The Merkle tree is serialized as:

```
"MERKLE-V1\n"
<u32 leaf_count, big-endian>
<u32 leaf_byte_len, big-endian>
<leaf_count * leaf_byte_len bytes of hex leaf hashes (ASCII)>
<u32 root_byte_len, big-endian>
<root_byte_len bytes, hex root (ASCII)>
```

Leaf hash function: `SHA-256(entry.hmac.encode("utf-8"))`, hex-encoded.
Internal nodes are `SHA-256(left_raw || right_raw)` where `left_raw`
and `right_raw` are the **raw 32-byte** digests (not hex). For an odd
number of nodes at any level the last hash is duplicated before
pairing — the same fill rule used by many production Merkle log
implementations. The serialized tree only stores leaves; the root is
recomputed from leaves on read and asserted against the stored root,
so any drift between writer and reader surfaces immediately as a
format error.

### Entries blob

The entries section is a gzip-compressed UTF-8 JSONL stream. Each line
is the same canonical JSON as `JsonlBackend.append` writes (sort_keys,
no whitespace, ensure_ascii=False). Determinism: gzip headers are
written with `mtime=0` and `compresslevel=6` — both pinned — so
the same input produces identical bytes on every run.

## The compaction marker

When `compact_audit_log` succeeds, the live log is rewritten to:

```
[compaction_marker, retained_entry_0, retained_entry_1, ...]
```

The compaction marker is a regular `AuditEntry` with these fields:

| Field          | Value                                                                          |
| -------------- | ------------------------------------------------------------------------------ |
| `check_name`   | `"_compaction"` (constant `COMPACTION_CHECK_NAME`)                             |
| `decision`     | `Decision.ALLOW`                                                               |
| `owner`        | `Owner.policy("audit-compactor")`                                              |
| `reason`       | `"compacted N entries into <archive-name>"`                                    |
| `metadata`     | `{ "_compaction_marker": {...payload...} }`                                    |
| `prev_hmac`    | The HMAC of the **last archived entry** (NOT the predecessor in the live log) |
| `hmac`         | Standard HMAC over the marker's payload, signed by the active key              |

The `_compaction_marker` payload is:

```json
{
  "archive_format_version": 1,
  "archive_path": "/abs/path/to/archive-2026-Q1.bin",
  "compacted_count": 47823,
  "merkle_root": "<hex>",
  "range_start": "2026-01-01T00:00:00Z",
  "range_end": "2026-04-01T00:00:00Z"
}
```

The marker is HMAC-signed using the chain's normal signing logic
(active key, anchor receipt, `_serialize_for_signing`) — the only
twist is that its `prev_hmac` is set explicitly to the last archived
entry's hmac rather than letting the chain auto-derive from the
backend's tail. We do this manually because, at compaction time, the
backend still contains the retained entries (which haven't been
trimmed yet); the chain's normal `last_entry()` lookup would return
the wrong predecessor.

### Bridging the gap

After compaction, the live log has a deliberate "fork" at the marker:

```
                  prev_hmac = X
                       |
[compaction_marker]----+
                       |
[retained_entry_0]-----+
                  prev_hmac = X
```

Both the marker and the first retained entry share the same
`prev_hmac` — namely, the hmac of the last archived entry. A linear
walker would flag this as a `LINK_MISMATCH`. The
`verify_with_archives` walker handles it correctly: on a marker, it
opens the archive, walks every archived entry verifying internal
links and self-HMACs, asserts that the marker's `prev_hmac` matches
the last archived hmac, and **then** sets the expected next prev_hmac
to that same hmac so the first retained entry checks out.

This means the live-log-only `ChainVerifier` will report breaks on a
post-compaction log. That's intentional: live-only verification is
faster and useful for "is the trimmed log internally consistent",
but full integrity needs the archives.

## Verification flow

```python
from pathlib import Path
from signet.audit import verify_with_archives

report = verify_with_archives(
    backend=jsonl_backend,
    keyring=keyring,
    archive_dir=Path("/var/lib/signet/archives"),
)
assert report.ok, report.breaks
assert report.total_entries == 50_000  # live + archives combined
```

The verifier:

1. Walks the live log entry by entry.
2. On each non-marker entry: verifies self-HMAC and link-to-prev.
3. On a marker entry: opens the referenced archive, recomputes the
   Merkle root, compares against the marker's claim, walks the archive
   internally, and bridges the prev_hmac forward.
4. Continues with the next live entry.

### Error kinds

| `BreakKind`              | Cause                                                                |
| ------------------------ | -------------------------------------------------------------------- |
| `MERKLE_MISMATCH`        | Marker's claimed root does not match recomputation from archive.      |
| `ARCHIVE_MISSING`        | Marker references an archive that's not on disk.                      |
| `ARCHIVE_FORMAT_INVALID` | Archive present but malformed (bad magic, version, truncated, etc.).  |
| `LINK_MISMATCH`          | Standard link break inside an archive or between archive and live.    |
| `SELF_MISMATCH`          | Entry HMAC doesn't match recomputation (live or archived).            |
| `UNKNOWN_KEY`            | Key used to sign an entry isn't in the supplied keyring.              |
| `MISSING_KEY_ID`         | Entry has no signing-key-id metadata.                                 |

Archive lookup tries the absolute `archive_path` from the marker
first, then falls back to `archive_dir / Path(archive_path).name`.
This keeps deployments working when the audit log is moved between
machines (the absolute path becomes invalid but the basename stays
stable).

## Worked example: 5 entries, compact 3, retain 2

Suppose the chain has five entries `e0..e4` with timestamps from
`2026-01-01T00:00:00Z` (e0) through `2026-01-05T00:00:00Z` (e4). Call
`compact_audit_log(before="2026-01-04T00:00:00Z", output="archive-jan.bin")`.
`e0`, `e1`, `e2` have timestamps before the cutoff; `e3` and `e4` are
retained.

**Before:**

```
e0(prev="")
e1(prev=e0.hmac)
e2(prev=e1.hmac)
e3(prev=e2.hmac)
e4(prev=e3.hmac)
```

**Step 1.** Build the Merkle tree over `[e0.hmac, e1.hmac, e2.hmac]`.
Three leaves → odd at the leaf level → duplicate `leaf_hash(e2.hmac)`
to pair with itself. Compute root.

**Step 2.** Write `archive-jan.bin`:

```
SIGNET-ARCHIVE-V1\n
{"archive_format_version":1,"entry_count":3,"merkle_root":"abc123...","range_end":"2026-01-03T00:00:00Z","range_start":"2026-01-01T00:00:00Z","signet_version":"0.1.6"}\n
MERKLE-START\n
<binary tree>
MERKLE-END\n
ENTRIES-START\n
<gzip(e0_json + "\n" + e1_json + "\n" + e2_json + "\n")>
ENTRIES-END\n
```

**Step 3.** Build the marker entry. Its `prev_hmac` is `e2.hmac`. Sign
with the active key. Get `marker.hmac`.

**Step 4.** Atomically rewrite the live log:

```
marker(prev=e2.hmac, hmac=marker.hmac, metadata.merkle_root=abc123...)
e3(prev=e2.hmac, hmac=e3.hmac)
e4(prev=e3.hmac, hmac=e4.hmac)
```

Note `marker` and `e3` share `prev=e2.hmac`. That's the deliberate
fork — the verifier resolves it via the archive.

**Verification with archives.** `verify_with_archives` walks the live
log:

* `marker`: link check expects `prev=""` (initial) — `marker.prev_hmac` is
  `e2.hmac`, MISMATCH if treated naively. But the verifier instead
  treats the start of the live log as the "fork point" — actually,
  for this example with no prior archive, the first live entry's
  `prev_hmac` should be `""`. Reading the archive: `e0.prev_hmac=""`
  (matches), `e1.prev_hmac=e0.hmac`, `e2.prev_hmac=e1.hmac`. All
  archive links clean, root matches. The bridge to the marker:
  `marker.prev_hmac == e2.hmac` (matches). The bridge from archive
  back to live: `e3.prev_hmac == e2.hmac` (matches).
* `e3`: link check expects `prev=e2.hmac` (set by the bridge);
  `e3.prev_hmac` is `e2.hmac`, OK. Self-HMAC OK.
* `e4`: link check expects `prev=e3.hmac`; OK.

`report.total_entries == 5`. `report.ok == True`.

## Recovery from interrupted compaction

The compactor writes the archive, then signs the marker, then
atomically rewrites the live log. If the process dies between steps:

| Crash point                                  | State                                                          | Recovery                                              |
| -------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| Before archive written                       | Live log unchanged, no archive                                 | Re-run compaction.                                     |
| After archive written, before live rewrite   | Live log unchanged, orphan archive                             | Delete the orphan archive, re-run.                     |
| During live rewrite                          | Live log MAY be corrupt (temp file replace not yet committed)  | Restore from backup; the temp file is named `<path>.compact-*` and may be in the same directory. |
| After live rewrite (success)                 | Done                                                           | None needed.                                           |

Operationally, the simplest defense is to take a backup of the live
log immediately before invoking `compact_audit_log`, then delete it
on success. Concurrent-write safety + transactional compaction is
0.1.7 work.

## Public API surface

The compactor module exposes:

* `compact_audit_log(*, chain, backend, before, output, ...)` — the
  main entry point. Returns a `CompactionResult` or `None`.
* `CompactionResult` — what the call returns (paths, root, count,
  range, marker entry id).
* `ArchiveHeader` — the parsed header.
* `MerkleTree` — the helper class. Most callers don't touch this
  directly.
* `read_archive(path)` — for forensic tooling that wants to inspect
  an archive without verifying.
* `trim_before_index(backend, index)` — operator escape hatch.
* `is_compaction_marker(entry)` — small predicate used by the verifier
  and any tooling that walks the live log.
* `ARCHIVE_FORMAT_VERSION`, `COMPACTION_CHECK_NAME`,
  `COMPACTION_MARKER_FIELD` — constants for callers building tools
  on top of this.

The verifier extension exposes:

* `verify_with_archives(backend, keyring, archive_dir)` — full-chain
  verifier. Returns the same `VerificationReport` shape as
  `ChainVerifier.verify()`.

The CLI integration (`signet audit compact`,
`signet audit verify --including-archives`) is implemented separately
and consumes these APIs.
