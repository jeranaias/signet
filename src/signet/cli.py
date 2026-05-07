"""signet CLI — operations interface.

Subcommands:

* ``signet init`` — scaffold a starter project (pipeline.py,
  client_example.py, .env.example, .gitignore).
* ``signet serve`` — run the FastAPI proxy. ``--dev`` bundles the
  three usual local-development flags into one.
* ``signet doctor`` — preflight check: prints versions, probes
  ``--upstream`` reachability, probes a running ``--self`` for
  /health, /version, and a no-owner refusal round-trip.
* ``signet audit verify`` — walk an HMAC-chained log and report any
  tampering.
* ``signet audit show`` — pretty-print one entry by ID. (Was
  ``signet replay`` in v0.1.0; that name remains as a deprecated
  alias because the original name implied pipeline re-execution
  which is roadmap not v0.1.)

Built on click. Entry point ``signet`` is registered in
``pyproject.toml`` under ``[project.scripts]``.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from signet import __version__

if TYPE_CHECKING:
    from signet.core.pipeline import Pipeline

logger = logging.getLogger("signet.cli")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="signet")
def main() -> None:
    """signet — capability-based safety gates for LLM agents."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )


@main.command()
@click.option(
    "--upstream",
    "upstream_url",
    required=True,
    envvar="SIGNET_UPSTREAM_URL",
    help="OpenAI-compatible upstream URL (e.g. http://localhost:11434/v1).",
)
@click.option(
    "--host",
    default="127.0.0.1",
    envvar="SIGNET_HOST",
    show_default=True,
    help="Bind interface.",
)
@click.option(
    "--port",
    default=8443,
    type=int,
    envvar="SIGNET_PORT",
    show_default=True,
    help="Bind port.",
)
@click.option(
    "--audit-log",
    "audit_log_path",
    type=click.Path(dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain (omit to disable persistent audit).",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    help="HMAC secret as hex (e.g. `openssl rand -hex 32`).",
)
@click.option(
    "--allow-ephemeral-key",
    is_flag=True,
    envvar="SIGNET_ALLOW_EPHEMERAL_KEY",
    help="Generate a temporary HMAC key on startup (DEV ONLY).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a Python file defining a `pipeline` variable. "
    "Without this, an open-by-default pipeline runs (no checks).",
)
@click.option(
    "--upstream-label",
    envvar="SIGNET_UPSTREAM_LABEL",
    default=None,
    help="Optional human-readable name for the upstream, surfaced in "
    "the X-Signet-Upstream response header so callers can finger-point "
    "upstream errors vs. signet errors. Defaults to a derivation of "
    "the upstream URL.",
)
@click.option(
    "--dev",
    "dev",
    is_flag=True,
    help="Bundle the dev defaults in one flag: --allow-ephemeral-key, "
    "--audit-log audit.jsonl, --config pipeline.py, "
    "--no-strict-error-redaction (so 4xx bodies surface check names + "
    "reasons during integration). Each is only set if not otherwise "
    "specified. Intended for local development only.",
)
@click.option(
    "--strict-error-redaction/--no-strict-error-redaction",
    "strict_error_redaction",
    default=None,
    envvar="SIGNET_STRICT_ERROR_REDACTION",
    help="Coarsen 4xx refusal bodies so they expose only "
    "{error, correlation_id} (default in production). Full detail "
    "remains in the audit chain — incident response correlates via the "
    "ID. Disable to surface check name + reason in the response body, "
    "useful while integrating. --dev disables automatically.",
)
@click.option(
    "--log-format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    envvar="SIGNET_LOG_FORMAT",
    help="Output format for application logs. 'text' (default) is the "
    "human-readable plain logging format. 'json' emits one JSON object "
    "per line via structlog — wire to your log aggregator (Loki, "
    "Datadog, ELK, etc.) for searchable structured logs.",
)
def serve(
    upstream_url: str,
    host: str,
    port: int,
    audit_log_path: Path | None,
    hmac_secret: str | None,
    allow_ephemeral_key: bool,
    config_path: Path | None,
    upstream_label: str | None,
    dev: bool,
    strict_error_redaction: bool | None,
    log_format: str,
) -> None:
    """Run the signet proxy."""
    import uvicorn

    if log_format == "json":
        _configure_structlog_json()

    from signet.core.pipeline import Pipeline
    from signet.server.app import SignetApp
    from signet.server.config import ServerConfig

    # --dev shorthand: fill in the four obvious dev defaults if the
    # user did not pass them explicitly. This keeps the most common
    # local invocation down to `signet serve --upstream <url> --dev`.
    if dev:
        if not allow_ephemeral_key and not hmac_secret:
            allow_ephemeral_key = True
        if audit_log_path is None:
            audit_log_path = Path("audit.jsonl")
        if config_path is None and Path("pipeline.py").exists():
            config_path = Path("pipeline.py")
        if strict_error_redaction is None:
            # Surface full refusal detail during integration so the
            # operator can see *which* check fired without tailing audit
            # logs. Production should use the strict default.
            strict_error_redaction = False

    # Load pipeline from config file or use empty one.
    if config_path:
        click.secho(
            f"warning: --config executes arbitrary Python from {config_path}. "
            "Only run with config files you control.",
            err=True,
            fg="yellow",
        )
        pipeline = _load_pipeline_from_path(config_path)
    else:
        click.echo(
            "warning: no --config provided; running with an empty pipeline (no checks).",
            err=True,
        )
        pipeline = Pipeline(checks=[])

    cfg = ServerConfig(
        upstream_url=upstream_url,
        host=host,
        port=port,
        audit_log_path=audit_log_path,
        hmac_secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET")
        if hmac_secret
        else None,
        allow_ephemeral_key=allow_ephemeral_key,
        upstream_label=upstream_label,
    )
    # CLI flag wins over the dataclass default (True), and over
    # SIGNET_STRICT_ERROR_REDACTION's env-driven value if both are set.
    if strict_error_redaction is not None:
        cfg.strict_error_redaction = strict_error_redaction

    signet_app = SignetApp(config=cfg, pipeline=pipeline)
    app = signet_app.app
    # ASCII arrow (-> not unicode) so the banner renders on Windows
    # cp1252 stdout without UnicodeEncodeError.
    click.echo(f"signet {__version__} -> {upstream_url}  (listening on {host}:{port})")

    # If we generated an ephemeral key, print it as hex so the user can
    # save it for post-mortem `signet audit verify`. Otherwise the audit
    # log we just spent the run building is unverifiable forever.
    if allow_ephemeral_key and not hmac_secret:
        ephemeral_hex = signet_app._keyring.active.secret.hex()
        click.secho(
            "EPHEMERAL HMAC KEY (save this if you want to verify the audit log later):",
            err=True,
            fg="yellow",
        )
        click.secho(f"  {ephemeral_hex}", err=True, fg="yellow")
        click.secho(
            "  (will be lost on restart; set SIGNET_HMAC_SECRET for production)",
            err=True,
            fg="yellow",
        )

    # Print loaded checks so operators can verify the configuration
    # without re-reading the file. Quiet on the empty-pipeline path
    # since the warning above is already loud about it.
    if pipeline.checks:
        click.echo(f"pipeline ({len(pipeline.checks)} checks):")
        for c in pipeline.checks:
            click.echo(f"  [{c.stage.value}] {c.name}")

    uvicorn.run(app, host=host, port=port, log_level="info")


@main.group()
def keys() -> None:
    """Cryptographic key management commands."""


@keys.command("generate-ed25519")
@click.option(
    "--out",
    "out_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path to write the PEM-encoded ed25519 private key. "
    "File mode is set to 0600 (owner read/write only) where supported.",
)
@click.option(
    "--public-out",
    "public_out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to write the matching public key. Defaults to "
    "<--out>.pub if not specified.",
)
@click.option(
    "--key-id",
    default=None,
    help="Optional key identifier to print alongside the public key for "
    "convenience. Not embedded in the key files themselves.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite the output files if they already exist.",
)
def keys_generate_ed25519(
    out_path: Path,
    public_out_path: Path | None,
    key_id: str | None,
    force: bool,
) -> None:
    """Generate a fresh ed25519 keypair for asymmetric receipt signing.

    The private key goes to ``--out`` (chmod 0600). The matching public
    key goes to ``<--out>.pub`` by default, or to ``--public-out`` if
    you want them in different locations. The public key is what you
    share with verifiers — they cannot forge receipts with it.

    Requires ``pip install signet-sign[ed25519]``.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise click.ClickException(
            "ed25519 key generation requires the cryptography package. "
            "Install with: pip install signet-sign[ed25519]"
        ) from exc

    if public_out_path is None:
        public_out_path = out_path.with_suffix(out_path.suffix + ".pub")

    for p in (out_path, public_out_path):
        if p.exists() and not force:
            raise click.ClickException(
                f"refusing to overwrite existing file {p}; pass --force to override"
            )

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    out_path.write_bytes(priv_pem)
    public_out_path.write_bytes(pub_pem)

    # Best-effort 0600 on POSIX. Windows ACLs differ — operator should
    # configure permissions through their normal IAM tooling.
    import contextlib
    import os

    if hasattr(os, "chmod"):
        with contextlib.suppress(OSError):
            os.chmod(out_path, 0o600)

    click.secho(f"  wrote private key:  {out_path} (chmod 0600 attempted)", fg="green")
    click.secho(f"  wrote public key:   {public_out_path}", fg="green")
    if key_id:
        click.echo(f"\nkey_id (record this; verifiers need it): {key_id}")
    click.echo("\nNext: configure signet with this key for asymmetric receipts.")
    click.echo(
        "  In your pipeline / app code:\n"
        "    from signet.server.receipt import Ed25519ReceiptSigner\n"
        f"    signer = Ed25519ReceiptSigner.from_pem(\n"
        f'        private_pem_path="{out_path}",\n'
        f'        key_id="{key_id or "REPLACE_ME"}",\n'
        "    )\n"
        "    SignetApp(config=cfg, pipeline=pipeline, receipt_signer=signer)"
    )
    click.echo(
        "\n  Share the public key with verifiers. They construct a verify-only signer:\n"
        "    Ed25519ReceiptSigner.from_pem(\n"
        f'        public_pem_path="{public_out_path}",\n'
        f'        key_id="{key_id or "REPLACE_ME"}",\n'
        "    )"
    )


@main.command()
@click.option(
    "--upstream",
    "upstream_url",
    envvar="SIGNET_UPSTREAM_URL",
    help="OpenAI-compatible upstream URL to probe for reachability.",
)
@click.option(
    "--self",
    "signet_url",
    default=None,
    help="signet proxy URL to probe for /health, /version, and a "
    "no-owner refusal round-trip. Use this to verify a running proxy "
    "against the gate's documented behavior.",
)
def doctor(upstream_url: str | None, signet_url: str | None) -> None:
    """Preflight check — is everything wired the way you think?

    Always prints versions and dependency status. With ``--upstream``,
    probes the upstream LLM endpoint. With ``--self``, probes a running
    signet proxy: hits /health, /version, and sends a no-owner POST
    that should come back 403 (proving the gate is enforcing). Neither
    flag is required; pass what you have.

    Auto-detection: when ``pipeline.py`` is present in the current
    directory (the layout produced by ``signet init``), doctor will
    pick up ``SIGNET_UPSTREAM_URL`` from a sibling ``.env`` /
    ``.env.example`` if ``--upstream`` was not supplied, and default
    ``--self`` to ``http://127.0.0.1:8443`` if that flag was also
    omitted. Mirrors the convenience that ``serve --dev`` already has.

    Exit code is 0 on success, 1 if any probe failed.
    """
    import platform

    import httpx

    failed = False

    upstream_url, signet_url = _doctor_autodetect(upstream_url, signet_url)

    click.echo(f"signet         {__version__}")
    click.echo(f"python         {platform.python_version()} ({platform.system()})")
    click.echo(f"httpx          {httpx.__version__}")

    try:
        import fastapi

        click.echo(f"fastapi        {fastapi.__version__}")
    except ImportError:  # pragma: no cover — installed by core deps
        click.secho("fastapi        MISSING (broken install)", fg="red")
        failed = True

    if upstream_url:
        click.echo(f"\nprobing upstream: {upstream_url}")
        try:
            resp = httpx.get(
                upstream_url.rstrip("/") + "/models", timeout=5.0, follow_redirects=True
            )
            if resp.status_code < 500:
                click.secho(f"  upstream reachable (HTTP {resp.status_code})", fg="green")
            else:
                click.secho(f"  upstream returned HTTP {resp.status_code}", fg="yellow")
        except httpx.HTTPError as exc:
            click.secho(f"  upstream unreachable: {type(exc).__name__}: {exc}", fg="red")
            failed = True

    if signet_url:
        click.echo(f"\nprobing signet:   {signet_url}")
        base = signet_url.rstrip("/")
        try:
            health = httpx.get(f"{base}/health", timeout=5.0)
            if health.status_code == 200 and health.json().get("status") == "ok":
                click.secho("  /health         ok", fg="green")
            else:
                click.secho(f"  /health         unexpected ({health.status_code})", fg="red")
                failed = True
        except httpx.HTTPError as exc:
            click.secho(f"  /health         unreachable: {exc}", fg="red")
            failed = True
            return

        try:
            ver = httpx.get(f"{base}/version", timeout=5.0).json()
            click.secho(f"  /version        signet {ver.get('version', '?')}", fg="green")
        except httpx.HTTPError as exc:
            click.secho(f"  /version        unreachable: {exc}", fg="red")
            failed = True

        # No-owner probe: should be refused if OwnerResolutionCheck is
        # configured. If it succeeds, the operator is running with no
        # owner enforcement (open-by-default). Either is honest output.
        try:
            no_owner = httpx.post(
                f"{base}/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
                timeout=5.0,
            )
            if no_owner.status_code == 403:
                click.secho("  no-owner probe  refused (gate is enforcing)", fg="green")
            elif no_owner.status_code == 202:
                click.secho(
                    "  no-owner probe  escalated (gate is enforcing via escalation)",
                    fg="green",
                )
            else:
                click.secho(
                    f"  no-owner probe  HTTP {no_owner.status_code} — gate is "
                    "OPEN (no owner enforcement). Add OwnerResolutionCheck "
                    "to your pipeline.",
                    fg="yellow",
                )
        except httpx.HTTPError as exc:
            click.secho(f"  no-owner probe  errored: {exc}", fg="red")
            failed = True

    if not upstream_url and not signet_url:
        click.echo("\n(pass --upstream <url> and/or --self <url> to probe endpoints)")

    sys.exit(1 if failed else 0)


@main.group()
def audit() -> None:
    """Audit-chain operations."""


@audit.command("verify")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    required=True,
    help="HMAC secret as hex (the same one used to write the chain).",
)
@click.option(
    "--key-id",
    "key_id",
    default="k1",
    show_default=True,
    envvar="SIGNET_HMAC_KEY_ID",
    help="ID of the active key. Match the writer's --hmac-key-id.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON instead of colored text. Use this "
    "from cron jobs, CI checks, and any scripted invocation.",
)
def audit_verify(log_path: Path, hmac_secret: str, key_id: str, as_json: bool) -> None:
    """Walk LOG_PATH and report any tampering."""
    from signet.audit.backend import JsonlBackend
    from signet.audit.keyring import Key, KeyRing
    from signet.audit.verifier import ChainVerifier

    keyring = KeyRing(
        active=Key(
            key_id=key_id,
            secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
        )
    )
    backend = JsonlBackend(log_path)
    report = ChainVerifier(backend, keyring).verify()

    if as_json:
        payload = {
            "ok": report.ok,
            "total_entries": report.total_entries,
            "last_known_good_index": report.last_known_good_index,
            "last_known_good_hmac": report.last_known_good_hmac,
            "breaks": [
                {
                    "index": b.index,
                    "entry_id": b.entry_id,
                    "kind": b.kind.value,
                    "detail": b.detail,
                }
                for b in report.breaks
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        sys.exit(0 if report.ok else 2)

    if report.ok:
        click.secho(
            f"OK: {report.total_entries} entries, chain intact "
            f"(last hmac={report.last_known_good_hmac[:16]}...)",
            fg="green",
        )
        return

    click.secho(
        f"BROKEN: {len(report.breaks)} issue(s) across {report.total_entries} entries",
        fg="red",
        bold=True,
    )
    for b in report.breaks[:50]:
        click.echo(f"  line {b.index} [{b.kind.value}] entry={b.entry_id}: {b.detail}")
    if len(report.breaks) > 50:
        click.echo(f"  ... and {len(report.breaks) - 50} more")
    sys.exit(2)


@audit.command("count")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--by",
    "group_by",
    type=click.Choice(["check", "owner", "decision", "owner_type", "stage"]),
    default=None,
    help="Group counts by this field. Default: just print total entries.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit machine-readable JSON.",
)
def audit_count(log_path: Path, group_by: str | None, as_json: bool) -> None:
    """Count entries in LOG_PATH, optionally grouped by a field.

    Quick incident-response primitive: how many blocks today? how many
    by which check? how many per owner? Reads the log lazily so it's
    safe on multi-GB chains.
    """
    from collections import Counter

    from signet.audit.backend import JsonlBackend

    backend = JsonlBackend(log_path)
    if group_by is None:
        total = sum(1 for _ in backend.iter_entries())
        if as_json:
            click.echo(json.dumps({"total": total}))
        else:
            click.echo(f"{total} entries")
        return

    counts: Counter[str] = Counter()
    for entry in backend.iter_entries():
        if group_by == "check":
            counts[entry.check_name] += 1
        elif group_by == "decision":
            counts[entry.decision.value] += 1
        elif group_by == "owner":
            counts[str(entry.owner)] += 1
        elif group_by == "owner_type":
            counts[entry.owner.owner_type.value] += 1
        elif group_by == "stage":
            stage = str(entry.metadata.get("_stage", "unknown"))
            counts[stage] += 1

    if as_json:
        click.echo(json.dumps(dict(counts.most_common()), indent=2, sort_keys=True))
        return
    width = max((len(k) for k in counts), default=10)
    for key, n in counts.most_common():
        click.echo(f"  {key:<{width}}  {n}")
    click.echo(f"({sum(counts.values())} total)")


@audit.command("tail")
@click.argument("log_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-n", "n_lines", type=int, default=10, show_default=True, help="Show last N entries.")
@click.option(
    "--filter",
    "filter_expr",
    default=None,
    help="Filter expression in form FIELD=VALUE (check, decision, owner_type). "
    "Multiple comma-separated. Example: decision=block,check=owner_resolution",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit one JSON object per line (JSONL, the same shape as the chain).",
)
def audit_tail(log_path: Path, n_lines: int, filter_expr: str | None, as_json: bool) -> None:
    """Show the last N entries from LOG_PATH (optionally filtered)."""
    from signet.audit.backend import JsonlBackend

    filters: dict[str, str] = {}
    if filter_expr:
        for clause in filter_expr.split(","):
            if "=" not in clause:
                raise click.ClickException(f"bad --filter clause {clause!r}; expected FIELD=VALUE")
            k, v = clause.split("=", 1)
            filters[k.strip()] = v.strip()

    from signet.core.audit import AuditEntry

    backend = JsonlBackend(log_path)
    matched: list[AuditEntry] = []
    for entry in backend.iter_entries():
        if filters:
            ok = True
            for f, v in filters.items():
                actual = (
                    entry.check_name
                    if f == "check"
                    else entry.decision.value
                    if f == "decision"
                    else entry.owner.owner_type.value
                    if f == "owner_type"
                    else None
                )
                if actual != v:
                    ok = False
                    break
            if not ok:
                continue
        matched.append(entry)
        if len(matched) > n_lines:
            matched.pop(0)

    for entry in matched:
        if as_json:
            click.echo(json.dumps(entry.to_dict(), separators=(",", ":"), sort_keys=True))
        else:
            ts_iso = _ns_to_iso(entry.ts_ns)
            click.echo(
                f"{ts_iso}  {entry.decision.value:8s} "
                f"{entry.check_name:20s} owner={entry.owner} "
                f"reason={entry.reason}"
            )


def _ns_to_iso(ts_ns: int) -> str:
    """Format a nanosecond wall-clock timestamp as ISO 8601 in UTC."""
    import datetime

    return datetime.datetime.fromtimestamp(ts_ns / 1e9, tz=datetime.UTC).isoformat(
        timespec="seconds"
    )


@audit.command("show")
@click.argument("entry_id")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
def audit_show(entry_id: str, audit_log_path: Path) -> None:
    """Pretty-print the audit row for ENTRY_ID.

    Deterministic re-evaluation of ADMISSION-stage checks against an
    archived request requires the original request body to be stored
    alongside the audit row — that's roadmap, not v0.1. For now this
    command reads the matching entry, pretty-prints it, and exits 0.
    Useful for incident response (`why did we block this entry?`) and
    for confirming receipts.
    """
    _show_entry(entry_id, audit_log_path)


@main.command()
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("pipeline.py"),
)
@click.option(
    "--strict/--no-strict",
    default=False,
    help="Treat warnings as errors. CI invocation pattern: "
    "`signet lint --strict` exits non-zero on any finding.",
)
def lint(config_path: Path, strict: bool) -> None:
    """Static analysis on a pipeline file. Catches the four most common
    misconfigurations operators ship with:

    \b
    1. RateLimitCheck registered before content checks (RegexContent,
       PromptInjection): a refused request still drains the bucket.
       Fixed in v0.1.5 by RateLimitCheck.priority=100, but
       user-defined Check subclasses can still get this wrong.
    2. No OwnerResolutionCheck registered: every audit row will record
       Owner.unresolved(), which makes attribution-based incident
       response impossible.
    3. ToolCallInspectorCheck(allow_unregistered=True): registered
       tools are gated by risk tier, but anything outside the registry
       is silently allowed. Almost always a mistake outside dev.
    4. ClassificationGateCheck without a matching ScopeDriftCheck at
       INSPECTION: ADMISSION-stage classification ladders only check
       what was *requested*; they do not see what the model actually
       generated. Pair them.

    Exits 0 with no findings, 0 with warnings (without ``--strict``),
    or 1 with findings (with ``--strict``).

    \b
    SECURITY NOTE: ``signet lint`` imports the pipeline file the same
    way ``signet serve --config`` does — arbitrary Python execution.
    Run only against files you control.
    """
    findings = _lint_pipeline(config_path)

    if not findings:
        click.secho("OK: pipeline passes the v0.1.5 lint checks.", fg="green")
        sys.exit(0)

    for f in findings:
        color = "red" if f.severity == "error" else "yellow"
        click.secho(f"  [{f.severity.upper()}] {f.code}: {f.message}", fg=color)
        if f.hint:
            click.echo(f"      hint: {f.hint}")

    has_errors = any(f.severity == "error" for f in findings)
    if has_errors or strict:
        sys.exit(1)
    sys.exit(0)


@main.command(hidden=True)
@click.argument("entry_id")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
def replay(entry_id: str, audit_log_path: Path) -> None:
    """Deprecated alias for `signet audit show`.

    Original name was misleading — this command does NOT re-execute
    the pipeline (that needs request-body archival, roadmap for v0.2).
    Use `signet audit show <entry-id>` instead. The `replay` alias
    will be removed in v0.2.
    """
    click.secho(
        "warning: `signet replay` is deprecated; use `signet audit show` instead.",
        err=True,
        fg="yellow",
    )
    _show_entry(entry_id, audit_log_path)


def _show_entry(entry_id: str, audit_log_path: Path) -> None:
    from signet.audit.backend import JsonlBackend

    # UUIDs are case-insensitive per RFC 4122; operators paste from
    # logs with whatever case the source rendered them in. Normalize
    # both sides to lowercase for the compare.
    target = entry_id.strip().lower()
    backend = JsonlBackend(audit_log_path)
    for entry in backend.iter_entries():
        if entry.entry_id.lower() == target:
            click.echo(json.dumps(entry.to_dict(), indent=2, sort_keys=True))
            return
    click.secho(f"no entry with id {entry_id!r} found in {audit_log_path}", fg="red")
    sys.exit(1)


@main.command()
@click.argument(
    "target_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("."),
)
def init(target_dir: Path) -> None:
    """Scaffold a starter signet project (config + sample pipeline)."""
    target_dir.mkdir(parents=True, exist_ok=True)

    pipeline_path = target_dir / "pipeline.py"
    env_path = target_dir / ".env.example"
    gitignore_path = target_dir / ".gitignore"
    client_path = target_dir / "client_example.py"

    if pipeline_path.exists():
        click.secho(f"refusing to overwrite existing {pipeline_path}", fg="yellow")
        sys.exit(1)

    pipeline_path.write_text(_PIPELINE_TEMPLATE, encoding="utf-8")
    env_path.write_text(_ENV_TEMPLATE, encoding="utf-8")
    client_path.write_text(_CLIENT_EXAMPLE_TEMPLATE, encoding="utf-8")
    # Also drop a .gitignore so the user doesn't accidentally commit
    # their HMAC secret (.env) or audit log (potentially sensitive
    # owner attribution data) on first push. Leave any existing
    # .gitignore alone.
    if not gitignore_path.exists():
        gitignore_path.write_text(_GITIGNORE_TEMPLATE, encoding="utf-8")
        click.secho(f"  wrote {gitignore_path}", fg="green")

    click.secho(f"  wrote {pipeline_path}", fg="green")
    click.secho(f"  wrote {env_path}", fg="green")
    click.secho(f"  wrote {client_path}", fg="green")
    click.echo("\nnext: review the files, then run:")
    click.echo("  signet serve --upstream http://localhost:11434/v1 --dev")
    click.echo("\nthen, in another terminal:")
    click.echo("  python client_example.py")


def _configure_structlog_json() -> None:
    """Configure structlog to emit JSON via the stdlib logging handler.

    All existing ``logging.getLogger(...)`` calls in signet then route
    through structlog's processor chain and emit one JSON object per
    line. The output goes to stderr (the standard signal-handler-safe
    stream for daemon logs).

    Required because all signet code uses stdlib ``logging`` (it predates
    this CLI flag); we don't rewrite every module to import structlog
    directly. Calling this function is enough.
    """
    import logging

    import structlog

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    pre_chain: list[Any] = [  # structlog's processor types vary; loose typing here
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
    ]

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=logging.INFO,
        force=True,
    )

    # Replace the root handler's formatter with structlog's JSON renderer
    handler = logging.getLogger().handlers[0]
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=pre_chain,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        )
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


@dataclass(frozen=True)
class _LintFinding:
    code: str
    severity: str  # "error" | "warning"
    message: str
    hint: str = ""


def _lint_pipeline(config_path: Path) -> list[_LintFinding]:
    """Static-ish analysis on a configured pipeline.

    Imports the file (arbitrary code execution — caller already warned)
    and walks the loaded ``pipeline._checks`` list. Returns a list of
    findings in declaration order.
    """
    pipeline = _load_pipeline_from_path(config_path)
    findings: list[_LintFinding] = []

    # Import the check classes lazily to avoid circular imports at
    # module top level. We compare by class identity (not name) where
    # possible so renames or re-exports don't fool us.
    from signet.checks.classification_gate import ClassificationGateCheck
    from signet.checks.owner_resolution import OwnerResolutionCheck
    from signet.checks.prompt_injection import PromptInjectionCheck
    from signet.checks.rate_limit import RateLimitCheck
    from signet.checks.regex_content import RegexContentCheck
    from signet.checks.scope_drift import ScopeDriftCheck
    from signet.checks.tool_call_inspector import ToolCallInspectorCheck
    from signet.core.stage import Stage

    checks_by_index: list[Any] = list(pipeline.checks)
    by_class: dict[type, list[int]] = {}
    for i, c in enumerate(checks_by_index):
        by_class.setdefault(type(c), []).append(i)

    # Rule 2: missing OwnerResolutionCheck (or a subclass).
    has_owner_resolver = any(isinstance(c, OwnerResolutionCheck) for c in checks_by_index)
    if not has_owner_resolver:
        findings.append(
            _LintFinding(
                code="SIG002",
                severity="error",
                message=(
                    "no OwnerResolutionCheck registered; every audit row will "
                    "record Owner.unresolved() and attribution-based incident "
                    "response will not work."
                ),
                hint=(
                    "Add OwnerResolutionCheck(require_owner=True) to your "
                    "ADMISSION-stage checks. See "
                    "docs/checks/owner_resolution.md."
                ),
            )
        )

    # Rule 1: RateLimit ordered before content-scanning ADMISSION checks.
    # By v0.1.5, RateLimitCheck.priority=100 self-orders late, so this
    # only fires when a custom subclass overrides priority back to <=
    # the default of a content check.
    content_check_classes = (RegexContentCheck, PromptInjectionCheck)
    rl_indexes = [i for i, c in enumerate(checks_by_index) if isinstance(c, RateLimitCheck)]
    content_indexes = [
        i for i, c in enumerate(checks_by_index) if isinstance(c, content_check_classes)
    ]
    for rl_i in rl_indexes:
        misordered = [ci for ci in content_indexes if ci > rl_i]
        if misordered:
            findings.append(
                _LintFinding(
                    code="SIG001",
                    severity="warning",
                    message=(
                        "RateLimitCheck runs before content-scanning checks "
                        f"(positions: rate_limit at {rl_i}, content at "
                        f"{misordered}). Refused requests still drain the "
                        "owner's token bucket."
                    ),
                    hint=(
                        "Either accept the default RateLimitCheck.priority=100 "
                        "(don't subclass to override), or set the content "
                        "check's priority lower than rate_limit's."
                    ),
                )
            )

    # Rule 3: ToolCallInspectorCheck(allow_unregistered=True).
    for c in checks_by_index:
        if isinstance(c, ToolCallInspectorCheck) and getattr(c, "allow_unregistered", False):
            findings.append(
                _LintFinding(
                    code="SIG003",
                    severity="warning",
                    message=(
                        "ToolCallInspectorCheck(allow_unregistered=True): "
                        "tools outside the registry are silently allowed."
                    ),
                    hint=(
                        "Set allow_unregistered=False (the default) and "
                        "register every tool you intend to permit."
                    ),
                )
            )

    # Rule 4: ClassificationGate without a matching ScopeDriftCheck.
    has_class_gate = any(isinstance(c, ClassificationGateCheck) for c in checks_by_index)
    has_scope_drift_at_inspection = any(
        isinstance(c, ScopeDriftCheck) and c.stage is Stage.INSPECTION for c in checks_by_index
    )
    if has_class_gate and not has_scope_drift_at_inspection:
        findings.append(
            _LintFinding(
                code="SIG004",
                severity="warning",
                message=(
                    "ClassificationGateCheck registered without a matching "
                    "ScopeDriftCheck at INSPECTION. ADMISSION classification "
                    "only validates what was requested; INSPECTION drift is "
                    "what catches the model generating outside its lane "
                    "after the request was admitted."
                ),
                hint="Add ScopeDriftCheck() to your INSPECTION-stage checks.",
            )
        )

    return findings


def _doctor_autodetect(
    upstream_url: str | None, signet_url: str | None
) -> tuple[str | None, str | None]:
    """Fill in ``--upstream`` and ``--self`` when invoked inside a
    ``signet init`` workspace and the user did not pass them.

    Looks for ``pipeline.py`` in the cwd as the marker for "this is
    a scaffold". When found:

    * ``--upstream`` is filled from ``SIGNET_UPSTREAM_URL`` in
      ``.env`` (preferred) or ``.env.example``, parsed with a tiny
      key=value reader to avoid pulling in python-dotenv as a hard
      dep.
    * ``--self`` defaults to ``http://127.0.0.1:8443`` (the
      ``serve`` defaults), so doctor probes the proxy that
      ``signet serve --dev`` would start.

    Both arguments are passed through unchanged when no scaffold is
    detected or when the user supplied a value explicitly.
    """
    if upstream_url and signet_url:
        return upstream_url, signet_url

    pipeline_marker = Path("pipeline.py")
    if not pipeline_marker.exists():
        return upstream_url, signet_url

    if upstream_url is None:
        for candidate in (Path(".env"), Path(".env.example")):
            if not candidate.exists():
                continue
            value = _read_env_var(candidate, "SIGNET_UPSTREAM_URL")
            if value:
                upstream_url = value
                click.echo(
                    f"(doctor: auto-detected --upstream={value} from {candidate})",
                    err=True,
                )
                break

    if signet_url is None:
        signet_url = "http://127.0.0.1:8443"
        click.echo(
            f"(doctor: auto-detected --self={signet_url} from local pipeline.py scaffold)",
            err=True,
        )

    return upstream_url, signet_url


def _read_env_var(path: Path, key: str) -> str | None:
    """Best-effort KEY=value reader for .env-style files.

    Strips matching surrounding quotes and inline ``#`` comments.
    Skips comment lines and lines without ``=``. Does not handle the
    full python-dotenv grammar (no escapes, no multi-line) — those are
    not what ``signet init`` writes.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        # Allow `export FOO=bar` (sh-compatible env files).
        if line.startswith("export "):
            line = line[len("export ") :]
        k, _, v = line.partition("=")
        if k.strip() != key:
            continue
        v = v.strip()
        # Strip surrounding quotes if matched.
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        # Strip inline comments only when not inside quotes (we already
        # stripped quotes); a literal `#` after whitespace ends the value.
        if " #" in v:
            v = v.split(" #", 1)[0].rstrip()
        return v or None
    return None


def _parse_hex_secret(value: str, source: str) -> bytes:
    """Decode a hex-encoded HMAC secret with a clear error on failure.

    Strips the optional ``0x`` prefix and any surrounding whitespace —
    real users paste from terminals and copy-managers that add either.
    Re-raises with the source name (env var or flag) so the operator
    knows where to fix the input.
    """
    cleaned = value.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    try:
        out = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise click.ClickException(
            f"{source} is not valid hex ({exc}). "
            "Generate a fresh secret with `openssl rand -hex 32` "
            "and pass the resulting 64-character string."
        ) from exc
    if len(out) < 16:
        raise click.ClickException(
            f"{source} decoded to {len(out)} bytes; HMAC-SHA256 needs at "
            "least 16 (32 recommended). Use `openssl rand -hex 32`."
        )
    return out


def _load_pipeline_from_path(path: Path) -> Pipeline:
    """Import a Python file and return its ``pipeline`` attribute.

    SECURITY: this calls ``importlib.exec_module`` on the file at
    ``path``, which is arbitrary-code execution by design. Only point
    ``signet serve --config`` at files you control. The CLI prints a
    warning at startup; this function is the actual gun.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("signet_user_config", path)
    if spec is None or spec.loader is None:
        raise click.ClickException(f"could not load config from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from signet.core.pipeline import Pipeline as _Pipeline

    pipeline = getattr(module, "pipeline", None)
    if pipeline is None:
        raise click.ClickException(
            f"{path} does not define a `pipeline` variable. "
            "Run `signet init` for a starter template."
        )
    if not isinstance(pipeline, _Pipeline):
        raise click.ClickException(
            f"{path}'s `pipeline` is {type(pipeline).__name__}, "
            "expected signet.core.pipeline.Pipeline"
        )
    return pipeline


_PIPELINE_TEMPLATE = '''"""signet pipeline configuration.

Edit the `pipeline` variable below to register the checks you want.
The CLI will import this file and pass the pipeline to SignetApp.
"""

from signet.checks import (
    ClassificationGateCheck,
    LoopbackTrustCheck,
    OwnerResolutionCheck,
    RateLimitCheck,
    ScopeDriftCheck,
    ToolCallInspectorCheck,
    ToolSpec,
    RiskTier,
)
from signet.core.pipeline import Pipeline


# A starter pipeline. Adjust to your needs.
pipeline = Pipeline(checks=[
    # ADMISSION
    LoopbackTrustCheck(),  # auto-resolve loopback + Tailscale CGNAT
    OwnerResolutionCheck(require_owner=True),
    RateLimitCheck(capacity=60, refill_per_second=1.0),
    ClassificationGateCheck(),

    # INSPECTION
    ScopeDriftCheck(),

    # COMMITMENT
    ToolCallInspectorCheck(
        registry={
            # Add your tools here. Example:
            # "list_files": ToolSpec(risk_tier=RiskTier.LOW),
            # "send_email": ToolSpec(
            #     risk_tier=RiskTier.HIGH,
            #     irreversible=True,
            #     dryrun_supported=False,
            # ),
        },
        max_allowed_tier=RiskTier.HIGH,
        allow_critical=False,
    ),
])
'''

_ENV_TEMPLATE = """# signet runtime configuration. Copy to .env, fill in, source before running.

# Upstream LLM (any OpenAI-compatible endpoint)
SIGNET_UPSTREAM_URL=http://localhost:11434/v1

# HMAC key for the audit chain. Generate with:  openssl rand -hex 32
SIGNET_HMAC_SECRET=

# Where to write the audit log (JSONL)
SIGNET_AUDIT_LOG_PATH=./audit.jsonl

# Bind address. 127.0.0.1 = loopback only; 0.0.0.0 = all interfaces.
SIGNET_HOST=127.0.0.1
SIGNET_PORT=8443
"""

# Generated alongside the scaffold so first-time users do not commit
# their HMAC secret or audit-log contents on first push.
_GITIGNORE_TEMPLATE = """# signet — keep secrets and audit logs out of version control.
.env
.env.*
!.env.example
*.jsonl
__pycache__/
*.pyc
"""

# Minimal-but-real client snippet so users do not have to read the
# README to find out how to call signet from Python.
_CLIENT_EXAMPLE_TEMPLATE = '''"""client_example.py — call signet from Python.

Two ways shown:
1. Plain httpx — works with no extras installed.
2. wrap_openai — drop-in replacement for the openai SDK that points
   at signet and injects the X-Commit-Owner header on every request.
   Requires the `openai` extra: `pip install signet-sign[openai]`.

Run after starting `signet serve --upstream <URL> --dev` in another
terminal.
"""

from __future__ import annotations

import httpx


SIGNET_URL = "http://localhost:8443/v1"


def call_with_httpx() -> None:
    """Plain HTTP — no SDK needed."""
    resp = httpx.post(
        f"{SIGNET_URL}/chat/completions",
        headers={
            "Content-Type": "application/json",
            # Required: caller-asserted commit owner. Any of these
            # three header forms is accepted:
            #   X-Commit-Owner: human:<principal>
            #   X-Agent-Id:     agent:<id>
            #   X-Policy-Name:  <policy>
            "X-Commit-Owner": "human:alice@example.com",
        },
        json={
            "model": "llama3.2:1b",  # change to a model your upstream actually has
            "messages": [{"role": "user", "content": "Reply with exactly: pong"}],
            "max_tokens": 10,
        },
        timeout=60.0,
    )
    print("status:", resp.status_code)
    print("upstream:", resp.headers.get("X-Signet-Upstream"))
    print("upstream-status:", resp.headers.get("X-Signet-Upstream-Status"))
    print("receipt:", resp.headers.get("X-Signet-Receipt", "(no audit log configured)"))
    print("body:", resp.json())


def call_with_openai_sdk() -> None:
    """Drop-in: existing OpenAI SDK code points at signet."""
    try:
        from openai import OpenAI
    except ImportError:
        print("install with: pip install signet-sign[openai]")
        return

    from signet.adapters.openai import wrap_openai

    client = wrap_openai(
        OpenAI(api_key="not-used-by-local-llm"),
        signet_url=SIGNET_URL,
        owner="human:alice@example.com",
    )
    resp = client.chat.completions.create(
        model="llama3.2:1b",
        messages=[{"role": "user", "content": "Reply with exactly: pong"}],
        max_tokens=10,
    )
    print(resp.choices[0].message.content)


if __name__ == "__main__":
    call_with_httpx()
    print("---")
    call_with_openai_sdk()
'''


if __name__ == "__main__":
    main()
