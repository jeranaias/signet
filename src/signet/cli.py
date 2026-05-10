"""signet CLI — operations interface.

Subcommands:

* ``signet init`` — scaffold a starter project (pipeline.py,
  client_example.py, .env.example, .gitignore).
* ``signet serve`` — run the FastAPI proxy. ``--dev`` bundles the
  three usual local-development flags into one.
* ``signet doctor`` — preflight check: prints versions, probes
  ``--upstream`` reachability, probes a running ``--self`` for
  /health, /version, and a no-owner refusal round-trip. With
  ``--probe-injection`` (v0.1.6+), runs the static obfuscated-
  injection corpus against ``--self`` and asserts every probe
  refuses.
* ``signet audit verify`` — walk an HMAC-chained log and report any
  tampering. With ``--including-archives <dir>`` (v0.1.6+), also
  walks every referenced compaction archive end-to-end.
* ``signet audit show`` — pretty-print one entry by ID.
* ``signet audit count`` / ``audit tail`` — quick group-by counts
  and tail with field filters.
* ``signet audit compact`` (v0.1.6+) — Merkle-archive a prefix of
  the chain and replace it with a compaction marker. Operator MUST
  quiesce the chain first (``--quiesce-confirm``).
* ``signet audit report`` (v0.1.6+) — periodic decision summary:
  decision distribution, top firing checks, top blocked owners
  (anonymized by default), deltas vs the prior period, chain-
  integrity attestation. Markdown or JSON.
* ``signet replay <id>`` — first-class shorthand for
  ``signet audit show <id>``. Promoted to first-class in v0.1.6;
  the v0.1.0 deprecation note has been retired since the name
  applies just fine to "replay this audit row to my eyeballs"
  even though true pipeline re-execution remains roadmap.
* ``signet plugins list`` (v0.1.6+) — discover installed
  ``signet.checks`` / ``signet.adapters`` / ``signet.anchors``
  entry points and report load status (``loaded``,
  ``incompatible_abi``, ``load_error``).
* ``signet keys generate-ed25519`` — fresh keypair for asymmetric
  receipt signing.
* ``signet lint`` — static analysis on a pipeline file.

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
    "--shadow/--no-shadow",
    "shadow",
    default=None,
    envvar="SIGNET_SHADOW",
    help="Run in shadow mode: pipeline runs but block/escalate "
    "decisions become allow at the response layer. Audit chain "
    "and metrics still record the original decision; the response "
    "carries X-Signet-Shadow-* headers describing the would-be "
    "refusal and a correlation ID. Use to pilot enforcement.",
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
    shadow: bool | None,
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
    if shadow is not None:
        cfg.shadow = shadow

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
    "convenience. Not embedded in the key files themselves. If --key-id "
    "is provided, a sidecar <out>.meta.json is written so the binding "
    "survives terminal close.",
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
    # C9 (v0.1.7): when --key-id is supplied, write a sidecar
    # ``<out>.meta.json`` so the operator does not lose the
    # key-id-to-key binding the moment they close their terminal.
    # The PEM file itself stays bit-identical to a no-key-id run —
    # the sidecar is purely metadata.
    if key_id:
        from datetime import UTC, datetime

        meta_path = out_path.with_suffix(out_path.suffix + ".meta.json")
        meta = {
            "key_id": key_id,
            "generated_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
            "signet_version": __version__,
        }
        meta_path.write_text(
            json.dumps(meta, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        click.secho(f"  wrote key metadata: {meta_path}", fg="green")
        click.echo(f"\nkey_id (record this; verifiers need it): {key_id}")
    click.echo("\nNext: configure signet with this key for asymmetric receipts.")
    # C4 (v0.1.7): emit Python's safe ``repr()`` of the path so Windows
    # backslashes (``D:\tmp\priv.pem``) are properly escaped. Previously
    # we wrapped the path in double quotes and let click format it,
    # which produced ``"D:\tmp\priv.pem"`` — pasting that into Python
    # interprets ``\t`` as a tab and ``\p`` as an invalid escape.
    # ``repr(str(path))`` produces ``'D:\\tmp\\priv.pem'`` (or just
    # ``'/tmp/priv.pem'`` on POSIX), which always parses cleanly.
    out_repr = repr(str(out_path))
    public_repr = repr(str(public_out_path))
    key_id_value = key_id or "REPLACE_ME"
    click.echo(
        "  In your pipeline / app code:\n"
        "    from signet.server.receipt import Ed25519ReceiptSigner\n"
        f"    signer = Ed25519ReceiptSigner.from_pem(\n"
        f"        private_pem_path={out_repr},\n"
        f'        key_id="{key_id_value}",\n'
        "    )\n"
        "    SignetApp(config=cfg, pipeline=pipeline, receipt_signer=signer)"
    )
    click.echo(
        "\n  Share the public key with verifiers. They construct a verify-only signer:\n"
        "    Ed25519ReceiptSigner.from_pem(\n"
        f"        public_pem_path={public_repr},\n"
        f'        key_id="{key_id_value}",\n'
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
@click.option(
    "--probe-injection",
    "probe_injection",
    is_flag=True,
    help="Send a corpus of obfuscated injection attempts to --self "
    "and assert every one is blocked. Catches 'someone "
    "mis-edited the rule list and the prompt-injection check "
    "stopped firing' regressions in CI.",
)
def doctor(
    upstream_url: str | None,
    signet_url: str | None,
    probe_injection: bool,
) -> None:
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
            # Fall through to the rest of the doctor flow — each
            # subsequent probe will surface its own failure and the
            # final ``sys.exit(1 if failed else 0)`` reports the
            # overall status. Previously a stray ``return`` here exited
            # the function before ``sys.exit(...)`` could fire, so
            # ``signet doctor --self <down>`` exited 0 despite the red
            # banner.

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

    if probe_injection:
        if not signet_url:
            click.secho(
                "  --probe-injection requires --self <url>; the corpus must "
                "be sent against a running signet proxy.",
                fg="red",
            )
            sys.exit(1)
        probe_failed = _run_probe_injection_corpus(signet_url)
        if probe_failed:
            failed = True

    sys.exit(1 if failed else 0)


def _run_probe_injection_corpus(signet_url: str) -> bool:
    """Send every probe in :data:`PROMPT_INJECTION_PROBE_CORPUS` and
    assert every one is refused.

    Returns ``True`` if any probe leaked through (gate failure),
    ``False`` if every probe was correctly blocked.

    Each probe is sent as an OpenAI-shaped chat-completion to
    ``<signet_url>/v1/chat/completions`` with a default
    ``X-Commit-Owner: human:doctor-probe`` header so OwnerResolutionCheck
    doesn't fire first. A successful probe sees one of:

    * HTTP 403 — strict-error-redaction default refusal.
    * HTTP 202 — escalation path (still a refusal at the response
      layer).
    * HTTP 200 with ``X-Signet-Shadow-Decision: block`` — shadow mode
      on the target.

    Any 200 without a shadow-block header counts as a leak.
    """
    import httpx

    from signet.cli_helpers.probe_injection_corpus import (
        PROMPT_INJECTION_PROBE_CORPUS,
    )

    base = signet_url.rstrip("/")
    click.echo(f"\nprobing prompt-injection corpus against: {base}")
    click.echo(f"  ({len(PROMPT_INJECTION_PROBE_CORPUS)} probes)")
    leaked = False

    for probe in PROMPT_INJECTION_PROBE_CORPUS:
        try:
            resp = httpx.post(
                f"{base}/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    # Pre-resolved owner so OwnerResolutionCheck does not
                    # fire first and shadow our intended target check.
                    "X-Commit-Owner": "human:doctor-probe",
                },
                json={
                    "model": "test",
                    "messages": [
                        {"role": "user", "content": probe.payload},
                    ],
                },
                timeout=10.0,
            )
        except httpx.HTTPError as exc:
            click.secho(
                f"  [{probe.name:<24}] errored: {type(exc).__name__}: {exc}",
                fg="red",
            )
            leaked = True
            continue

        # Decide pass/fail. The "shadow-mode block" path is the only
        # case where 200 is acceptable.
        shadow_decision = resp.headers.get("X-Signet-Shadow-Decision", "")
        firing_check = _probe_firing_check(resp)
        if resp.status_code == 403 or resp.status_code == 202:
            click.secho(
                f"  [{probe.name:<24}] refused HTTP {resp.status_code} "
                f"(check={firing_check or 'redacted'})",
                fg="green",
            )
        elif resp.status_code == 200 and shadow_decision == "block":
            click.secho(
                f"  [{probe.name:<24}] shadow-blocked "
                f"(check={firing_check or 'redacted'})",
                fg="green",
            )
        else:
            click.secho(
                f"  [{probe.name:<24}] LEAKED HTTP {resp.status_code} "
                f"(expected refusal; shadow_decision={shadow_decision!r})",
                fg="red",
            )
            leaked = True

    if leaked:
        click.secho("\n  prompt-injection probe: FAIL (gate let one through)", fg="red")
    else:
        click.secho("\n  prompt-injection probe: ok (all probes blocked)", fg="green")
    return leaked


def _probe_firing_check(resp: Any) -> str | None:
    """Best-effort extraction of the firing check name from a refusal.

    Looks first at the ``X-Signet-Shadow-Decision-Check`` header
    (shadow mode), then at the response JSON body's ``check`` field
    (only populated when ``--no-strict-error-redaction`` is on the
    target). Returns ``None`` when neither channel surfaces it.
    """
    name = resp.headers.get("X-Signet-Shadow-Decision-Check")
    if name:
        return str(name)
    try:
        body = resp.json()
    except (ValueError, AttributeError):
        return None
    if isinstance(body, dict):
        check = body.get("check") or body.get("firing_check")
        if isinstance(check, str):
            return check
    return None


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
@click.option(
    "--including-archives",
    "archive_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Walk the live chain plus every referenced compaction archive "
    "as one logical chain. Recomputes Merkle roots and reports "
    "MERKLE_MISMATCH / ARCHIVE_MISSING / ARCHIVE_FORMAT_INVALID.",
)
@click.option(
    "--summarize-cascades",
    is_flag=True,
    help="Collapse cascading link_mismatch breaks downstream of a "
    "single tamper into one CASCADE_SUPPRESSED summary break. Useful "
    "for keeping large-chain reports readable when one forgery would "
    "otherwise surface as N+ link breaks. Mirrors the verifier's "
    "compact_breaks parameter (A11).",
)
def audit_verify(
    log_path: Path,
    hmac_secret: str,
    key_id: str,
    as_json: bool,
    archive_dir: Path | None,
    summarize_cascades: bool,
) -> None:
    """Walk LOG_PATH and report any tampering."""
    from signet.audit.backend import JsonlBackend, MalformedAuditEntry
    from signet.audit.keyring import Key, KeyRing
    from signet.audit.verifier import ChainVerifier, verify_with_archives

    keyring = KeyRing(
        active=Key(
            key_id=key_id,
            secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
        )
    )
    backend = JsonlBackend(log_path)
    try:
        if archive_dir is None:
            report = ChainVerifier(
                backend, keyring, compact_breaks=summarize_cascades
            ).verify()
        else:
            report = verify_with_archives(
                backend,
                keyring,
                archive_dir,
                compact_breaks=summarize_cascades,
            )
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

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
        # A15 (v0.1.7): drop the dangling ``(last hmac=)`` parenthesis
        # when the chain is empty. There's no head HMAC on a zero-entry
        # chain, so the empty parens just looked like a render bug.
        if report.total_entries == 0:
            click.secho("OK: 0 entries (chain is empty)", fg="green")
        else:
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
        hint = _verify_break_hint(b.kind.value)
        if hint:
            click.echo(f"      hint: {hint}")
    if len(report.breaks) > 50:
        click.echo(f"  ... and {len(report.breaks) - 50} more")
    sys.exit(2)


def _verify_break_hint(kind: str) -> str:
    """Return an operator-readable hint for a verify break kind.

    The new v0.1.6 archive-aware kinds (``MERKLE_MISMATCH``,
    ``ARCHIVE_MISSING``, ``ARCHIVE_FORMAT_INVALID``) get explicit
    remediation guidance because they're brand new to operators
    upgrading from v0.1.5. The pre-existing kinds already render with
    enough detail in ``b.detail``.
    """
    if kind == "merkle_mismatch":
        return (
            "the marker's claimed Merkle root no longer matches the archive. "
            "Either the marker or the archive was tampered with."
        )
    if kind == "archive_missing":
        return (
            "pass --including-archives <dir> pointing at the directory that "
            "contains the referenced archive file."
        )
    if kind == "archive_format_invalid":
        return (
            "the archive on disk is malformed (bad magic, version mismatch, "
            "or truncated). Restore from a known-good copy."
        )
    return ""


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

    from signet.audit.backend import JsonlBackend, MalformedAuditEntry

    backend = JsonlBackend(log_path)
    if group_by is None:
        try:
            total = sum(1 for _ in backend.iter_entries())
        except MalformedAuditEntry as exc:
            raise _malformed_audit_to_click_exception(exc) from exc
        if as_json:
            click.echo(json.dumps({"total": total}))
        else:
            click.echo(f"{total} entries")
        return

    counts: Counter[str] = Counter()
    try:
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
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

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
    from signet.audit.backend import JsonlBackend, MalformedAuditEntry

    # C7 (v0.1.7): validate filter field names up-front. Previously an
    # unknown field (``foo=bar``) silently filtered out every entry —
    # the operator saw zero output and assumed the chain was empty.
    # Allowed fields are documented in the --filter help text and
    # mirror the comparison branches below.
    _ALLOWED_FILTER_FIELDS = {"check", "decision", "owner_type"}

    filters: dict[str, str] = {}
    if filter_expr:
        for clause in filter_expr.split(","):
            if "=" not in clause:
                raise click.ClickException(f"bad --filter clause {clause!r}; expected FIELD=VALUE")
            k, v = clause.split("=", 1)
            field_name = k.strip()
            if field_name not in _ALLOWED_FILTER_FIELDS:
                raise click.ClickException(
                    f"unknown filter field {field_name!r}; "
                    f"known fields: {', '.join(sorted(_ALLOWED_FILTER_FIELDS))}"
                )
            filters[field_name] = v.strip()

    from signet.core.audit import AuditEntry

    backend = JsonlBackend(log_path)
    matched: list[AuditEntry] = []
    try:
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
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

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


def _malformed_audit_to_click_exception(exc: Any) -> click.ClickException:
    """Wrap a :class:`signet.audit.backend.MalformedAuditEntry` into a
    one-line :class:`click.ClickException`.

    Surfaces the offending line number, the parse error, and a
    truncated raw line (capped at 200 chars) plus a one-line operator
    fix instruction. Used by every CLI surface that walks the live
    audit log so a corrupted JSONL line gives an operator-readable
    error instead of a Python traceback. Mid-write truncation after a
    crash is the realistic source of a malformed line, so the message
    points at the audit-archive operator playbook for restore-from-
    backup as the canonical fix.
    """
    raw = exc.raw_line if isinstance(exc.raw_line, str) else str(exc.raw_line)
    return click.ClickException(
        f"audit log line {exc.line_number} is malformed: {exc.parse_error}\n"
        f"  raw line: {raw[:200]}\n"
        f"  fix: edit the file to remove or fix the bad line, "
        f"or restore from backup."
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


@audit.command("compact")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the live JSONL audit chain to compact.",
)
@click.option(
    "--before",
    required=True,
    help="ISO 8601 UTC timestamp; entries with ts strictly < this are "
    "compacted into the archive.",
)
@click.option(
    "--output",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path to write the archive file. Parent directory is created "
    "if missing.",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    required=True,
    help="HMAC secret as hex (the same one the chain was written with).",
)
@click.option(
    "--key-id",
    "key_id",
    envvar="SIGNET_HMAC_KEY_ID",
    default="k1",
    show_default=True,
    help="ID of the active key. The compaction marker is signed with "
    "this key.",
)
@click.option(
    "--quiesce-confirm",
    is_flag=True,
    help="Confirm you have stopped all writers to the chain. "
    "Compaction WILL corrupt the chain if writers are active. "
    "See docs/audit-archive-format.md for the operator playbook.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing archive file at --output. The default "
    "is refusal so an accidental re-run with the same --output never "
    "destroys an archive on disk.",
)
def audit_compact(
    audit_log_path: Path,
    before: str,
    output: Path,
    hmac_secret: str,
    key_id: str,
    quiesce_confirm: bool,
    force: bool,
) -> None:
    """Archive entries before --before into --output and replace them
    with a compaction marker in the live chain.

    The live chain MUST be quiesced first (no concurrent writers).
    Concurrent writes during compaction will corrupt the chain.
    """
    if not quiesce_confirm:
        raise click.ClickException(
            "audit compact REQUIRES --quiesce-confirm because the live "
            "chain MUST be quiesced first (no concurrent writers). "
            "Concurrent writes during compaction WILL corrupt the chain. "
            "See docs/audit-archive-format.md threat-model section before "
            "proceeding."
        )

    from datetime import UTC, datetime

    from signet.audit.backend import JsonlBackend
    from signet.audit.chain import HmacChain
    from signet.audit.compactor import compact_audit_log
    from signet.audit.keyring import Key, KeyRing

    # Parse --before. Accept ``Z`` suffix and bare ISO; reject ambiguity
    # by normalizing to UTC.
    try:
        before_dt = datetime.fromisoformat(before.replace("Z", "+00:00"))
    except ValueError as exc:
        raise click.ClickException(
            f"--before {before!r} is not valid ISO 8601 ({exc}). "
            "Try e.g. '2026-05-01T00:00:00Z'."
        ) from exc
    if before_dt.tzinfo is None:
        before_dt = before_dt.replace(tzinfo=UTC)

    keyring = KeyRing(
        active=Key(
            key_id=key_id,
            secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
        )
    )
    backend = JsonlBackend(audit_log_path)
    chain = HmacChain(backend, keyring)

    # ``compact_audit_log`` raises ``FileExistsError`` when output
    # exists and ``force`` is False. Surface that as a ClickException
    # rather than a Python traceback.
    try:
        result = compact_audit_log(
            chain=chain,
            backend=backend,
            before=before_dt,
            output=output,
            force=force,
        )
    except FileExistsError as exc:
        raise click.ClickException(
            f"refusing to overwrite existing archive at {output}; "
            f"pass --force to override ({exc})"
        ) from exc

    if result is None:
        click.secho(
            f"no-op: nothing before {before_dt.isoformat()}",
            fg="yellow",
        )
        sys.exit(0)

    click.secho("compaction complete:", fg="green")
    click.echo(f"  marker_entry_id:   {result.marker_entry_id}")
    click.echo(f"  merkle_root:       {result.merkle_root}")
    click.echo(f"  compacted_count:   {result.compacted_count}")
    click.echo(f"  range_start:       {result.range[0]}")
    click.echo(f"  range_end:         {result.range[1]}")
    click.echo(f"  archive_path:      {result.archive_path}")
    click.echo(
        "\nverify with:\n"
        f"  signet audit verify {audit_log_path} --hmac-secret <hex> "
        f"--including-archives {result.archive_path.parent}"
    )


@audit.command("report")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
@click.option(
    "--since",
    default="24h",
    show_default=True,
    help=(
        "Duration of the report window. Accepts: <int>m (minutes), "
        "<int>h (hours), <int>d (days), <int>w (weeks), or an ISO 8601 "
        "duration like PT1H30M, P1D, P1W. Examples: 30m, 1h, 24h, 7d, "
        "1w, PT90M."
    ),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    show_default=True,
    help="Output format. ``markdown`` is human-readable; ``json`` is "
    "structured for downstream tooling.",
)
@click.option(
    "--anonymize/--no-anonymize",
    default=True,
    show_default=True,
    help="Hash owner IDs with a salted SHA-256 before rendering. "
    "--no-anonymize emits raw owner IDs (only safe in private "
    "incident-response channels).",
)
@click.option(
    "--anonymize-salt",
    envvar="SIGNET_ANONYMIZE_SALT",
    default=None,
    help="Salt used for owner-ID anonymization. Required with "
    "--anonymize unless SIGNET_ANONYMIZE_SALT env is set.",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    default=None,
    help="HMAC secret as hex. When provided, the chain is verified "
    "and the integrity section reports ok/breaks. Without it the "
    "integrity section is omitted (still safe for ops dashboards).",
)
@click.option(
    "--key-id",
    "key_id",
    envvar="SIGNET_HMAC_KEY_ID",
    default="k1",
    show_default=True,
    help="ID of the active key for chain integrity verification.",
)
@click.option(
    "--service-label",
    "service_label",
    default=None,
    help="Optional service label rendered in the report header (e.g. "
    "'thornveil-prod'). Defaults to omitting the suffix.",
)
def audit_report(
    audit_log_path: Path,
    since: str,
    fmt: str,
    anonymize: bool,
    anonymize_salt: str | None,
    hmac_secret: str | None,
    key_id: str,
    service_label: str | None,
) -> None:
    """Periodic decision summary suitable for dashboards and weekly
    reviews.

    Aggregates decisions, top firing checks, top blocked owners
    (anonymized by default), deltas vs the prior equivalent period,
    and the chain-integrity attestation when --hmac-secret is supplied.
    """
    from datetime import UTC, datetime

    if anonymize and not anonymize_salt:
        raise click.ClickException(
            "--anonymize requires --anonymize-salt or SIGNET_ANONYMIZE_SALT. "
            "Pass --no-anonymize only if you understand the disclosure risk."
        )

    duration = _parse_duration(since)
    now = datetime.now(tz=UTC)
    window_start = now - duration
    prior_start = now - 2 * duration
    prior_end = window_start

    from signet.audit.backend import JsonlBackend, MalformedAuditEntry

    backend = JsonlBackend(audit_log_path)
    cur_window: list[Any] = []
    prior_window: list[Any] = []
    try:
        for entry in backend.iter_entries():
            ts = datetime.fromtimestamp(entry.ts_ns / 1e9, tz=UTC)
            if window_start <= ts <= now:
                cur_window.append(entry)
            elif prior_start <= ts < prior_end:
                prior_window.append(entry)
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    integrity_section: dict[str, Any] | None = None
    if hmac_secret:
        from signet.audit.keyring import Key, KeyRing
        from signet.audit.verifier import ChainVerifier

        keyring = KeyRing(
            active=Key(
                key_id=key_id,
                secret=_parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET"),
            )
        )
        report = ChainVerifier(backend, keyring).verify()
        head_hmac = report.last_known_good_hmac
        integrity_section = {
            "ok": report.ok,
            "breaks": len(report.breaks),
            "head_hmac_short": head_hmac[-8:] if head_hmac else "",
            "total_entries": report.total_entries,
        }

    aggregates = _aggregate_audit_window(
        cur_window,
        anonymize=anonymize,
        salt=anonymize_salt or "",
    )
    prior_aggregates = _aggregate_audit_window(
        prior_window,
        anonymize=anonymize,
        salt=anonymize_salt or "",
    )

    payload = {
        "range": {
            "start": window_start.isoformat(timespec="minutes"),
            "end": now.isoformat(timespec="minutes"),
            "duration": since,
        },
        "service": service_label,
        "signet_version": __version__,
        "total_decisions": aggregates["total"],
        "decision_counts": aggregates["decision_counts"],
        "top_checks": aggregates["top_checks"],
        "top_blocked_owners": aggregates["top_blocked_owners"],
        "deltas": _compute_deltas(aggregates, prior_aggregates),
        "integrity": integrity_section,
        # Carried into the markdown renderer so the section header
        # ("(anonymized)") matches the anonymize flag operators
        # actually passed (A5).
        "anonymize": anonymize,
    }

    if fmt == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    click.echo(_render_audit_report_markdown(payload))


def _parse_duration(spec: str) -> Any:
    """Parse a duration spec to a :class:`datetime.timedelta`.

    Accepted formats:

    * ``<int>m`` — N minutes
    * ``<int>h`` — N hours
    * ``<int>d`` — N days
    * ``<int>w`` — N weeks
    * ISO 8601 duration with a ``P`` prefix — ``P1D``, ``P1W``,
      ``PT1H30M``, ``PT90M``, etc. Years and months are rejected
      because their length depends on the calendar position.

    Raises :class:`click.ClickException` on bad input so the operator
    gets a clear error rather than a ValueError.

    Returns a :class:`datetime.timedelta`; typed as :class:`Any` only
    because importing ``datetime`` at module top would force every
    other CLI subcommand to pay that import even when not needed.
    """
    import re
    from datetime import timedelta

    raw = spec.strip()
    if not raw:
        raise click.ClickException(
            "--since cannot be empty; expected e.g. '30m', '1h', "
            "'24h', '7d', '1w', or an ISO 8601 duration like 'PT1H30M'."
        )

    # Suffix forms first — the original v0.1.6 surface plus minutes
    # and weeks. Reject negatives and overflow before they reach
    # timedelta() (which would raise OverflowError on huge values).
    suffix_match = re.fullmatch(
        r"(\d+)\s*([mhdw])", raw, flags=re.IGNORECASE
    )
    if suffix_match:
        n = int(suffix_match.group(1))
        unit = suffix_match.group(2).lower()
        factor_seconds = {
            "m": 60,
            "h": 3600,
            "d": 86400,
            "w": 604800,
        }[unit]
        try:
            return timedelta(seconds=n * factor_seconds)
        except OverflowError as exc:
            raise click.ClickException(
                f"--since {spec!r} overflows timedelta: {exc}"
            ) from exc

    # ISO 8601 duration — accept ``PnW`` or ``PnDTnHnMnS`` shapes.
    # Years/months are intentionally rejected because their length is
    # ambiguous (a "1 month" report window is meaningless without a
    # calendar anchor). isodate is a third-party dep; rather than
    # adding it just for a fallback, parse the subset we actually
    # care about with a regex.
    iso_match = re.fullmatch(
        r"P(?:(\d+)W"
        r"|(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?)",
        raw,
        flags=re.IGNORECASE,
    )
    if iso_match and any(g is not None for g in iso_match.groups()):
        weeks_grp, days_grp, hours_grp, minutes_grp, seconds_grp = (
            iso_match.groups()
        )
        try:
            if weeks_grp is not None:
                return timedelta(weeks=int(weeks_grp))
            return timedelta(
                days=int(days_grp) if days_grp else 0,
                hours=int(hours_grp) if hours_grp else 0,
                minutes=int(minutes_grp) if minutes_grp else 0,
                seconds=float(seconds_grp) if seconds_grp else 0,
            )
        except OverflowError as exc:
            raise click.ClickException(
                f"--since {spec!r} overflows timedelta: {exc}"
            ) from exc

    raise click.ClickException(
        f"--since {spec!r} is not a valid duration; expected forms: "
        "30m, 1h, 24h, 7d, 1w, or an ISO 8601 duration like PT1H30M, "
        "P1D, P1W. Years/months (P1Y, P1M) are rejected — use weeks "
        "or days for an unambiguous window."
    )


def _aggregate_audit_window(
    entries: list[Any],
    *,
    anonymize: bool,
    salt: str,
) -> dict[str, Any]:
    """Roll up an audit-log window into the report's aggregate fields.

    Memory note: this loads the entries that fall in the window into
    memory before aggregating. For chains with very large 24h windows
    that's the cap on this command's footprint — see the report-back
    note about scalability.
    """
    from collections import Counter

    decision_counts: Counter[str] = Counter()
    check_counts: Counter[str] = Counter()
    check_owner_sets: dict[str, set[str]] = {}
    check_decision_breakdown: dict[str, Counter[str]] = {}
    blocked_owner_counts: Counter[str] = Counter()

    for entry in entries:
        d = entry.decision.value
        decision_counts[d] += 1
        if d in {"block", "escalate", "redact"}:
            check_counts[entry.check_name] += 1
            check_owner_sets.setdefault(entry.check_name, set()).add(str(entry.owner))
            check_decision_breakdown.setdefault(entry.check_name, Counter())[d] += 1
        if d == "block":
            owner_str = str(entry.owner)
            rendered = _maybe_anonymize_owner(owner_str, anonymize=anonymize, salt=salt)
            blocked_owner_counts[rendered] += 1

    top_checks: list[dict[str, Any]] = []
    for name, count in check_counts.most_common(10):
        top_checks.append(
            {
                "name": name,
                "firings": count,
                "distinct_owners": len(check_owner_sets.get(name, set())),
                "by_decision": dict(check_decision_breakdown.get(name, Counter())),
            }
        )
    top_blocked_owners = [
        {"owner": k, "blocks": v} for k, v in blocked_owner_counts.most_common(10)
    ]
    return {
        "total": sum(decision_counts.values()),
        "decision_counts": dict(decision_counts),
        "top_checks": top_checks,
        "top_blocked_owners": top_blocked_owners,
    }


def _maybe_anonymize_owner(owner_str: str, *, anonymize: bool, salt: str) -> str:
    """Render an owner string for the report.

    With ``anonymize=True``, returns ``owner_<8hex>`` where the 8 hex
    characters are the first 8 of ``SHA-256(salt + ":" + owner_str)``.
    With ``anonymize=False``, returns the raw owner string.
    """
    if not anonymize:
        return owner_str
    import hashlib

    h = hashlib.sha256(f"{salt}:{owner_str}".encode()).hexdigest()
    return f"owner_{h[:8]}"


def _compute_deltas(
    cur: dict[str, Any], prior: dict[str, Any]
) -> dict[str, Any]:
    """Compute "current vs prior" deltas the report renders.

    Two notable signals:

    * ``check_pct_delta`` — for every name in the current top-10, what
      was its count in the prior window? Render ``inf`` when the prior
      count was zero (genuinely new firing).
    * ``new_blocked_owners`` — owners in the current top-10 not present
      in the prior top-10. ``len(...)`` is the headline number; the
      list of names is the supporting detail.
    """
    prior_check_counts = {row["name"]: row["firings"] for row in prior.get("top_checks", [])}
    check_pct_delta: list[dict[str, Any]] = []
    for row in cur.get("top_checks", []):
        prev = prior_check_counts.get(row["name"], 0)
        cur_n = row["firings"]
        if prev == 0:
            pct: float | None = float("inf") if cur_n > 0 else 0.0
        else:
            pct = (cur_n - prev) / prev * 100.0
        check_pct_delta.append(
            {
                "name": row["name"],
                "prior": prev,
                "current": cur_n,
                "pct_delta": pct,
            }
        )

    prior_owner_set = {row["owner"] for row in prior.get("top_blocked_owners", [])}
    cur_owner_list = [row["owner"] for row in cur.get("top_blocked_owners", [])]
    new_owners = [o for o in cur_owner_list if o not in prior_owner_set]
    return {
        "check_pct_delta": check_pct_delta,
        "new_blocked_owners": new_owners,
    }


def _strip_utc_suffix(iso: str) -> str:
    """Strip the trailing ``+00:00`` from an ISO 8601 string.

    A12 (v0.1.7): the report header used to render
    ``2026-05-09T12:00+00:00 UTC``, double-tagging the timezone. The
    payload's ISO timestamp is already known to be in UTC by
    construction (``datetime.now(tz=UTC)``), so the explicit ``UTC``
    suffix is the human-readable label and the ``+00:00`` is
    redundant. Strip the offset from the ISO portion before
    interpolating into the markdown.
    """
    return iso.replace("+00:00", "")


def _pluralize_blocks(n: int) -> str:
    """Render ``n blocks`` / ``1 block`` correctly.

    Tiny but worth its own helper because the report renders the
    string in two places (raw and anonymized owner lists) and the bug
    of "1 blocks" was loud enough to flag in ergonomics review.
    """
    return f"{n} block{'s' if n != 1 else ''}"


def _render_audit_report_markdown(payload: dict[str, Any]) -> str:
    """Render the report payload as the operator-facing markdown doc."""
    lines: list[str] = []
    rng = payload["range"]
    service_suffix = f" @ {payload['service']}" if payload.get("service") else ""
    lines.append("# signet audit report")
    lines.append(
        f"**Range:** {_strip_utc_suffix(rng['start'])} -> "
        f"{_strip_utc_suffix(rng['end'])} UTC ({rng['duration']})"
    )
    lines.append(
        f"**Service:** signet {payload['signet_version']}{service_suffix}"
    )
    lines.append(f"**Total decisions:** {payload['total_decisions']:,}")
    lines.append("")

    lines.append("## Decision distribution")
    lines.append("| Decision  | Count | %     |")
    lines.append("|-----------|-------|-------|")
    total = max(1, payload["total_decisions"])
    for d in ("allow", "block", "escalate", "redact"):
        n = payload["decision_counts"].get(d, 0)
        pct = n / total * 100.0
        lines.append(f"| {d:<9} | {n:>5} | {pct:5.1f}% |")
    lines.append("")

    lines.append("## Top firing checks (block + escalate + redact)")
    if not payload["top_checks"]:
        lines.append("(no block/escalate/redact decisions in the window)")
    else:
        for i, row in enumerate(payload["top_checks"], start=1):
            by = row.get("by_decision", {})
            if by and len(by) > 1:
                breakdown = ", ".join(f"{v} {k}" for k, v in sorted(by.items()))
                detail = f"{row['firings']} firings ({breakdown})"
            else:
                detail = (
                    f"{row['firings']} firings, {row['distinct_owners']} distinct owners"
                )
            lines.append(f"{i}. `{row['name']}` -- {detail}")
    lines.append("")

    # A5 (v0.1.7): only mark the section header as "(anonymized)" when
    # owners actually were anonymized. The previous header was
    # hard-coded regardless of the --anonymize/--no-anonymize flag.
    is_anonymized = bool(payload.get("anonymize", True))
    if payload.get("top_blocked_owners"):
        if is_anonymized:
            lines.append("## Top blocked owners (anonymized)")
        else:
            lines.append("## Top blocked owners")
        for i, row in enumerate(payload["top_blocked_owners"], start=1):
            lines.append(
                f"{i}. `{row['owner']}` -- {_pluralize_blocks(row['blocks'])}"
            )
        lines.append("")
    else:
        lines.append("")

    lines.append("## Notable deltas vs prior period")
    deltas = payload.get("deltas", {})
    rendered_any = False
    for d in deltas.get("check_pct_delta", []):
        pct = d["pct_delta"]
        if pct is None or pct == 0.0:
            continue
        if pct == float("inf"):
            lines.append(
                f"- `{d['name']}` firings NEW in this window "
                f"({d['current']} firings; prior=0)"
            )
        else:
            arrow = "up" if pct > 0 else "down"
            lines.append(
                f"- `{d['name']}` firings {arrow} {abs(pct):.0f}% "
                f"({d['prior']} -> {d['current']})"
            )
        rendered_any = True
    new_owners = deltas.get("new_blocked_owners", [])
    if new_owners:
        lines.append(
            f"- New blocked owners: {len(new_owners)} first-time appearances "
            "in the top-10"
        )
        rendered_any = True
    if not rendered_any:
        lines.append("(no notable deltas)")
    lines.append("")

    if payload.get("integrity"):
        i = payload["integrity"]
        lines.append("## Audit chain integrity")
        lines.append(f"- Verified: ok={i['ok']}, breaks={i['breaks']}")
        if i.get("head_hmac_short"):
            lines.append(f"- Head HMAC (last 8 hex): `{i['head_hmac_short']}`")
        lines.append(f"- Total entries (entire chain): {i['total_entries']:,}")
    return "\n".join(lines).rstrip() + "\n"


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
        click.secho(
            f"OK: pipeline passes the v{__version__} lint checks.",
            fg="green",
        )
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


@main.group()
def plugins() -> None:
    """Plugin discovery and management.

    signet discovers third-party plugins via Python entry points under
    these groups:

    \b
    - signet.checks: full Check subclasses
    - signet.adapters: HTTP adapter shims
    - signet.anchors: external anchor backends

    Each discovered plugin is reported with one of four statuses:

    \b
    - loaded: ABI-compatible, ready to use
    - incompatible_abi: declares a CHECK_ABI_VERSION signet doesn't know
    - load_error: import/instantiation failed
    - duplicate_name: another package registers the same (group, name)

    Use 'signet plugins list' to see what's installed and 'signet plugins
    doctor' to gate CI on plugin health.
    """


@plugins.command("list")
@click.option(
    "--group",
    type=click.Choice(["signet.checks", "signet.adapters", "signet.anchors", "all"]),
    default="all",
    show_default=True,
    help="Restrict the listing to a single entry-point group.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a JSON array matching the DiscoveredPlugin shape.",
)
def plugins_list(group: str, as_json: bool) -> None:
    """List discovered plugins.

    Reports every entry point under ``signet.checks``,
    ``signet.adapters`` and ``signet.anchors``, including
    ``loaded``, ``incompatible_abi`` and ``load_error`` statuses so
    misconfiguration is visible (rather than silently dropped).
    """
    from signet.plugins import discover_plugins

    plugins_found = discover_plugins(refresh=True)
    if group != "all":
        plugins_found = [p for p in plugins_found if p.group == group]

    if as_json:
        payload = []
        for p in plugins_found:
            payload.append(
                {
                    "group": p.group,
                    "name": p.name,
                    "package": p.package,
                    "package_version": p.package_version,
                    "target": p.target,
                    "status": p.status,
                    "abi_declared": p.abi_declared,
                    "abi_required": p.abi_required,
                    "error": p.error,
                }
            )
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    # Group rows by group for readability. Order: checks, adapters,
    # anchors. Empty sections render an explicit "(none)" line so the
    # operator can tell "no plugins" apart from "we forgot to scan".
    group_titles = {
        "signet.checks": "INSTALLED CHECKS",
        "signet.adapters": "INSTALLED ADAPTERS",
        "signet.anchors": "INSTALLED ANCHORS",
    }
    seen_any = False
    for grp in ("signet.checks", "signet.adapters", "signet.anchors"):
        if group != "all" and group != grp:
            continue
        rows = [p for p in plugins_found if p.group == grp]
        click.echo(f"\n{group_titles[grp]} ({len(rows)})")
        if not rows:
            click.echo("  (none)")
            continue
        seen_any = True
        # Compute aligned columns. ``name`` and ``package`` have the
        # widest variance.
        name_w = max(len(p.name) for p in rows)
        pkg_w = max(len(_render_pkg(p)) for p in rows)
        for p in rows:
            pkg = _render_pkg(p)
            abi_seg = ""
            if grp == "signet.checks":
                abi = p.abi_declared if p.abi_declared is not None else "?"
                abi_seg = f"ABI {abi:<3}"
            status_seg = _render_plugin_status(p)
            line = f"  {p.name:<{name_w}}  {pkg:<{pkg_w}}  {abi_seg:<8}{status_seg}".rstrip()
            color = (
                "green"
                if p.status == "loaded"
                else "red"
                if p.status == "load_error"
                else "yellow"
            )
            click.secho(line, fg=color)

    if not seen_any and group == "all":
        click.echo("\n(no plugins discovered; install signet plugin packages "
                   "to populate this list)")


@plugins.command("doctor")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit a JSON object describing the issues found.",
)
def plugins_doctor(as_json: bool) -> None:
    """Lint the discovered plugin set and exit non-zero on any issue.

    Wraps :func:`discover_plugins` (with refresh on) and reports two
    classes of failure that ``plugins list`` would otherwise show
    only via color in the terminal:

    * **Duplicate (group, name) pairs** — two plugin packages
      registering the same entry-point name within one group. The
      resolver picks one and silently shadows the other; in CI you
      want the build to fail.
    * **Plugins with non-loaded status** — ``incompatible_abi`` (the
      plugin declares a CHECK_ABI_VERSION signet does not accept) and
      ``load_error`` (import or type-validation failure during
      :meth:`EntryPoint.load`).

    Exit code is 0 when both classes are empty, 1 otherwise. Intended
    to be the CI gate for plugin-heavy deployments — pair with
    ``signet lint --strict`` and ``signet doctor --probe-injection``.
    """
    from signet.plugins import discover_plugins

    plugins_found = discover_plugins(refresh=True)

    # Detect duplicate (group, name) pairs. ``discover_plugins`` does
    # not deduplicate — both entries surface as separate
    # ``DiscoveredPlugin`` rows — so we can group them here.
    seen: dict[tuple[str, str], list[Any]] = {}
    for p in plugins_found:
        seen.setdefault((p.group, p.name), []).append(p)
    duplicates = {
        (group, name): rows
        for (group, name), rows in seen.items()
        if len(rows) > 1
    }

    # Plugins that failed to come up at all.
    failed = [p for p in plugins_found if p.status != "loaded"]

    if as_json:
        payload = {
            "ok": not duplicates and not failed,
            "duplicate_count": len(duplicates),
            "failed_count": len(failed),
            "duplicates": [
                {
                    "group": group,
                    "name": name,
                    "packages": [_render_pkg(r) for r in rows],
                }
                for (group, name), rows in sorted(duplicates.items())
            ],
            "failed": [
                {
                    "group": p.group,
                    "name": p.name,
                    "package": _render_pkg(p),
                    "status": p.status,
                    "error": p.error,
                }
                for p in failed
            ],
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        sys.exit(0 if payload["ok"] else 1)

    issues = 0
    if duplicates:
        click.secho(
            f"DUPLICATE PLUGIN NAMES ({len(duplicates)})", fg="red", bold=True
        )
        for (group, name), rows in sorted(duplicates.items()):
            packages = ", ".join(_render_pkg(r) for r in rows)
            click.secho(
                f"  [{group}] {name} registered by: {packages}", fg="red"
            )
        issues += len(duplicates)
        click.echo("")

    if failed:
        click.secho(
            f"PLUGINS WITH NON-LOADED STATUS ({len(failed)})",
            fg="red",
            bold=True,
        )
        for p in failed:
            click.secho(
                f"  [{p.group}] {p.name} ({_render_pkg(p)}): "
                f"{p.status} -- {p.error or 'unknown'}",
                fg="red",
            )
        issues += len(failed)
        click.echo("")

    if issues == 0:
        click.secho(
            f"OK: {len(plugins_found)} plugin(s) discovered, all loaded "
            "cleanly with unique (group, name) pairs.",
            fg="green",
        )
        sys.exit(0)

    click.secho(
        f"FAIL: {issues} plugin issue(s) detected; resolve before deploy.",
        fg="red",
    )
    sys.exit(1)


def _render_pkg(p: Any) -> str:
    """Render a plugin's package name + version in one column.

    Empty package strings happen for dynamically-registered entry
    points (test fixtures, in-process registration). Render those as
    ``-`` so the column never collapses.
    """
    pkg = p.package or "-"
    ver = p.package_version or ""
    return f"{pkg} {ver}".strip() if pkg != "-" else "-"


def _render_plugin_status(p: Any) -> str:
    """Format the status column for one plugin."""
    if p.status == "loaded":
        return "loaded"
    if p.status == "incompatible_abi":
        # Use the structured error if present; otherwise synthesize.
        err = p.error or (
            f"declares CHECK_ABI_VERSION={p.abi_declared}; "
            f"signet requires {p.abi_required}"
        )
        return f"incompatible_abi: {err}"
    if p.status == "load_error":
        return f"load_error: {p.error or 'unknown'}"
    return p.status  # forward-compat for new statuses


@main.command()
@click.argument("entry_id")
@click.option(
    "--audit-log",
    "audit_log_path",
    default=Path("audit.jsonl"),
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="SIGNET_AUDIT_LOG_PATH",
    help="Path to the JSONL audit chain.",
)
@click.option(
    "--hmac-secret",
    envvar="SIGNET_HMAC_SECRET",
    default=None,
    help="HMAC secret as hex. When provided, the entry's HMAC is "
    "verified against this key and the hmac line is annotated as "
    "``(verified against ring <key-id>)``. Without it, the hmac is "
    "rendered unverified.",
)
@click.option(
    "--key-id",
    "key_id",
    default="k1",
    show_default=True,
    envvar="SIGNET_HMAC_KEY_ID",
    help="ID of the active key to verify against when --hmac-secret "
    "is provided.",
)
def replay(
    entry_id: str,
    audit_log_path: Path,
    hmac_secret: str | None,
    key_id: str,
) -> None:
    """Pretty-print the audit row for ENTRY_ID.

    First-class incident-response surface. Hand it the
    ``correlation_id`` from a 403/202 refusal body and it prints the
    full audit row with field labels aligned. With
    ``SIGNET_HMAC_SECRET`` (or ``--hmac-secret``) configured, the hmac
    line is verified against the active key and annotated.

    Equivalent to ``signet audit show <id>`` (which remains as the
    canonical alias). Exit 0 if found, 1 if not.
    """
    _replay_pretty_print(
        entry_id=entry_id,
        audit_log_path=audit_log_path,
        hmac_secret=hmac_secret,
        key_id=key_id,
    )


def _show_entry(entry_id: str, audit_log_path: Path) -> None:
    from signet.audit.backend import JsonlBackend, MalformedAuditEntry

    # UUIDs are case-insensitive per RFC 4122; operators paste from
    # logs with whatever case the source rendered them in. Normalize
    # both sides to lowercase for the compare.
    target = entry_id.strip().lower()
    backend = JsonlBackend(audit_log_path)
    try:
        for entry in backend.iter_entries():
            if entry.entry_id.lower() == target:
                click.echo(json.dumps(entry.to_dict(), indent=2, sort_keys=True))
                return
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc
    click.secho(f"no entry with id {entry_id!r} found in {audit_log_path}", fg="red")
    sys.exit(1)


def _replay_pretty_print(
    *,
    entry_id: str,
    audit_log_path: Path,
    hmac_secret: str | None,
    key_id: str,
) -> None:
    """Look up ENTRY_ID in ``audit_log_path`` and pretty-print it.

    Output format mirrors the ``signet replay`` example in the v0.1.6
    docs: aligned ``label: value`` rows, ISO timestamps, indented
    metadata block, and an optional ``(verified against ring k1)``
    annotation on the hmac line when ``hmac_secret`` is supplied and
    the recomputed HMAC matches.
    """
    import hashlib
    import hmac as _hmac

    from signet.audit.backend import JsonlBackend, MalformedAuditEntry
    from signet.audit.chain import KEY_ID_FIELD, _serialize_for_signing

    target = entry_id.strip().lower()
    backend = JsonlBackend(audit_log_path)
    found = None
    try:
        for entry in backend.iter_entries():
            if entry.entry_id.lower() == target:
                found = entry
                break
    except MalformedAuditEntry as exc:
        raise _malformed_audit_to_click_exception(exc) from exc

    if found is None:
        click.secho(f"no entry with id {entry_id!r} found in {audit_log_path}", fg="red")
        sys.exit(1)

    ts_iso = _ns_to_iso(found.ts_ns)
    hmac_full = found.hmac or ""
    hmac_short = (hmac_full[:8] + "...") if hmac_full else "(none)"
    hmac_suffix = ""
    if hmac_secret:
        secret = _parse_hex_secret(hmac_secret, "--hmac-secret/SIGNET_HMAC_SECRET")
        entry_key_id = str(found.metadata.get(KEY_ID_FIELD, key_id))
        try:
            payload = _serialize_for_signing(found)
            recomputed = _hmac.new(secret, payload, hashlib.sha256).hexdigest()
        except Exception as exc:  # pragma: no cover — payload integrity issue
            hmac_suffix = f"  (verification error: {type(exc).__name__})"
        else:
            if _hmac.compare_digest(recomputed, hmac_full):
                hmac_suffix = f"  (verified against ring {entry_key_id})"
            else:
                hmac_suffix = f"  (FAILED verification against ring {entry_key_id})"
    else:
        hmac_suffix = "  (unverified — pass --hmac-secret/SIGNET_HMAC_SECRET to check)"

    # Render aligned label: value rows. Width chosen to line up the
    # documented fields.
    rows: list[tuple[str, str]] = [
        ("entry_id", found.entry_id),
        ("ts", ts_iso),
        ("owner", str(found.owner)),
        # ``_stage`` is the convention used elsewhere (audit count, tail) for
        # surfacing the pipeline stage out of metadata. Fall back to "-".
        ("stage", str(found.metadata.get("_stage", "-"))),
        ("check", found.check_name),
        ("decision", found.decision.value),
        ("reason", found.reason),
    ]
    label_width = max(len(label) for label, _ in rows) + 1  # ":"
    for label, value in rows:
        click.echo(f"{(label + ':').ljust(label_width)}    {value}")

    # Metadata block. Skip the chain-internal fields (key id, anchor
    # receipt) by default — they're load-bearing for the chain but
    # noisy for an operator paging through one row. Show them under a
    # collapsed "_chain" line so power users still see they exist.
    visible_meta: dict[str, Any] = {}
    chain_meta_keys: list[str] = []
    for k, v in found.metadata.items():
        if k.startswith("_"):
            chain_meta_keys.append(k)
        else:
            visible_meta[k] = v

    click.echo("metadata:".ljust(label_width))
    if not visible_meta and not chain_meta_keys:
        click.echo("    (none)")
    else:
        # Inner alignment for the metadata sub-rows.
        meta_label_w = max((len(k) for k in visible_meta), default=0) + 1
        for k, v in visible_meta.items():
            click.echo(f"  {(k + ':').ljust(meta_label_w)}  {v}")
        if chain_meta_keys:
            click.echo(f"  (chain-internal: {', '.join(sorted(chain_meta_keys))})")

    click.echo(f"{('hmac:').ljust(label_width)}    {hmac_short}{hmac_suffix}")
    sys.exit(0)


@main.command()
@click.argument(
    "target_dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("."),
)
def init(target_dir: Path) -> None:
    """Scaffold a starter signet project (config + sample pipeline).

    Writes four files into TARGET_DIR (current directory by default):

    \b
    - pipeline.py: a four-check pipeline (OwnerResolutionCheck,
      ClassificationGateCheck, RateLimitCheck, ScopeDriftCheck) you
      hand to ``signet serve --config``.
    - client_example.py: a minimal OpenAI-Python client that points
      at the local proxy and sends ``X-Commit-Owner`` so the gate
      has an attributable identity to record.
    - .env.example: the environment variables ``signet serve``
      reads (upstream URL, audit-log path, HMAC secret).
    - .gitignore: keeps ``.env`` and ``*.jsonl`` audit logs out of
      version control on first ``git add``.

    Per-file overwrite policy: each file is written only if it does
    not already exist. Pre-existing files are skipped with a
    ``skipped (already exists)`` line so an operator who deleted
    just ``pipeline.py`` (the most common "let me regenerate this
    one" workflow) can re-run ``signet init`` and get exactly that
    file back without losing edits to ``client_example.py`` or
    ``.env.example``. If every file is already present, the command
    refuses with exit code 1 — this preserves the original "do not
    overwrite an existing project" guard.

    Post-init checklist:

    \b
    1. Review the four scaffolded files and edit them for your env.
    2. ``signet serve --upstream <URL> --dev`` (the ``--dev`` shorthand
       wires up an ephemeral HMAC key, an in-tmp audit log, and
       ``--config pipeline.py`` for local iteration).
    3. In another terminal, ``python client_example.py``.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    pipeline_path = target_dir / "pipeline.py"
    env_path = target_dir / ".env.example"
    gitignore_path = target_dir / ".gitignore"
    client_path = target_dir / "client_example.py"

    files: list[tuple[Path, str]] = [
        (pipeline_path, _PIPELINE_TEMPLATE),
        (env_path, _ENV_TEMPLATE),
        (client_path, _CLIENT_EXAMPLE_TEMPLATE),
        (gitignore_path, _GITIGNORE_TEMPLATE),
    ]

    # If every scaffolded file already exists, the operator is calling
    # init on an already-initialized directory — refuse so we don't
    # silently no-op. Mirrors the v0.1.6 contract that an existing
    # ``pipeline.py`` is load-bearing.
    if all(path.exists() for path, _ in files):
        click.secho(
            f"refusing to overwrite existing {pipeline_path}", fg="yellow"
        )
        sys.exit(1)

    wrote_any = False
    for path, content in files:
        if path.exists():
            click.secho(f"  skipped (already exists): {path}", fg="yellow")
            continue
        path.write_text(content, encoding="utf-8")
        click.secho(f"  wrote {path}", fg="green")
        wrote_any = True

    if not wrote_any:
        # Defensive: the all-exist branch above should already have
        # exited. Keeps mypy and humans happy.
        sys.exit(1)

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
    from signet.checks.rate_limit import RateLimitCheck
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

    # Rule 1 (SIG001 — v0.1.6 repurpose, v0.1.7 docstring fix):
    # The original v0.1.4 SIG001 fired on declared-position misordering of
    # RateLimitCheck before content checks. v0.1.5 made that moot: the
    # check's class-level ``priority=100`` self-orders it last within
    # ADMISSION regardless of registration order. The remaining footgun
    # is operators who SUBCLASS ``RateLimitCheck`` and override the
    # class-level ``priority`` attribute below 100 (e.g.
    # ``class FastRL(RateLimitCheck): priority = 10``), which re-creates
    # the original drain-on-refused-request behavior.
    #
    # IMPORTANT: ``RateLimitCheck.__init__`` does NOT accept a
    # ``priority=`` keyword argument. v0.1.6 of this file's docstring
    # incorrectly suggested it did. The lint logic itself is correct —
    # it inspects the class-level attribute exposed via ``c.priority`` —
    # but the only way for operators to make it fire is to subclass and
    # override the class attr. Treat the rule as catching subclass
    # overrides, not constructor arguments.
    #
    # CHANGELOG: SIG001 was repurposed in v0.1.6. Its original
    # registration-order check was retired alongside the v0.1.5 priority
    # default. The rule now fires on explicit priority<100 overrides
    # via subclass, surfaced through the resolved ``c.priority``.
    for c in checks_by_index:
        if not isinstance(c, RateLimitCheck):
            continue
        # The class default is 100. ``c.priority`` may be a class attr
        # (subclass override — the documented trigger) or an instance
        # attr (rare, but possible if an operator monkey-patches one).
        # Compare to 100 directly.
        rl_priority = getattr(c, "priority", 100)
        if isinstance(rl_priority, int) and rl_priority < 100:
            findings.append(
                _LintFinding(
                    code="SIG001",
                    severity="warning",
                    message=(
                        f"RateLimitCheck has priority={rl_priority}; values < 100 "
                        "recreate the v0.1.4 footgun where rate limits drain "
                        "on downstream-blocked requests. The most common "
                        "trigger is a subclass override "
                        "(`class FastRL(RateLimitCheck): priority = 10`); "
                        "RateLimitCheck.__init__ does not accept priority "
                        "as a keyword argument."
                    ),
                    hint=(
                        "Remove the subclass priority override and keep the "
                        "default of 100 unless you specifically need rate "
                        "limiting to run before content checks."
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
    # C5 (v0.1.7): Wrap the exec so the operator sees a one-line
    # ClickException instead of a Python traceback when ``signet lint``
    # / ``signet serve --config`` is pointed at a file with a syntax or
    # import error. The traceback is the wrong UX for a CLI surface —
    # they want to know which file and which line, not the Python call
    # stack. The broad catch is intentional: arbitrary user code may
    # raise anything at import time (NameError, AttributeError, ...).
    try:
        spec.loader.exec_module(module)
    except SyntaxError as exc:
        raise click.ClickException(
            f"syntax error in {path}: {exc.msg} at line {exc.lineno}"
        ) from exc
    except ImportError as exc:
        raise click.ClickException(
            f"failed to import {path}: {exc}"
        ) from exc
    except click.ClickException:
        # Don't double-wrap — _load_pipeline_from_path may be called
        # transitively. Pass through.
        raise
    except Exception as exc:
        raise click.ClickException(
            f"failed to load {path}: {type(exc).__name__}: {exc}"
        ) from exc
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
