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
from pathlib import Path
from typing import TYPE_CHECKING

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
    "--audit-log audit.jsonl, --config pipeline.py. Each is only set "
    "if not otherwise specified. Equivalent to typing all three; "
    "intended for local development only.",
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
) -> None:
    """Run the signet proxy."""
    import uvicorn

    from signet.core.pipeline import Pipeline
    from signet.server.app import SignetApp
    from signet.server.config import ServerConfig

    # --dev shorthand: fill in the three obvious dev defaults if the
    # user did not pass them explicitly. This keeps the most common
    # local invocation down to `signet serve --upstream <url> --dev`.
    if dev:
        if not allow_ephemeral_key and not hmac_secret:
            allow_ephemeral_key = True
        if audit_log_path is None:
            audit_log_path = Path("audit.jsonl")
        if config_path is None and Path("pipeline.py").exists():
            config_path = Path("pipeline.py")

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

    Exit code is 0 on success, 1 if any probe failed.
    """
    import platform

    import httpx

    failed = False

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
def audit_verify(log_path: Path, hmac_secret: str, key_id: str) -> None:
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
