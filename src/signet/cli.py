"""signet CLI — operations interface.

Four subcommands:

* ``signet serve`` — run the FastAPI proxy.
* ``signet audit verify`` — walk an HMAC-chained audit log and report
  any tampering.
* ``signet replay`` — reproduce a past decision from an audit row;
  useful for incident response and check development.
* ``signet init`` — scaffold a starter config + sample pipeline file.

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
def serve(
    upstream_url: str,
    host: str,
    port: int,
    audit_log_path: Path | None,
    hmac_secret: str | None,
    allow_ephemeral_key: bool,
    config_path: Path | None,
) -> None:
    """Run the signet proxy."""
    import uvicorn

    from signet.core.pipeline import Pipeline
    from signet.server.app import SignetApp
    from signet.server.config import ServerConfig

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
    )

    app = SignetApp(config=cfg, pipeline=pipeline).app
    # ASCII arrow (-> not →) so the banner renders on Windows cp1252 stdout
    # without UnicodeEncodeError when the user has not reconfigured their
    # console code page. See v0.1.0 → v0.1.1 release notes.
    click.echo(f"signet {__version__} -> {upstream_url}  (listening on {host}:{port})")

    # Print loaded checks so operators can verify the configuration
    # without re-reading the file. Quiet on the empty-pipeline path
    # since the warning above is already loud about it.
    if pipeline.checks:
        click.echo(f"pipeline ({len(pipeline.checks)} checks):")
        for c in pipeline.checks:
            click.echo(f"  [{c.stage.value}] {c.name}")

    uvicorn.run(app, host=host, port=port, log_level="info")


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


@main.command()
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
    """Show the audit row for ENTRY_ID. (Does NOT re-execute the pipeline yet.)

    Deterministic re-evaluation of ADMISSION-stage checks against an
    archived request requires the original request body to be stored
    alongside the audit row — that's roadmap, not v0.1. For now this
    command reads the matching entry, pretty-prints it, and exits 0.
    Useful for incident response (`why did we block this entry?`) and
    for confirming receipts; not yet useful for pipeline regression
    testing against historical traffic.
    """
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

    if pipeline_path.exists():
        click.secho(f"refusing to overwrite existing {pipeline_path}", fg="yellow")
        sys.exit(1)

    pipeline_path.write_text(_PIPELINE_TEMPLATE, encoding="utf-8")
    env_path.write_text(_ENV_TEMPLATE, encoding="utf-8")
    # Also drop a .gitignore so the user doesn't accidentally commit
    # their HMAC secret (.env) or audit log (potentially sensitive
    # owner attribution data) on first push. Leave any existing
    # .gitignore alone.
    if not gitignore_path.exists():
        gitignore_path.write_text(_GITIGNORE_TEMPLATE, encoding="utf-8")
        click.secho(f"  wrote {gitignore_path}", fg="green")

    click.secho(f"  wrote {pipeline_path}", fg="green")
    click.secho(f"  wrote {env_path}", fg="green")
    click.echo("\nnext: review the files, then run:")
    click.echo("  signet serve --upstream http://localhost:11434/v1 --config pipeline.py \\")
    click.echo("    --audit-log audit.jsonl --allow-ephemeral-key")


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


if __name__ == "__main__":
    main()
