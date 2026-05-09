"""Internal helpers used by ``signet.cli``.

Modules under this package back specific subcommands but are kept out of
``cli.py`` so the dispatcher stays readable. None of these are part of
the public API; consumers should reach for the CLI itself.
"""

from __future__ import annotations
