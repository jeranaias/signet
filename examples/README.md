# signet deployment examples

| Recipe | Use case |
|---|---|
| [docker-compose](docker-compose/) | Local development, single-node prod |
| [github-action](github-action/) | CI gating: lint + probe + bench |
| [kubernetes](kubernetes/) | Multi-replica production |

Each example is paste-and-go. Reach for the one closest to your
target.

## Per-language client examples

The Python adapter examples (`openai_example.py`, `anthropic_example.py`,
`langchain_example.py`) live in this directory too. They assume signet
is already running -- pair them with whichever deployment recipe
matches your environment.

## Version alignment

All three deployment recipes pin `signet-sign==0.1.8`. When you bump
the package version in production, bump the pin here in lockstep so
the examples never drift behind a documented release.
