> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# X12 — CTF Toolkit & Challenge Authorship

Offline CTF challenge kit: generates real web, crypto, and misc challenges with flags, a SQLite scoreboard, and a solver-checker that solves each challenge and verifies recovered flags against stored hashes.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/x12-ctf.svg)](https://github.com/5h4d0wn1k/x12-ctf)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/x12-ctf.svg)](https://github.com/5h4d0wn1k/x12-ctf)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/x12-ctf.svg)](https://github.com/5h4d0wn1k/x12-ctf)

## Why

CTFs are the best hands-on school for offensive security — and the worst place to skip the "challenge ≠ real target" boundary. X12 builds genuine challenges and solves them for real: a working stdlib HTTP server exposes a leaked admin token, a repeat-key-XOR ciphertext is broken from its `FLAG{` prefix, and a carved disk image yields a base64-payload flag. A SQLite scoreboard stores only SHA-256 flag hashes and verifies every solve. Everything runs offline on localhost, so the mechanics are real and the blast radius is zero.

## Features

- **Real challenge generator** — writes `web_app.py`, `flag.txt`, `crypto_flag.enc`, `misc_drive.img` and a hashes-only `manifest.json`
- **Web challenge (WEB-001)** — live stdlib HTTP server with a token-gated admin area; solver recovers a token from page source
- **Crypto challenge (CRYPTO-001)** — repeat-key-XOR ciphertext; known-plaintext key recovery then full decrypt
- **Misc challenge (MISC-001)** — noisy disk image; magic-marker carving + base64 decode
- **SQLite scoreboard** — SHA-256 flag hashes, duplicate-safe, reject-wrong-flag, solve tallies
- **Solver-checker pipeline** — generate → solve → submit with a JSON report; deterministic `--seed N` reproduction

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/x12-ctf.git && cd x12-ctf

# Full offline demo: generate -> solve -> scoreboard (temp dir, self-cleaning)
python3 firmware/ctf_toolkit.py

# Generate challenge artifacts into challenges/
python3 firmware/ctf_toolkit.py --generate

# Solve + verify against the scoreboard
python3 firmware/ctf_toolkit.py --solve

# Full run + reports/ctf_report.json
python3 firmware/ctf_toolkit.py --demo-report

# Use as a library
from ctf_toolkit import ChallengeGenerator, WebSolver, Scoreboard
gen = ChallengeGenerator("out")
manifest = gen.generate_all()
flag = WebSolver().solve("out")

# Unit tests (22 assertions)
python3 -m unittest discover -s tests
```

## Project structure

- `firmware/ctf_toolkit.py` — generator, solvers, scoreboard and CLI
- `tests/` — 22 deterministic assertions (wrong-flag rejection, live-server token gate, plaintext-free manifest, end-to-end runs)

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New challenge categories, solvers and scoreboard features are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); challenges stay synthetic and are for authorized competitions and labs only.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized CTF use only.