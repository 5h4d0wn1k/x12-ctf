# X12 — CTF Toolkit + Challenge Authorship

Generator of real local challenges (web / crypto / misc) with flags, a SQLite
scoreboard, and a solver-checker that solves each challenge and verifies the
recovered flags against stored hashes. Fully offline on localhost.

## Overview

This project implements a genuine CTF harness where every stage does real work:

- **Web challenge (WEB-001)**: the generator writes an actual stdlib HTTP server
  (`web_app.py`) that serves an index page, an admin area and a `flag.txt`
  "flag database". The solver walks the live application over HTTP on an
  ephemeral `127.0.0.1` port: fetch `/`, recover the admin token from the page
  source, then authenticate to `/admin` and extract the flag from the response.
- **Crypto challenge (CRYPTO-001)**: the generator writes a real repeat-key-XOR
  ciphertext (`crypto_flag.enc`). The solver performs a known-plaintext key
  recovery from the `FLAG{` prefix, then decrypts the whole flag.
- **Misc challenge (MISC-001)**: the generator writes a noisy disk image
  (`misc_drive.img`). The solver carves bytes after the magic marker and
  base64-decodes the hidden payload.
- **SQLite scoreboard**: each challenge is registered with a SHA-256 hash of its
  flag (never the plaintext). `submit()` verifies a solver's flag against the
  stored hash, records accepted solves with timestamps, rejects wrong or
  duplicate submissions, and tallies scores.
- **Solver-checker pipeline**: generate → solve → submit — the demo asserts all
  three flags are accepted by the scoreboard and writes `reports/ctf_report.json`.

## Features

- **Real challenge generator**: creates runnable web server source, ciphertext,
  disk image and a JSON `manifest.json` (hashes only, no plaintext flags)
- **Real web solving**: HTTP requests against a live localhost stdlib server
- **Real crypto solving**: known-plaintext repeat-key-XOR key recovery
- **Real misc solving**: byte-level marker carving + base64 decode
- **SQLite scoreboard**: persistent, hash-verified, duplicate-safe, size-accounting
- **Deterministic seeds**: `--seed N` reproduces identical challenges/flags
- **CLI**: `--generate`, `--solve`, `--demo-report`, `--dry-run`
- **Legal disclaimer**: Heavy authorization/lab-use-only requirements

## Installation

```bash
# No external dependencies required — pure Python standard library
python3 firmware/ctf_toolkit.py
```

## Usage

```bash
# Full offline demo: generate -> solve -> scoreboard (temp dir, self-cleaning)
python3 firmware/ctf_toolkit.py

# Generate challenge artifacts into challenges/
python3 firmware/ctf_toolkit.py --generate

# Solve + verify against the scoreboard
python3 firmware/ctf_toolkit.py --solve

# Full run + reports/ctf_report.json
python3 firmware/ctf_toolkit.py --demo-report

# Import as module
from ctf_toolkit import ChallengeGenerator, WebSolver, CryptoSolver, \
    MiscSolver, Scoreboard
gen = ChallengeGenerator("out")
manifest = gen.generate_all()
flag = WebSolver().solve("out")          # real HTTP against the generated server
sb = Scoreboard("out/scoreboard.db")
sb.register_manifest_hashes(manifest)
print(sb.submit("WEB-001", flag))        # {'accepted': True, ...}
```

## Example Output

```
[*] X12 — CTF Toolkit + Challenge Authorship
[*] Offline demo: generate -> solve -> SQLite scoreboard

[*] Generated 3 challenges in /tmp/x12_ctf_abc123
  [PASS] WEB-001: FLAG{web_leak_admin_token_0135282b} (flag accepted)
  [PASS] CRYPTO-001: FLAG{crypto_repeat_key_xor_knwn_pt} (flag accepted)
  [PASS] MISC-001: FLAG{misc_carve_the_disk_image} (flag accepted)
[+] Report written: .../reports/ctf_report.json

======================================================================
  Self-test PASSED. Demo complete.
  Legal: This toolkit is for authorized CTF/lab use only.
======================================================================
```

## Live Lab Test Plan

1. `python3 firmware/ctf_toolkit.py` — generates 3 real challenges, solves each
   (web = live HTTP against the spawned stdlib server, crypto = XOR key
   recovery, misc = disk-image carving), submits all flags to the SQLite
   scoreboard; every flag is `flag accepted`; exit 0.
2. `python3 firmware/ctf_toolkit.py --generate --workdir /tmp/ctf-out` — writes
   `web_app.py`, `flag.txt`, `crypto_flag.enc`, `misc_drive.img`, `manifest.json`.
3. `python3 firmware/ctf_toolkit.py --solve --workdir /tmp/ctf-out` — runs the
   solver-checker and writes `scoreboard.db` with exactly 3 accepted solves.
4. `python3 -m unittest discover -s tests` — 22 deterministic assertions,
   including wrong-flag rejection, duplicate-solve rejection, plaintext-free
   manifest, live-server token gate, and end-to-end generate→solve→score.

## Metrics

- 3 challenge categories (web/crypto/misc), each with distinct real mechanics
- Web: real HTTP exchange over `127.0.0.1:<ephemeral>`; wrong token returns 401/no flag
- Crypto: repeat-key XOR, key length 5, recovered purely from the `FLAG{` prefix
- Scoreboard: SQLite, SHA-256 flag hashes, duplicate-safe, solve tallies
- Manifest stores 0 plaintext flags (only SHA-256 digests)
- `reports/ctf_report.json` (gitignored); `challenges/`, `reports/`, `scoreboard.db` gitignored
- 22 unittest assertions, all offline; no external network, no external deps

## License

MIT

## IMPORTANT: Read before use.

### Authorization Requirements
- You MUST have explicit written authorization before solving or deploying CTF challenges
- CTF challenges should only be solved in authorized competition or lab environments
- Challenge deployment requires explicit approval from the system owner
- This toolkit is for educational and authorized security training purposes only

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime, even for educational purposes
- **CTF Competition Rules**: Most competitions require explicit registration and acceptance of rules before participation
- **Academic Institutional Policies**: University and research lab policies may restrict security testing tools
- **State Laws**: Many states have additional computer crime statutes that may apply to challenge-solving techniques
- **Export Controls**: Some exploitation techniques may be subject to export controls (EAR/ITAR)

### Acceptable Use
- Solving challenges in authorized CTF competitions with explicit rules of engagement
- Academic research and coursework in controlled, authorized lab environments
- Security training and education with synthetic, purpose-built challenge data
- Authoring challenges for authorized competitions with organizer approval
- Personal learning with challenges you have permission to solve
- Red team/blue team exercises with explicit written authorization

### Prohibited Use
- Using challenge-solving techniques against systems without authorization
- Deploying exploit code outside of authorized competition/lab environments
- Sharing exploit solutions before competition organizers authorize disclosure
- Using this toolkit to attack production systems under any circumstances
- Any activity that violates applicable laws or competition rules
- Commercial use of exploit techniques without proper licensing and legal review

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software. Challenge solutions are provided for educational purposes and may not reflect real-world attack scenarios.

### Responsible Disclosure
If you discover vulnerabilities while solving CTF challenges or authoring new ones:
1. Follow the competition's rules for responsible disclosure
2. Report discovered vulnerabilities to the challenge author or competition organizer
3. Do not exploit vulnerabilities beyond what is required to solve the challenge
4. If you find real-world vulnerabilities during CTF practice, report them through proper channels
5. Follow coordinated vulnerability disclosure (CVD) practices
6. Do not publish exploit code without authorization from affected parties

## License

MIT
