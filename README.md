# X12 — CTF Toolkit + Challenge Authorship

CTF toolkit with writeup generator and 3 original challenge solutions (pwn, rev, forensics).

## Overview

This project implements a CTF toolkit and challenge authorship pack that:
- Generates a markdown writeup index from solved challenges
- Implements a PWN challenge: stack buffer overflow with ROP return-address overwrite
- Implements a REV challenge: XOR-packed binary decode with key extraction
- Implements a FORENSICS challenge: file carving from a raw disk image (PNG + JPEG)
- Provides solve-stats reporting with step counts and hint availability for each challenge
- Verifies all flags match expected values during the offline self-test demo

## Features

- **Writeup generator**: Produces formatted markdown writeup index from solved challenges
- **PWN challenge (PWN-001)**: Stack offset calculation and return-address overwrite exploit
- **REV challenge (REV-001)**: ELF header analysis and XOR-packed payload decoding
- **FORENSICS challenge (FORENSICS-001)**: File magic scanning and PNG/JPEG carving from raw image
- **Solve-stats reporting**: Steps taken, hints available, success verification per challenge
- **Flag verification**: All flags validated against expected values at demo time
- **Offline demo**: Fully self-contained with embedded synthetic challenge binaries
- **Legal disclaimer**: Heavy authorization/lab-use-only requirements

## Installation

```bash
# No external dependencies required — pure Python standard library
python3 ctf_toolkit.py
```

## Usage

```bash
# Run all challenge solves and verify flags
python3 ctf_toolkit.py

# Import as module
from ctf_toolkit import PWNChallenge, REVChallenge, ForensicsChallenge, WriteupGenerator
pwn = PWNChallenge()
result = pwn.solve()
print(result["flag"])

writer = WriteupGenerator()
writer.register(pwn, result)
print(writer.generate_markdown())
```

## Example Output

```
[*] X12 — CTF Toolkit + Challenge Authorship
[*] Running offline self-test...

  --- PWN-001: Stack Offset ROP ---
  Flag: FLAG{pwn_stack_offset_0x11b6}
  Success: True
  Steps taken: 5
    Step 1: Identified buffer size = 60 bytes (15 x 4-byte DWORDs)
    Step 2: Calculated offset to saved RBP = 60 bytes
    Step 3: Overwrote saved RBP with 0x41414141 (placeholder)
    Step 4: Overwrote return address with 0x4011B6 (win_function)
    Step 5: Verified exploit produces win message
  Hints available: 4

  --- REV-001: XOR-Packed Binary Decode ---
  Flag: FLAG{rev_packed_binary_decoded}
  Success: True
  Steps taken: 6
    Step 1: Analyzed ELF header — identified as x86-64 ELF
    Step 2: Found marker 'PACKED_XOR_5A:' at known offset
    Step 3: Extracted XOR-encoded payload bytes
    Step 4: Applied XOR 0x5A decryption
    Step 5: Verified decoded string matches expected flag format
    Step 6: Decoded payload: FLAG{rev_packed_binary_decoded}
  Hints available: 3

  --- FORENSICS-001: File Carving from Raw Image ---
  Flag: FLAG{forensics_file_carved_png}
  Success: True
  Steps taken: 7
    Step 1: Scanned raw image for file magic signatures
    Step 2: Found PNG signature at offset 0x80
    Step 3: PNG IHDR chunk — type=IHDR, data_len=31
    Step 4: Extracted flag from PNG chunk: FLAG{forensics_file_carved_png}
    Step 5: Found JPEG APP0 marker at offset 0x200
    Step 6: JPEG payload: FLAG{forensics_jpeg_app0_marker}
    Step 7: Carved 2 files from raw image
  Hints available: 3

  --- Solve Stats Summary ---
  Total challenges: 3
  Solved: 3/3
  Total steps used: 18
  Total hints available: 10
  Average steps per challenge: 6.0
    [PASS] PWN-001: Stack Offset ROP: FLAG{pwn_stack_offset_0x11b6}
    [PASS] REV-001: XOR-Packed Binary Decode: FLAG{rev_packed_binary_decoded}
    [PASS] FORENSICS-001: File Carving from Raw Image: FLAG{forensics_file_carved_png}

======================================================================
  Self-test PASSED. Demo complete.
  Legal: This toolkit is for authorized CTF/lab use only.
======================================================================
```

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
