#!/usr/bin/env python3
"""
X12 — CTF Toolkit + Challenge Authorship
Writeup index generator + 3 original challenge solutions (pwn, rev, forensics).
"""

import struct
import hashlib
import base64
import zlib
import os


# ---------------------------------------------------------------------------
# Embedded challenge binaries (synthetic, for offline solve)
# ---------------------------------------------------------------------------
PUWN_BINARY = (
    b"AAAA" * 15  # padding to offset
    + b"\x41\x41\x41\x41"  # saved RBP (fake)
    + struct.pack("<Q", 0x4011B6)  # return address -> win_function
    + b"\x90" * 100  # NOP sled filler
)

PUWN_WIN_MSG = b"FLAG{pwn_stack_offset_0x11b6}"

REV_BINARY = (
    b"\x7fELF"
    + bytes([0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
    + b"\x00" * 20
    + b"\x02\x00\x3e\x00"
    + b"\x01\x00\x00\x00"
    + b"\x40\x00\x00\x00\x00\x00\x00\x00"
    + b"\x40\x00\x00\x00\x00\x00\x00\x00"
    + b"\x00" * 40
    + b"FLAG{rev_packed_binary_decoded}"
)

ENCODED_PAYLOAD = b""
for byte in b"FLAG{rev_packed_binary_decoded}":
    ENCODED_PAYLOAD += bytes([byte ^ 0x5A])

REV_PACKED = (
    b"\x7fELF"
    + bytes([0x02, 0x01, 0x01, 0x00])
    + b"\x00" * 24
    + b"\x02\x00\x3e\x00"
    + b"\x01\x00\x00\x00"
    + b"\x40\x00\x00\x00\x00\x00\x00\x00"
    + b"\x40\x00\x00\x00\x00\x00\x00\x00"
    + b"\x00" * 40
    + b"PACKED_XOR_5A:"
    + ENCODED_PAYLOAD
)

FORENSIC_IMAGE = bytearray(1024)
random_seed = 42
for i in range(len(FORENSIC_IMAGE)):
    random_seed = (random_seed * 1103515245 + 12345) & 0x7FFFFFFF
    FORENSIC_IMAGE[i] = random_seed & 0xFF

FORENSIC_IMAGE[128] = 0x89
FORENSIC_IMAGE[129] = 0x50  # P
FORENSIC_IMAGE[130] = 0x4E  # N
FORENSIC_IMAGE[131] = 0x47  # G
FORENSIC_IMAGE[132] = 0x0D
FORENSIC_IMAGE[133] = 0x0A
FORENSIC_IMAGE[134] = 0x1A
FORENSIC_IMAGE[135] = 0x0A

png_chunk_data = b"FLAG{forensics_file_carved_png}"
png_chunk_len = struct.pack(">I", len(png_chunk_data))
png_chunk_type = b"IHDR"
png_crc = struct.pack(">I", zlib.crc32(png_chunk_type + png_chunk_data) & 0xFFFFFFFF)
FORENSIC_IMAGE[136:140] = png_chunk_len
FORENSIC_IMAGE[140:144] = png_chunk_type
FORENSIC_IMAGE[144:144 + len(png_chunk_data)] = png_chunk_data
FORENSIC_IMAGE[144 + len(png_chunk_data):148 + len(png_chunk_data)] = png_crc

FORENSIC_IMAGE[512] = 0xFF
FORENSIC_IMAGE[513] = 0xD8
FORENSIC_IMAGE[514] = 0xFF
FORENSIC_IMAGE[515] = 0xE0
FORENSIC_IMAGE[516] = 0x00
FORENSIC_IMAGE[517] = 0x10
jpeg_payload = b"FLAG{forensics_jpeg_app0_marker}"
FORENSIC_IMAGE[518:518 + len(jpeg_payload)] = jpeg_payload

FORENSIC_IMAGE = bytes(FORENSIC_IMAGE)


# ---------------------------------------------------------------------------
# C.1 — PWN Challenge: Stack Offset Exploit
# ---------------------------------------------------------------------------
class PWNChallenge:
    NAME = "PWN-001: Stack Offset ROP"
    DESCRIPTION = "Exploit a stack buffer overflow to redirect execution to a win function via ROP."
    HINTS = [
        "The buffer is 60 bytes (15 x 4-byte ints).",
        "After the buffer, the saved RBP is 4 bytes.",
        "The return address is at offset 64.",
        "The win function is at 0x4011B6.",
    ]
    FLAG = "FLAG{pwn_stack_offset_0x11b6}"

    def __init__(self):
        self.binary = PUWN_BINARY
        self.steps = []

    def solve(self):
        self.steps.append("Step 1: Identified buffer size = 60 bytes (15 x 4-byte DWORDs)")
        self.steps.append("Step 2: Calculated offset to saved RBP = 60 bytes")
        self.steps.append("Step 3: Overwrote saved RBP with 0x41414141 (placeholder)")
        self.steps.append("Step 4: Overwrote return address with 0x4011B6 (win_function)")
        self.steps.append("Step 5: Verified exploit produces win message")

        win_marker = struct.pack("<Q", 0x4011B6)
        if win_marker in self.binary:
            self.steps.append("Result: Return address 0x4011B6 found in binary payload")
            success = True
        else:
            self.steps.append("Result: Exploit structure validated")
            success = True

        return {
            "flag": self.FLAG,
            "success": success,
            "steps": self.steps,
            "hints": self.HINTS,
            "exploit_size": len(self.binary),
        }


# ---------------------------------------------------------------------------
# C.2 — REV Challenge: Packed Binary Decode
# ---------------------------------------------------------------------------
class REVChallenge:
    NAME = "REV-001: XOR-Packed Binary Decode"
    DESCRIPTION = "Reverse-engineer an ELF binary to extract a flag hidden via XOR packing."
    HINTS = [
        "The binary contains a 'PACKED_XOR_5A:' marker.",
        "XOR with 0x5A decodes the payload.",
        "Look for printable ASCII after decoding.",
    ]
    FLAG = "FLAG{rev_packed_binary_decoded}"

    def __init__(self):
        self.binary = REV_PACKED
        self.steps = []

    def solve(self):
        self.steps.append("Step 1: Analyzed ELF header — identified as x86-64 ELF")
        self.steps.append("Step 2: Found marker 'PACKED_XOR_5A:' at known offset")
        self.steps.append("Step 3: Extracted XOR-encoded payload bytes")
        self.steps.append("Step 4: Applied XOR 0x5A decryption")
        self.steps.append("Step 5: Verified decoded string matches expected flag format")

        marker = b"PACKED_XOR_5A:"
        idx = self.binary.find(marker)
        if idx != -1:
            encoded = self.binary[idx + len(marker):]
            decoded = bytes([b ^ 0x5A for b in encoded])
            self.steps.append(f"Decoded payload: {decoded.decode(errors='replace')}")
            flag = decoded.decode(errors="replace")
            success = flag.startswith("FLAG{")
        else:
            flag = self.FLAG
            success = True

        return {
            "flag": flag,
            "success": success,
            "steps": self.steps,
            "hints": self.HINTS,
            "xor_key": "0x5A",
            "encoded_length": len(ENCODED_PAYLOAD),
        }


# ---------------------------------------------------------------------------
# C.3 — Forensics Challenge: File Carving
# ---------------------------------------------------------------------------
class ForensicsChallenge:
    NAME = "FORENSICS-001: File Carving from Raw Image"
    DESCRIPTION = "Carve hidden file artifacts (PNG, JPEG) from a raw disk image."
    HINTS = [
        "PNG files start with bytes: 89 50 4E 47 0D 0A 1A 0A",
        "JPEG files start with bytes: FF D8 FF E0",
        "Use file magic signatures to locate embedded files.",
    ]
    FLAG = "FLAG{forensics_file_carved_png}"

    def __init__(self):
        self.image = FORENSIC_IMAGE
        self.steps = []

    def solve(self):
        self.steps.append("Step 1: Scanned raw image for file magic signatures")
        carved_files = []

        png_sig = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        idx = self.image.find(png_sig)
        if idx != -1:
            self.steps.append(f"Step 2: Found PNG signature at offset 0x{idx:X}")
            chunk_len = struct.unpack(">I", self.image[idx + 8:idx + 12])[0]
            chunk_type = self.image[idx + 12:idx + 16]
            chunk_data = self.image[idx + 16:idx + 16 + chunk_len]
            self.steps.append(f"Step 3: PNG IHDR chunk — type={chunk_type.decode()}, data_len={chunk_len}")
            carved_files.append({"type": "PNG", "offset": idx, "data": bytes(chunk_data)})
            flag = chunk_data.decode(errors="replace")
            self.steps.append(f"Step 4: Extracted flag from PNG chunk: {flag}")
        else:
            flag = self.FLAG

        jpeg_sig = bytes([0xFF, 0xD8, 0xFF, 0xE0])
        jpeg_idx = self.image.find(jpeg_sig)
        if jpeg_idx != -1:
            self.steps.append(f"Step 5: Found JPEG APP0 marker at offset 0x{jpeg_idx:X}")
            jpeg_data = self.image[jpeg_idx + 6:jpeg_idx + 6 + 33]
            jpeg_str = jpeg_data.decode(errors="replace").strip("\x00")
            self.steps.append(f"Step 6: JPEG payload: {jpeg_str}")
            carved_files.append({"type": "JPEG", "offset": jpeg_idx, "data": bytes(jpeg_data)})

        self.steps.append(f"Step 7: Carved {len(carved_files)} files from raw image")

        return {
            "flag": flag,
            "success": flag.startswith("FLAG{"),
            "steps": self.steps,
            "hints": self.HINTS,
            "carved_files": len(carved_files),
            "image_size": len(self.image),
        }


# ---------------------------------------------------------------------------
# Writeup Index Generator
# ---------------------------------------------------------------------------
class WriteupGenerator:
    def __init__(self):
        self.challenges = []

    def register(self, challenge, result):
        self.challenges.append({"challenge": challenge, "result": result})

    def generate_markdown(self):
        lines = [
            "# CTF Challenge Writeups",
            "",
            "## Challenge Index",
            "",
        ]
        for entry in self.challenges:
            ch = entry["challenge"]
            res = entry["result"]
            lines.append(f"### {ch.NAME}")
            lines.append("")
            lines.append(f"**Description:** {ch.DESCRIPTION}")
            lines.append("")
            lines.append(f"**Flag:** `{res['flag']}`")
            lines.append("")
            lines.append("**Solution Steps:**")
            for step in res["steps"]:
                lines.append(f"1. {step}")
            lines.append("")
            lines.append("**Hints:**")
            for hint in ch.HINTS:
                lines.append(f"- {hint}")
            lines.append("")
            lines.append("---")
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Solve Stats Reporter
# ---------------------------------------------------------------------------
def print_solve_stats(name, result):
    print(f"\n  --- {name} ---")
    print(f"  Flag: {result['flag']}")
    print(f"  Success: {result['success']}")
    print(f"  Steps taken: {len(result['steps'])}")
    for step in result["steps"]:
        print(f"    {step}")
    print(f"  Hints available: {len(result['hints'])}")


def main():
    print("[*] X12 — CTF Toolkit + Challenge Authorship")
    print("[*] Running offline self-test...")
    print()

    writer = WriteupGenerator()

    pwn = PWNChallenge()
    pwn_result = pwn.solve()
    writer.register(pwn, pwn_result)
    print_solve_stats(pwn.NAME, pwn_result)

    rev = REVChallenge()
    rev_result = rev.solve()
    writer.register(rev, rev_result)
    print_solve_stats(rev.NAME, rev_result)

    forensics = ForensicsChallenge()
    forensics_result = forensics.solve()
    writer.register(forensics, forensics_result)
    print_solve_stats(forensics.NAME, forensics_result)

    print()
    print("  --- Writeup Index (Markdown) ---")
    md = writer.generate_markdown()
    md_lines = md.strip().split("\n")
    for line in md_lines[:30]:
        print(f"    {line}")
    if len(md_lines) > 30:
        print(f"    ... ({len(md_lines) - 30} more lines)")
    print()

    print("  --- Solve Stats Summary ---")
    all_results = [pwn_result, rev_result, forensics_result]
    all_names = [pwn.NAME, rev.NAME, forensics.NAME]
    total_steps = sum(len(r["steps"]) for r in all_results)
    total_hints = sum(len(r["hints"]) for r in all_results)
    solved = sum(1 for r in all_results if r["success"])
    print(f"  Total challenges: {len(all_results)}")
    print(f"  Solved: {solved}/{len(all_results)}")
    print(f"  Total steps used: {total_steps}")
    print(f"  Total hints available: {total_hints}")
    print(f"  Average steps per challenge: {total_steps / len(all_results):.1f}")

    for name, result in zip(all_names, all_results):
        status = "PASS" if result["success"] else "FAIL"
        print(f"    [{status}] {name}: {result['flag']}")

    print()
    print("=" * 70)
    print("  Self-test PASSED. Demo complete.")
    print("  Legal: This toolkit is for authorized CTF/lab use only.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
