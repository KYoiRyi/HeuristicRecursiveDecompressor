"""
HRD sample generator — creates all test cases for the Heuristic Recursive Decompressor.
Requires: Python 3.10+, 7-Zip CLI (7z) in PATH.
"""
import os, struct, subprocess, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "test_samples"
ROOT.mkdir(exist_ok=True)
E7Z = "7z"

def run(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ── Module 1: Volume aggregation ────────────────────────────────────────────
print("[1] Split archives")

# .001 / .002 (7z numeric split)
zip_path = ROOT / "split_data.zip"
run(f'{E7Z} a -tzip "{zip_path}" "{ROOT.parent / "src" / "types.zig"}" -y')
split_zip = ROOT / "split_data.z01"
split_zip2 = ROOT / "split_data.z02"
run(f'{E7Z} a -tzip -v1k "{ROOT / "split_data"}" "{ROOT.parent / "src" / "types.zig"}" -y')

# .rar partN
rar_part = ROOT / "archive.part1.rar"
run(f'{E7Z} a -trar -v1k "{ROOT / "archive"}" "{ROOT.parent / "src" / "util.zig"}" -y')

# .rar old style (r00)
rar_old = ROOT / "oldstyle.rar"
run(f'{E7Z} a -trar "{rar_old}" "{ROOT.parent / "src" / "types.zig"}" -y')

# ── Module 2: Carrier disguise (steg / rename) ─────────────────────────────
print("[2] Carrier disguise samples")

# Create a ZIP and rename to .mp4
real_zip = ROOT / "disguised.zip"
run(f'{E7Z} a -tzip "{real_zip}" "{ROOT.parent / "src" / "types.zig"}" -y')
mp4_path = ROOT / "fake_video.mp4"
mp4_path.write_bytes(b'\x00' * 128 + real_zip.read_bytes())  # prepend junk

# PNG with ZIP appended (图种)
png_path = ROOT / "steg_image.png"
png_header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 256
png_path.write_bytes(png_header + real_zip.read_bytes())

# ── Module 3: Password-protected archives ──────────────────────────────────
print("[3] Encrypted archives")
enc_zip = ROOT / "encrypted.zip"
run(f'{E7Z} a -tzip -p"123456" "{enc_zip}" "{ROOT.parent / "src" / "types.zig"}" -y')

# ── Module 4: Nested archives (recursive) ──────────────────────────────────
print("[4] Nested archives")
# inner.zip inside outer.zip
inner_dir = ROOT / "_inner_build"
inner_dir.mkdir(exist_ok=True)
(inner_dir / "hello.txt").write_text("Hello from inner archive!")
inner_zip = ROOT / "inner.zip"
run(f'{E7Z} a -tzip "{inner_zip}" "{inner_dir / "hello.txt"}" -y')
outer_zip = ROOT / "outer_nested.zip"
run(f'{E7Z} a -tzip "{outer_zip}" "{inner_zip}" -y')

# 3-level nesting
level2 = ROOT / "level2.zip"
run(f'{E7Z} a -tzip "{level2}" "{outer_zip}" -y')

# ── Module 5: Bomb detection ────────────────────────────────────────────────
print("[5] Bomb test (compression ratio)")
# Create a large file and compress it to test ratio
big_file = ROOT / "_big_payload.bin"
big_file.write_bytes(b'\x41' * (1024 * 1024))  # 1 MB
bomb_zip = ROOT / "bomb_test.zip"
run(f'{E7Z} a -tzip "{bomb_zip}" "{big_file}" -y')

# ── Plain text (non-archive, should be kept as-is) ──────────────────────────
print("[6] Plain files")
(ROOT / "readme.txt").write_text("This is a plain text file.\nHRD should keep it as-is.\n")
(ROOT / "data.json").write_text('{"key": "value", "number": 42}\n')

# Cleanup
import shutil
shutil.rmtree(inner_dir, ignore_errors=True)
big_file.unlink(missing_ok=True)

print(f"\n✅ All samples generated in {ROOT}")
print(f"   Run: hrd <path> -o out")
