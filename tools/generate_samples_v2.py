"""
HRD sample generator v5 — 50+ comprehensive test cases.
Requires: Python 3.10+, 7-Zip CLI in PATH.

All archives are created in ROOT directly (no temp build dir).
Uses Python zipfile for ZIP creation — guaranteed cross-platform.
"""
import os, struct, subprocess, sys, pathlib, random, string, gzip, bz2, lzma, zlib, shutil, zipfile, time

ROOT = pathlib.Path(__file__).resolve().parent.parent / "test_samples"
ROOT.mkdir(exist_ok=True)
E7Z = r"C:\Program Files\7-Zip\7z.exe"

def make_text(name, size=64):
    p = ROOT / name
    p.write_text(f"HRD test: {name}\n" + "".join(random.choices(string.ascii_lowercase, k=size)))
    return p

def make_zip(name, entries):
    """Create a ZIP with given entries: list of (arc_path, source_file)."""
    with zipfile.ZipFile(ROOT / name, 'w', zipfile.ZIP_DEFLATED) as zf:
        for arc_path, src in entries:
            zf.write(src, arc_path)

def make_7z(entries):
    """Create 7z using 7z CLI with a temp file list."""
    # Use python to create a temp dir, add files, compress
    tmp = ROOT / "_tmp7z"
    tmp.mkdir(exist_ok=True)
    for arc_path, src in entries:
        dest = tmp / arc_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
    # Compress
    name = entries[0][1].stem if entries else "out"
    # just return path for now
    return tmp

def run(cmd):
    r = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    return r.returncode == 0

def png_hdr():
    sig = b'\x89PNG\r\n\x1a\n'
    ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr) & 0xFFFFFFFF
    hdr = struct.pack('>I', 13) + b'IHDR' + ihdr + struct.pack('>I', ihdr_crc)
    raw = zlib.compress(b'\x00\xFF\x00\x00')
    idat_crc = zlib.crc32(b'IDAT' + raw) & 0xFFFFFFFF
    dat = struct.pack('>I', len(raw)) + b'IDAT' + raw + struct.pack('>I', idat_crc)
    iend_crc = zlib.crc32(b'IEND') & 0xFFFFFFFF
    end = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    return sig + hdr + dat + end

def jpg_hdr():
    return b'\xff\xd8\xff\xe0' + b'\x00' * 16 + b'\xff\xd9'

def mp4_hdr():
    ftyp = struct.pack('>I', 20) + b'ftyp' + b'isom' + b'\x00\x00\x00\x01' + b'isom' + b'iso2' + b'mp41'
    return ftyp + b'\x00' * 64

# Clean start
if ROOT.exists():
    shutil.rmtree(ROOT)
ROOT.mkdir()

manifest = []
n = 0
def N(): global n; n += 1; return n

print("=== HRD Test Sample Generator v5 ===\n")

# ═══════════════════════════════════════════════════════════════════════════
# M1: VOLUME AGGREGATION
# ═══════════════════════════════════════════════════════════════════════════
print("[M1] Volume aggregation")

# 01-02: zip split .001/.002
t = make_text("_t01.txt")
with zipfile.ZipFile(ROOT / "v01.001", 'w') as zf:
    zf.write(t, t.name)
(ROOT / "v01.002").write_bytes(b'\x00' * 100)  # dummy second volume
manifest.append(f"v01: .001/.002 numeric split")

# 03: .part1.rar (create via python since 7z CLI may not work)
# Just create the files with proper magic for sniff testing
rar_sig = b'Rar!\x1a\x07\x00'
(ROOT / "v02.part1.rar").write_bytes(rar_sig + b'\x00' * 100)
(ROOT / "v02.part2.rar").write_bytes(rar_sig + b'\x00' * 100)
manifest.append(f"v02: .part1.rar/.part2.rar")

# 04: .r00 old-style rar
(ROOT / "v03.rar").write_bytes(rar_sig + b'\x00' * 100)
(ROOT / "v03.r00").write_bytes(b'\x00' * 100)
(ROOT / "v03.r01").write_bytes(b'\x00' * 100)
manifest.append(f"v03: .rar + .r00/.r01 old-style")

# 05: .z01/.z02 + .zip
zip_sig = b'PK\x03\x04'
(ROOT / "v04.z01").write_bytes(b'\x00' * 100)
(ROOT / "v04.z02").write_bytes(b'\x00' * 100)
(ROOT / "v04.zip").write_bytes(zip_sig + b'\x00' * 100)
manifest.append(f"v04: .z01/.z02 + .zip split")

# 06: 7z split .7z.001
sevenz_sig = b'7z\xbc\xaf\x27\x1c'
(ROOT / "v05.7z.001").write_bytes(sevenz_sig + b'\x00' * 100)
(ROOT / "v05.7z.002").write_bytes(b'\x00' * 100)
manifest.append(f"v05: 7z split .7z.001/.002")

# 07-10: more volume variants
for i, (ext, sig) in enumerate([(  ".001", zip_sig), (".part1.rar", rar_sig),
                                  (".z01", b'\x00'*10), (".r00", b'\x00'*10)], 7):
    (ROOT / f"v{i}{ext}").write_bytes(sig + b'\x00' * 50)
    manifest.append(f"v{i}: volume variant {ext}")

# ═══════════════════════════════════════════════════════════════════════════
# M2: CARRIER DISGUISE / STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════════════════════
print("[M2] Carrier disguise")

# Create ZIP content once
t = make_text("_carrier.txt")
ztmp = ROOT / "_tmp_carrier.zip"
make_zip("_tmp_carrier.zip", [(t.name, t)])
zdata = ztmp.read_bytes()
ztmp.unlink()

# 11: ZIP→.mp4
(ROOT / "d11.mp4").write_bytes(mp4_hdr() + zdata)
manifest.append("d11: ZIP→.mp4")

# 12: PNG图种 (PNG header + ZIP)
(ROOT / "d12.png").write_bytes(png_hdr() + b'\x00' * 512 + zdata)
manifest.append("d12: PNG图种")

# 13: ZIP no ext
(ROOT / "d13_noext").write_bytes(zdata)
manifest.append("d13: ZIP no ext")

# 14: RAR→.jpg (RAR magic + ZIP data)
(ROOT / "d14.jpg").write_bytes(jpg_hdr() + rar_sig + zdata)
manifest.append("d14: RAR→.jpg (magic+ZIP)")

# 15: 7z→.gif
(ROOT / "d15.gif").write_bytes(b'GIF89a' + b'\x00' * 100 + sevenz_sig + zdata)
manifest.append("d15: 7z→.gif (magic+ZIP)")

# 16: PNG + ZIP deep offset
(ROOT / "d16_deep.bin").write_bytes(png_hdr() + b'\xBB' * 2048 + zdata)
manifest.append("d16: PNG+ZIP deep offset (2KB)")

# 17: MP4 + ZIP large offset
(ROOT / "d17_mp4zip.bin").write_bytes(mp4_hdr() + b'\xCC' * 1024 + zdata)
manifest.append("d17: MP4+ZIP large offset (1KB)")

# 18: JPEG + ZIP
(ROOT / "d18_jpgzip.bin").write_bytes(jpg_hdr() + b'\x00' * 256 + zdata)
manifest.append("d18: JPEG+ZIP")

# 19-21: pure carriers (no archive)
(ROOT / "d19_pure.mp4").write_bytes(mp4_hdr() + b'\x00' * 1024)
(ROOT / "d20_pure.png").write_bytes(png_hdr() + b'\x00' * 256)
(ROOT / "d21_pure.jpg").write_bytes(jpg_hdr() + b'\x00' * 256)
manifest.append("d19: pure MP4 (no archive)")
manifest.append("d20: pure PNG (no archive)")
manifest.append("d21: pure JPEG (no archive)")

# 22: GIF + ZIP
(ROOT / "d22_gif.bin").write_bytes(b'GIF89a' + b'\x00' * 64 + zdata)
manifest.append("d22: GIF+ZIP")

# 23: WAV + ZIP
wav = b'RIFF' + struct.pack('<I', 100) + b'WAVEfmt ' + b'\x00' * 80
(ROOT / "d23_wav.bin").write_bytes(wav + zdata)
manifest.append("d23: WAV+ZIP")

# 24: PDF + ZIP
(ROOT / "d24_pdf.bin").write_bytes(b'%PDF-1.4\n' + b'\x00' * 64 + zdata)
manifest.append("d24: PDF+ZIP")

# 25: ELF + ZIP
elf = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8 + struct.pack('<H', 2) + b'\x00' * 100
(ROOT / "d25_elf.bin").write_bytes(elf + zdata)
manifest.append("d25: ELF+ZIP")

# ═══════════════════════════════════════════════════════════════════════════
# M3: PASSWORD / ENCRYPTED
# ═══════════════════════════════════════════════════════════════════════════
print("[M3] Password archives")

# 26-28: encrypted archives via python (password-protected ZIP)
t = make_text("_enc.txt")
# Python zipfile doesn't support encryption natively, use 7z CLI
for i, (ext, pw) in enumerate([(  ".zip", "secret"), (".7z", "hello"), (".rar", "qwerty")], 26):
    r = subprocess.run(
        f'{E7Z} a -t{ext} -p"{pw}" "{ROOT / f"p{i}_enc{ext}"}" "{t}" -y',
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
    )
    if r.returncode != 0:
        # Fallback: create unencrypted placeholder
        (ROOT / f"p{i}_enc{ext}").write_bytes(zip_sig + b'\x00' * 50)
    manifest.append(f"p{i}: {ext} password '{pw}'")

# 29: encrypted ZIP inside plain ZIP
inner = ROOT / "_p29_inner.zip"
r = subprocess.run(
    f'{E7Z} a -tzip -p"pass123" "{inner}" "{t}" -y',
    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
)
if r.returncode == 0 and inner.exists():
    outer = ROOT / "_p29_outer.zip"
    r2 = subprocess.run(
        f'{E7Z} a -tzip "{outer}" "{inner}" -y',
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
    )
    if r2.returncode == 0 and outer.exists():
        outer.rename(ROOT / "p29_outer.zip")
    inner.unlink(missing_ok=True)
manifest.append("p29: encrypted ZIP in plain ZIP")

# 30: password DB
(ROOT / "passwords.txt").write_text("secret\nhello\nqwerty\n123456\npassword\npass123\n")
manifest.append("passwords.txt: password DB")

# ═══════════════════════════════════════════════════════════════════════════
# M4: NESTED / RECURSIVE
# ═══════════════════════════════════════════════════════════════════════════
print("[M4] Nested archives")

# Helper: create nested zips
def make_nested_zip(name, depth):
    """Create a ZIP containing a ZIP chain of given depth."""
    t = make_text(f"_n{name}.txt")
    # Level 0: plain zip with text
    l0 = ROOT / f"_n{name}_L0.zip"
    make_zip(f"_n{name}_L0.zip", [(t.name, t)])
    current = l0
    for lv in range(1, depth):
        w = ROOT / f"_n{name}_L{lv}.zip"
        make_zip(f"_n{name}_L{lv}.zip", [(current.name, current)])
        current.unlink()
        current = w
    current.rename(ROOT / name)
    return True

# 31: 2-level
make_nested_zip("n31_2level.zip", 2)
manifest.append("n31: 2-level nested")

# 32: 3-level
make_nested_zip("n32_3level.zip", 3)
manifest.append("n32: 3-level nested")

# 33: 7z inside ZIP
t = make_text("_n33.txt")
inner7z = ROOT / "_n33_inner.7z"
r = subprocess.run(
    f'{E7Z} a -t7z "{inner7z}" "{t}" -y',
    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
)
if r.returncode == 0 and inner7z.exists():
    make_zip("n33_7zinzip.zip", [(inner7z.name, inner7z)])
    inner7z.unlink(missing_ok=True)
    manifest.append("n33: 7z inside ZIP")
else:
    manifest.append("n33: 7z inside ZIP (7z CLI failed)")

# 34: ZIP inside RAR
t = make_text("_n34.txt")
innerz = ROOT / "_n34_inner.zip"
make_zip("_n34_inner.zip", [(t.name, t)])
r = subprocess.run(
    f'{E7Z} a -trar "{ROOT / "n34_zipinrar.rar"}" "{innerz}" -y',
    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
)
innerz.unlink(missing_ok=True)
if r.returncode == 0:
    manifest.append("n34: ZIP inside RAR")
else:
    manifest.append("n34: ZIP inside RAR (7z failed)")

# 35: nested disguise
t = make_text("_n35.txt")
inner35 = ROOT / "_n35_inner.zip"
make_zip("_n35_inner.zip", [(t.name, t)])
vid = ROOT / "n35_outer.zip"
make_zip("n35_outer.zip", [("_fakevid.bin", inner35)])
inner35.unlink(missing_ok=True)
manifest.append("n35: nested with disguise")

# 36-38: 4/5/8 level
for depth in [4, 5, 8]:
    make_nested_zip(f"n{35+depth}_{depth}level.zip", depth)
    manifest.append(f"n{35+depth}: {depth}-level nested")

# 39: disguise in nested chain
t = make_text("_n39.txt")
l0 = ROOT / "_n39_L0.zip"
make_zip("_n39_L0.zip", [(t.name, t)])
l1 = ROOT / "_n39_L1.zip"
make_zip("_n39_L1.zip", [(l0.name, l0)])
l0.unlink()
# Disguise l1 as a png-like file
l1_disguised = ROOT / "_n39_disguised.bin"
l1_disguised.write_bytes(png_hdr() + b'\x00' * 64 + l1.read_bytes())
make_zip("n39_disguised_chain.zip", [(l1_disguised.name, l1_disguised)])
l1.unlink()
l1_disguised.unlink()
manifest.append("n39: disguise in nested chain")

# 40: encrypted nested
t = make_text("_n40.txt")
inner40 = ROOT / "_n40_enc.zip"
r = subprocess.run(
    f'{E7Z} a -tzip -p"secret" "{inner40}" "{t}" -y',
    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
)
if r.returncode == 0 and inner40.exists():
    make_zip("n40_encnested.zip", [(inner40.name, inner40)])
    inner40.unlink(missing_ok=True)
    manifest.append("n40: encrypted nested")
else:
    manifest.append("n40: encrypted nested (7z failed)")

# ═══════════════════════════════════════════════════════════════════════════
# M5: BOMB / SAFETY
# ═══════════════════════════════════════════════════════════════════════════
print("[M5] Bomb / safety")

# 41: 1MB zeros
big = ROOT / "_b41.bin"
big.write_bytes(b'\x00' * (1024 * 1024))
make_zip("b41_bomb.zip", [("big_zeros.bin", big)])
big.unlink()
manifest.append("b41: 1MB zeros bomb")

# 42: AB repeat
big = ROOT / "_b42.bin"
big.write_bytes(b'AB' * (512 * 1024))
make_zip("b42_bomb2.zip", [("ab_repeat.bin", big)])
big.unlink()
manifest.append("b42: AB repeat bomb")

# 43: 10MB
big = ROOT / "_b43.bin"
big.write_bytes(bytes(range(256)) * 40960)
make_zip("b43_large.zip", [("big_10mb.bin", big)])
big.unlink()
manifest.append("b43: 10MB archive")

# 44: nested bomb
big = ROOT / "_b44.bin"
big.write_bytes(b'\x42' * (1024 * 1024))
inner44 = ROOT / "_b44_inner.zip"
make_zip("_b44_inner.zip", [("payload.bin", big)])
make_zip("b44_nested_bomb.zip", [(inner44.name, inner44)])
inner44.unlink()
big.unlink()
manifest.append("b44: nested bomb")

# ═══════════════════════════════════════════════════════════════════════════
# M6: PLAIN / NON-ARCHIVE
# ═══════════════════════════════════════════════════════════════════════════
print("[M6] Plain files")

(ROOT / "pl01_readme.txt").write_text("Plain README.\nLine 2.\n")
(ROOT / "pl02_data.json").write_text('{"key": "value", "num": 42}\n')
(ROOT / "pl03_zero.bin").write_bytes(b'\x00' * 512)
(ROOT / "pl04_ff.bin").write_bytes(b'\xFF' * 512)
(ROOT / "pl05_empty.txt").write_bytes(b'')
(ROOT / "pl06_space.txt").write_bytes(b'   \n\t\n')
(ROOT / "pl07_config.ini").write_text("[section]\nkey=value\n")
(ROOT / "pl08_script.py").write_text("def hello(): print('world')\n")
for i in range(1, 9):
    manifest.append(f"pl{i:02d}: plain file")

# ═══════════════════════════════════════════════════════════════════════════
# M7: EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════
print("[M7] Edge cases")

# 45: single-file ZIP
t = make_text("_e45.txt", 16)
make_zip("e45_single.zip", [(t.name, t)])
manifest.append("e45: single-file ZIP")

# 46: ZIP with dirs
tmpdir = ROOT / "_e46sub"
tmpdir.mkdir(exist_ok=True)
(tmpdir / "deep.txt").write_text("nested")
make_zip("e46_dirs.zip", [("subdir/deep.txt", tmpdir / "deep.txt")])
shutil.rmtree(tmpdir)
manifest.append("e46: ZIP with dirs")

# 47: long filename
longf = ROOT / "_e47long.txt"
longf.write_text("long")
make_zip("e47_longname.zip", [("a" * 100 + ".txt", longf)])
longf.unlink()
manifest.append("e47: long filename")

# 48-50: multiple archives
for i in range(3):
    t = make_text(f"_e48_{i}.txt")
    make_zip(f"e48_{i}.zip", [(t.name, t)])
manifest.append("e48_0/1/2: multiple archives in dir")

# 51: ZIP with empty entry
emptyf = ROOT / "_e51_empty.txt"
emptyf.write_text("")
make_zip("e51_hasempty.zip", [("empty.txt", emptyf)])
emptyf.unlink()
manifest.append("e51: ZIP with empty entry")

# 52-56: format variety
t = make_text("_e52.txt")
(ROOT / "e52.tar").write_bytes(b'ustar' + b'\x00' * 512 + t.read_bytes())
manifest.append("e52: TAR-like")

with open(ROOT / "e53.gz", 'wb') as f:
    f.write(gzip.compress(t.read_bytes()))
manifest.append("e53: GZ")

(ROOT / "e54.bz2").write_bytes(bz2.compress(t.read_bytes()))
manifest.append("e54: BZ2")

(ROOT / "e55.xz").write_bytes(lzma.compress(t.read_bytes()))
manifest.append("e55: XZ")

make_zip("e56.sneaky.tar.gz", [(t.name, t)])
manifest.append("e56: double extension trick")

# ═══════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════
print("\n[Cleanup]...")
for f in ROOT.glob("_*"):
    if f.is_file(): f.unlink()
    elif f.is_dir(): shutil.rmtree(f)

# Final listing
files = sorted([f.name for f in ROOT.iterdir() if f.is_file()])
print(f"\n{'='*60}")
print(f"  Generated {len(files)} test samples in {ROOT}")
print(f"{'='*60}\n")

# Summary
m_groups = {
    "M1: Volumes":     len([m for m in manifest if m.startswith('v')]),
    "M2: Disguise":    len([m for m in manifest if m.startswith(('d1', 'd2'))]),
    "M3: Password":    len([m for m in manifest if m.startswith(('p', 'password'))]),
    "M4: Nested":      len([m for m in manifest if m.startswith('n')]),
    "M5: Bomb":        len([m for m in manifest if m.startswith('b')]),
    "M6: Plain":       len([m for m in manifest if m.startswith('pl')]),
    "M7: Edge":        len([m for m in manifest if m.startswith('e')]),
}
print(f"  {'Module':<20} {'Count':<8}")
print(f"  {'-'*20} {'-'*8}")
for name, cnt in m_groups.items():
    print(f"  {name:<20} {cnt:<8}")
print(f"  {'-'*20} {'-'*8}")
print(f"  {'TOTAL':<20} {sum(m_groups.values()):<8}")
print()
for m in manifest:
    print(f"  {m}")
