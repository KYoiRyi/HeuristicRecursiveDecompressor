import struct, sys
p = r'third_party\7zip\7z.dll'
data = open(p, 'rb').read()
peoff = struct.unpack_from('<I', data, 0x3C)[0]
assert data[peoff:peoff+4] == b'PE\0\0'
coff = peoff + 4
nsec = struct.unpack_from('<H', data, coff + 2)[0]
optsize = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', data, opt)[0]
exp_rva, exp_size = struct.unpack_from('<II', data, opt + (112 if magic == 0x20b else 96))
sec = opt + optsize

def rva2off(rva):
    for i in range(nsec):
        base = sec + 40 * i
        vsize, vaddr, rawsize, rawoff = struct.unpack_from('<IIII', data, base + 8)
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawoff + (rva - vaddr)
    return None

exp = rva2off(exp_rva)
(flags, ts, maj, mino, name_rva, base, nfunc, nname,
 addrfunc, addrname, addrord) = struct.unpack_from('<IIHHIIIIIII', data, exp)
nameoff = rva2off(addrname)
names = []
for i in range(nname):
    nrva = struct.unpack_from('<I', data, nameoff + 4 * i)[0]
    noff = rva2off(nrva)
    end = data.index(b'\0', noff)
    names.append(data[noff:end].decode())

with open(r'third_party\7zip\7z.def', 'w') as f:
    f.write('LIBRARY 7z\nEXPORTS\n')
    for n in sorted(names):
        f.write('    %s\n' % n)
print('\n'.join(sorted(names)))
