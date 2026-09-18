import ctypes, struct, sys

dll = ctypes.WinDLL(r'C:\Program Files\7-Zip\7z.dll')
ctypes.windll.ole32.CoInitialize(None)

GetNumberOfFormats = dll.GetNumberOfFormats
GetNumberOfFormats.restype = ctypes.c_long
GetNumberOfFormats.argtypes = [ctypes.POINTER(ctypes.c_uint)]
n = ctypes.c_uint(0)
GetNumberOfFormats(ctypes.byref(n))

GetHandlerProperty2 = dll.GetHandlerProperty2
GetHandlerProperty2.restype = ctypes.c_long

# Find "zip" handler and extract its CLSID bytes
for i in range(n.value):
    ext_pv = (ctypes.c_byte * 24)()
    hr = GetHandlerProperty2(i, 2, ext_pv)
    if hr < 0: continue
    vt = struct.unpack_from('<H', ext_pv)[0]
    if vt != 8: continue
    bstr_ptr = struct.unpack_from('<Q', ext_pv, 8)[0]
    if not bstr_ptr: continue
    wlen = 0
    while ctypes.c_ushort.from_address(bstr_ptr + wlen*2).value != 0 and wlen < 100:
        wlen += 1
    ext = ctypes.wstring_at(bstr_ptr, wlen)
    if 'zip' in ext.lower():
        # kpidClassID returns raw GUID bytes (16 bytes) as BSTR
        cls_pv = (ctypes.c_byte * 32)()
        hr2 = GetHandlerProperty2(i, 1, cls_pv)
        vt2 = struct.unpack_from('<H', cls_pv)[0]
        bstr2 = struct.unpack_from('<Q', cls_pv, 8)[0]
        # Read raw bytes from the BSTR
        if bstr2:
            raw = ctypes.string_at(bstr2, 16)
            d1 = struct.unpack_from('<I', raw, 0)[0]
            d2 = struct.unpack_from('<H', raw, 4)[0]
            d3 = struct.unpack_from('<H', raw, 6)[0]
            d4 = raw[8:16]
            guid_hex = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{''.join(f'{b:02X}' for b in d4[2:])}}}"
            sys.stdout.buffer.write(f"idx={i} ext='{ext}' GUID={guid_hex}\n".encode('utf-8'))
            sys.stdout.buffer.write(f"raw CLSID bytes: {raw.hex()}\n".encode('utf-8'))
        break
