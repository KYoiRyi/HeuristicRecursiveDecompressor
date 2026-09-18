// Minimal COM interface definitions for driving 7z.dll (7-Zip client API).
// Layouts follow 7-Zip's IUnknown.h / IArchive.h / IStream.h.
const std = @import("std");

// On x86_64 Windows, COM uses the standard C calling convention.
pub const cc_com: std.builtin.CallingConvention = .c;

pub const HRESULT = i32;
pub const S_OK: HRESULT = 0;
pub const S_FALSE: HRESULT = 1;
pub const E_OUTOFMEMORY: HRESULT = @bitCast(@as(u32, 0x8007000E));
pub const E_INVALIDARG: HRESULT = @bitCast(@as(u32, 0x80070057));
pub const E_ABORT: HRESULT = @bitCast(@as(u32, 0x80004004));
pub const E_FAIL: HRESULT = @bitCast(@as(u32, 0x80004005));
pub const E_NOTIMPL: HRESULT = @bitCast(@as(u32, 0x80004001));

pub fn succeeded(hr: HRESULT) bool {
    return hr >= 0;
}

pub const GUID = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,

    pub fn eql(a: GUID, b: GUID) bool {
        return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
    }
};

pub const PROPVARIANT = extern struct {
    vt: u16,
    wReserved1: u16 = 0,
    wReserved2: u16 = 0,
    wReserved3: u16 = 0,
    data: extern union {
        bVal: u8,
        iVal: i16,
        uiVal: u16,
        lVal: i32,
        ulVal: u32,
        intVal: i32,
        uintVal: u32,
        hVal: i64,
        uhVal: u64,
        filetime: u64,
        boolVal: i16,
        bstrVal: ?[*]u16,
        pVal: ?*anyopaque,
    },
    // pad to 16 bytes data area like native PROPVARIANT (8 bytes header + 8 data + 8 pad on x64)
    _pad: [8]u8 = undefined,
};

comptime {
    // PROPVARIANT on Win64 = 24 bytes
    std.debug.assert(@sizeOf(PROPVARIANT) == 24);
}

pub const VTable = extern struct {
    QueryInterface: *const fn (self: *anyopaque, riid: *const GUID, out: *?*anyopaque) callconv(cc_com) HRESULT,
    AddRef: *const fn (self: *anyopaque) callconv(cc_com) u32,
    Release: *const fn (self: *anyopaque) callconv(cc_com) u32,
};

pub fn release(pp: *?*anyopaque) void {
    if (pp.*) |p| {
        const vtbl: *const VTable = @ptrCast(@alignCast(@as(*const *const anyopaque, @ptrCast(@alignCast(p))).*));
        _ = vtbl.Release(p);
        pp.* = null;
    }
}

// ---------------- ISequentialInStream / IInStream ----------------
pub const IID_ISequentialInStream = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00 } };
pub const IID_ISequentialOutStream = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00 } };
pub const IID_IInStream = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00 } };
pub const IID_IOutStream = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00 } };

pub const ISequentialInStreamVt = extern struct {
    base: VTable,
    Read: *const fn (self: *anyopaque, data: [*]u8, size: u32, processed: ?*u32) callconv(cc_com) HRESULT,
};
pub const IInStreamVt = extern struct {
    base: ISequentialInStreamVt,
    Seek: *const fn (self: *anyopaque, offset: i64, origin: u32, newPos: ?*u64) callconv(cc_com) HRESULT,
};
pub const ISequentialOutStreamVt = extern struct {
    base: VTable,
    Write: *const fn (self: *anyopaque, data: [*]const u8, size: u32, processed: ?*u32) callconv(cc_com) HRESULT,
};
pub const IOutStreamVt = extern struct {
    base: ISequentialOutStreamVt,
    Seek: *const fn (self: *anyopaque, offset: i64, origin: u32, newPos: ?*u64) callconv(cc_com) HRESULT,
    SetSize: *const fn (self: *anyopaque, newSize: u64) callconv(cc_com) HRESULT,
};

// ---------------- IArchiveOpenCallback / IArchiveExtractCallback ----------------
pub const IID_IArchiveOpenCallback = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x10, 0x00, 0x00 } };
pub const IID_IArchiveOpenVolumeCallback = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x30, 0x00, 0x00 } };
pub const IArchiveOpenVolumeCallbackVt = extern struct {
    base: VTable,
    GetProperty: *const fn (self: *anyopaque, propID: u32, value: *PROPVARIANT) callconv(cc_com) HRESULT,
    GetStream: *const fn (self: *anyopaque, name: [*:0]const u16, inStream: *?*anyopaque) callconv(cc_com) HRESULT,
};
pub const IArchiveOpenCallbackVt = extern struct {
    base: VTable,
    SetTotal: *const fn (self: *anyopaque, files: ?*const u64, bytes: ?*const u64) callconv(cc_com) HRESULT,
    SetCompleted: *const fn (self: *anyopaque, files: ?*const u64, bytes: ?*const u64) callconv(cc_com) HRESULT,
};

pub const IID_ICryptoGetTextPassword = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00 } };
pub const ICryptoGetTextPasswordVt = extern struct {
    base: VTable,
    CryptoGetTextPassword: *const fn (self: *anyopaque, password: *?[*]u16) callconv(cc_com) HRESULT,
};

pub const NExtract = struct {
    pub const NAskMode = enum(i32) { @"extract" = 0, @"test" = 1, @"skip" = 2 };
    pub const NOperationResult = enum(i32) {
        ok = 0,
        unsupported_method = 1,
        data_error = 2,
        crc_error = 3,
        unavailable = 4,
        unexpected_end = 5,
        data_after_end = 6,
        is_not_arc = 7,
        headers_error = 8,
        wrong_password = 9,
    };
};

pub const IID_IArchiveExtractCallback = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x20, 0x00, 0x00 } };
pub const IArchiveExtractCallbackVt = extern struct {
    base: VTable,
    SetTotal: *const fn (self: *anyopaque, total: u64) callconv(cc_com) HRESULT,
    SetCompleted: *const fn (self: *anyopaque, completeValue: *const u64) callconv(cc_com) HRESULT,
    GetStream: *const fn (self: *anyopaque, index: u32, outStream: *?*anyopaque, askExtractMode: i32) callconv(cc_com) HRESULT,
    PrepareOperation: *const fn (self: *anyopaque, askExtractMode: i32) callconv(cc_com) HRESULT,
    SetOperationResult: *const fn (self: *anyopaque, opRes: i32) callconv(cc_com) HRESULT,
};

// ---------------- IInArchive ----------------
pub const IID_IInArchive = GUID{ .data1 = 0x23170F69, .data2 = 0x40C1, .data3 = 0x278A, .data4 = .{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x60, 0x00, 0x00 } };
pub const IInArchiveVt = extern struct {
    base: VTable,
    Open: *const fn (self: *anyopaque, stream: *anyopaque, maxCheckStartPosition: ?*const u64, openArchiveCallback: ?*anyopaque) callconv(cc_com) HRESULT,
    Close: *const fn (self: *anyopaque) callconv(cc_com) HRESULT,
    GetNumberOfItems: *const fn (self: *anyopaque, numItems: *u32) callconv(cc_com) HRESULT,
    GetProperty: *const fn (self: *anyopaque, index: u32, propID: u32, value: *PROPVARIANT) callconv(cc_com) HRESULT,
    Extract: *const fn (self: *anyopaque, indices: ?*const u32, numItems: u32, testMode: i32, extractCallback: ?*anyopaque) callconv(cc_com) HRESULT,
    GetArchiveProperty: *const fn (self: *anyopaque, propID: u32, value: *PROPVARIANT) callconv(cc_com) HRESULT,
    GetNumberOfProperties: *const fn (self: *anyopaque, numProps: *u32) callconv(cc_com) HRESULT,
    GetPropertyInfo: *const fn (self: *anyopaque, index: u32, name: *?[*]u16, propID: *u32, varType: *u16) callconv(cc_com) HRESULT,
    GetNumberOfArchiveProperties: *const fn (self: *anyopaque, numProps: *u32) callconv(cc_com) HRESULT,
    GetArchivePropertyInfo: *const fn (self: *anyopaque, index: u32, name: *?[*]u16, propID: *u32, varType: *u16) callconv(cc_com) HRESULT,
};

// kpid property ids (7-Zip) — official numbering from PropID.h
pub const kpidPath: u32 = 3;
pub const kpidName: u32 = 4;
pub const kpidIsDir: u32 = 6;
pub const kpidSize: u32 = 7;
pub const kpidEncrypted: u32 = 15;
pub const kpidIsAnti: u32 = 21;
pub const kpidErrorFlags: u32 = 70;

// ---------------- 7z.dll exports ----------------
pub const CreateObjectFn = *const fn (clsid: *const GUID, iid: *const GUID, out: *?*anyopaque) callconv(cc_com) HRESULT;
pub const GetNumberOfFormatsFn = *const fn (num: *u32) callconv(cc_com) HRESULT;
pub const GetHandlerProperty2Fn = *const fn (index: u32, propID: u32, value: *PROPVARIANT) callconv(cc_com) HRESULT;

pub const NArchive = struct {
    pub const NHandlerPropID = enum(u32) {
        name = 0,
        class_id = 1,
        extension = 2,
        add_extension = 3,
        update = 4,
        keep_name = 5,
        signature = 6,
        multi_signature = 7,
        signature_offset = 8,
        alternate_stream = 9,
        pack_type = 10,
    };
};

pub fn vt(comptime T: type, obj: anytype) *const T {
    const p: *const *const anyopaque = @ptrCast(@alignCast(obj));
    return @ptrCast(@alignCast(p.*));
}
