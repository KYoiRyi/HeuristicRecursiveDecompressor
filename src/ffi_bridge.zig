const std = @import("std");
const com = @import("sevenzip_com.zig");
const util = @import("util.zig");
const ioctx = @import("ioctx.zig");

pub const ArchiveEntry = struct { index: u32, path: []u8, is_dir: bool, size: u64, encrypted: bool };

/// BSTR stores byte-length in a 4-byte header immediately before the data pointer.
fn bstrLen(bstr: [*]const u16) usize {
    const n: *align(2) const u32 = @ptrCast(bstr - 2); // 4 bytes = 2 u16
    return n.* / 2;
}

extern "kernel32" fn GetStdHandle(nStdHandle: u32) ?*anyopaque;
extern "kernel32" fn WriteFile(h: ?*anyopaque, buf: [*]const u8, n: u32, written: ?*u32, overlapped: ?*anyopaque) i32;

/// Unbuffered stderr print — survives crashes (no lost output).
pub fn dbg(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    const h = GetStdHandle(0xFFFFFFF4); // STD_ERROR_HANDLE
    if (h) |hh| _ = WriteFile(hh, s.ptr, @intCast(s.len), null, null);
}
pub const ProbeResult = struct { entries: []ArchiveEntry, any_encrypted: bool };
pub const ExtractResult = struct { files: u64, bytes: u64 };
pub const PasswordProvider = struct { getPassword: *const fn (ctx: *PasswordProvider) ?[]const u8, ctx_data: ?*anyopaque = null };
pub const ExtractOptions = struct {
    out_dir: []const u8, overwrite: bool = true, bomb_limit: u64 = 0, test_only: bool = false, password: ?[]const u8 = null,
};

// ═══════════════════════════════════════════════════════════════════════════
// Lib — dynamic 7z.dll loader
// ═══════════════════════════════════════════════════════════════════════════
pub const Lib = struct {
    create_object: com.CreateObjectFn,

    pub fn load() !Lib {
        const lib = loadLib() orelse return error.BackendMissing;
        const sym = getProcAddress(lib, "CreateObject") orelse return error.BackendMissing;
        return .{ .create_object = @ptrCast(sym) };
    }

    fn loadLib() ?*anyopaque {
        const os = @import("builtin").os.tag;
        if (os == .windows) return LoadLibraryW(&[_:0]u16{ '7', 'z', '.', 'd', 'l', 'l' });
        if (os == .macos) return dlopenLoad("lib7z.dylib") orelse dlopenLoad("lib7z.so");
        return dlopenLoad("lib7z.so");
    }

    extern "kernel32" fn LoadLibraryW(name: [*:0]const u16) callconv(.c) ?*anyopaque;
    extern "kernel32" fn GetProcAddress(h: ?*anyopaque, name: [*:0]const u8) callconv(.c) ?*anyopaque;
    extern "c" fn dlopen_posix_ext(filename: [*:0]const u8, flags: c_int) callconv(.c) ?*anyopaque;
    extern "c" fn dlsym_ext(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque;
    fn dlopenLoad(comptime name: [:0]const u8) ?*anyopaque {
        return if (@import("builtin").os.tag == .windows) null else dlopen_posix_ext(name, 1);
    }
    fn getProcAddress(lib: ?*anyopaque, name: [*:0]const u8) ?*anyopaque {
        if (@import("builtin").os.tag == .windows) return GetProcAddress(lib, name);
        return dlsym_ext(lib, name);
    }

    pub fn findHandler(self: *const Lib, alloc: std.mem.Allocator, ext_want: []const u8) !?com.GUID {
        return self.findHandlerSig(alloc, ext_want, null);
    }

    /// Find a handler by extension. When sig_want is provided, the handler's
    /// kpidSignature must start with those bytes (used to disambiguate the
    /// Rar (v4) vs Rar5 handlers, which share the "rar" extension).
    pub fn findHandlerSig(self: *const Lib, alloc: std.mem.Allocator, ext_want: []const u8, sig_want: ?[]const u8) !?com.GUID {
        _ = self;
        const lib = loadLib() orelse return error.BackendMissing;
        const gnf = getProcAddress(lib, "GetNumberOfFormats") orelse return error.BackendMissing;
        const ghp = getProcAddress(lib, "GetHandlerProperty2") orelse return error.BackendMissing;
        const gnf_fn: com.GetNumberOfFormatsFn = @ptrCast(gnf);
        const ghp_fn: com.GetHandlerProperty2Fn = @ptrCast(ghp);
        var n: u32 = 0;
        if (!com.succeeded(gnf_fn(&n))) return error.BackendMissing;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            var pv_ext: com.PROPVARIANT = .{ .vt = 0, .data = .{ .bVal = 0 } };
            if (!com.succeeded(ghp_fn(i, @intFromEnum(com.NArchive.NHandlerPropID.extension), &pv_ext))) continue;
            defer propClear(&pv_ext);
            if (pv_ext.vt != 8 or pv_ext.data.bstrVal == null) continue;
            const bstr = pv_ext.data.bstrVal.?;
            const wlen = bstrLen(bstr);
            const ext_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, bstr[0..wlen]);
            defer alloc.free(ext_utf8);
            var matched = false;
            var tok_it = std.mem.tokenizeScalar(u8, ext_utf8, ' ');
            while (tok_it.next()) |tok| { if (util.eqlNoCase(tok, ext_want)) { matched = true; break; } }
            if (matched) {
                // Optional disambiguation by handler name (Rar vs Rar5 share "rar" ext)
                if (sig_want) |name_want| {
                    var pv_name: com.PROPVARIANT = .{ .vt = 0, .data = .{ .bVal = 0 } };
                    if (com.succeeded(ghp_fn(i, @intFromEnum(com.NArchive.NHandlerPropID.name), &pv_name))) {
                        defer propClear(&pv_name);
                        if (pv_name.vt == 8) {
                            if (pv_name.data.bstrVal) |name_bstr| {
                                const wlen2 = bstrLen(@ptrCast(name_bstr));
                                const nm = try std.unicode.utf16LeToUtf8Alloc(alloc, name_bstr[0..wlen2]);
                                defer alloc.free(nm);
                                if (!util.eqlNoCase(nm, name_want)) continue;
                            } else continue;
                        } else continue;
                    } else continue;
                }
                // kpidClassID returns raw 16-byte GUID as BSTR (not a string!)
                var pv_cls: com.PROPVARIANT = .{ .vt = 0, .data = .{ .bVal = 0 } };
                if (com.succeeded(ghp_fn(i, @intFromEnum(com.NArchive.NHandlerPropID.class_id), &pv_cls))) {
                    defer propClear(&pv_cls);
                    if (pv_cls.vt == 8) {
                        if (pv_cls.data.bstrVal) |cls_bstr| {
                        // Read 16 raw bytes from the BSTR pointer
                        const raw: [*]const u8 = @ptrCast(cls_bstr);
                        return com.GUID{
                            .data1 = @bitCast(raw[0..4].*),
                            .data2 = @bitCast(raw[4..6].*),
                            .data3 = @bitCast(raw[6..8].*),
                            .data4 = raw[8..16].*,
                        };
                        }
                    }
                }
            }
        }
        return null;
    }

    pub fn openArchive(self: *const Lib, alloc: std.mem.Allocator, path: []const u8, clsid: com.GUID, volumes: []const []const u8, password: ?[]const u8) !*Archive {
        const io = ioctx.io();
        var obj: ?*anyopaque = null;
        const hr = self.create_object(&clsid, &com.IID_IInArchive, &obj);
        if (!com.succeeded(hr) or obj == null) return error.OpenFailed;
        var file = ioctx.cwd().openFile(io, path, .{}) catch return error.OpenFailed;
        const size = (file.stat(io) catch { file.close(io); return error.OpenFailed; }).size;
        const stream = try FileInStream.create(io, file, size);
        const open_cb = try OpenCallback.create(alloc, path, volumes, password);
        const vt: *const com.IInArchiveVt = com.vt(com.IInArchiveVt, obj.?);
        const open_hr = vt.Open(obj.?, stream, null, open_cb);
        _ = com.vt(com.IArchiveOpenCallbackVt, open_cb).base.Release(open_cb);
        // Only S_OK means fully opened. S_FALSE (partial open / wrong password on
        // encrypted headers) must be treated as failure.
        if (open_hr != com.S_OK) {
            _ = FileInStream.release(@ptrCast(stream)); com.release(&obj); return error.NotArchive;
        }
        var num: u32 = 0;
        if (!com.succeeded(vt.GetNumberOfItems(obj.?, &num))) { _ = vt.Close(obj.?); _ = vt.base.Release(obj.?); _ = FileInStream.release(@ptrCast(stream)); return error.NotArchive; }
        const a = try alloc.create(Archive);
        a.* = .{ .alloc = alloc, .handle = obj.?, .stream = stream, .num_items = num, .vt = vt };
        return a;
    }

    pub fn probe(self: *const Lib, alloc: std.mem.Allocator, path: []const u8, clsid: com.GUID, volumes: []const []const u8, password: ?[]const u8) !ProbeResult {
        const arc = try self.openArchive(alloc, path, clsid, volumes, password);
        defer { arc.close(); alloc.destroy(arc); }
        const entries = try arc.listEntries(alloc);
        var any = false;
        for (entries) |e| { if (e.encrypted) any = true; }
        return .{ .entries = entries, .any_encrypted = any };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Archive — list + streaming extract
// ═══════════════════════════════════════════════════════════════════════════
pub const Archive = struct {
    alloc: std.mem.Allocator,
    handle: *anyopaque,
    stream: *FileInStream,
    num_items: u32,
    vt: *const com.IInArchiveVt,

    pub fn listEntries(self: *Archive, alloc: std.mem.Allocator) ![]ArchiveEntry {
        var list = std.ArrayList(ArchiveEntry).empty;
        errdefer { for (list.items) |e| alloc.free(e.path); list.deinit(alloc); }
        var i: u32 = 0;
        while (i < self.num_items) : (i += 1) {
            var pv_path: com.PROPVARIANT = .{ .vt = 0, .data = .{ .bVal = 0 } };
            _ = self.vt.GetProperty(self.handle, i, com.kpidPath, &pv_path);
            defer propClear(&pv_path);
            var path: []u8 = "";
            if (pv_path.vt == 8 and pv_path.data.bstrVal != null) {
                const bstr = pv_path.data.bstrVal.?;
                const wlen = bstrLen(bstr);
                path = try std.unicode.utf16LeToUtf8Alloc(alloc, bstr[0..wlen]);
            } else { path = try alloc.dupe(u8, "unnamed"); }
            var is_dir = false; var encrypted = false; var size: u64 = 0;
            var pv: com.PROPVARIANT = .{ .vt = 0, .data = .{ .bVal = 0 } };
            if (com.succeeded(self.vt.GetProperty(self.handle, i, com.kpidIsDir, &pv))) { if (pv.vt == 11) is_dir = pv.data.boolVal != 0; propClear(&pv); }
            pv = .{ .vt = 0, .data = .{ .bVal = 0 } };
            if (com.succeeded(self.vt.GetProperty(self.handle, i, com.kpidEncrypted, &pv))) { if (pv.vt == 11) encrypted = pv.data.boolVal != 0; propClear(&pv); }
            pv = .{ .vt = 0, .data = .{ .bVal = 0 } };
            if (com.succeeded(self.vt.GetProperty(self.handle, i, com.kpidSize, &pv))) {
                size = switch (pv.vt) { 19 => pv.data.ulVal, 21 => pv.data.uhVal, 3 => @intCast(@max(0, pv.data.lVal)), else => 0, };
                propClear(&pv);
            }
            try list.append(alloc, .{ .index = i, .path = path, .is_dir = is_dir, .size = size, .encrypted = encrypted });
        }
        return list.toOwnedSlice(alloc);
    }

    pub fn extractAll(self: *Archive, opts: ExtractOptions) !ExtractResult {
        const io = ioctx.io();
        try ioctx.cwd().createDirPath(io, opts.out_dir);

        // Pre-fetch all entry paths for fast lookup during extraction
        const entries = try self.listEntries(self.alloc);
        defer {
            for (entries) |e| self.alloc.free(e.path);
            self.alloc.free(entries);
        }

        // Create the streaming extraction callback (heap: 32MB write buffer must not live on the stack)
        const cb = try self.alloc.create(ExtractCB);
        cb.* = .{
            .alloc = self.alloc,
            .io = io,
            .refcount = std.atomic.Value(u32).init(1),
            .out_dir = opts.out_dir,
            .bomb_limit = opts.bomb_limit,
            .total_written = 0,
            .files_written = 0,
            .bomb_tripped = false,
            .first_error = null,
            .cur_file = null,
            .cur_pos = 0,
            .entries = entries,
            .password = opts.password,
            .out_dir_z = try self.alloc.dupeZ(u8, opts.out_dir),
        };
        defer {
            self.alloc.destroy(cb);
        }
        defer {
            self.alloc.free(cb.out_dir_z);
        }

        // indices=NULL + numItems=(UInt32)-1 => extract ALL items (7-Zip convention)
        const hr = self.vt.Extract(self.handle, null, std.math.maxInt(u32), if (opts.test_only) 1 else 0, @ptrCast(cb));

        if (cb.bomb_tripped) return error.Bomb;
        if (cb.first_error) |e| return e;
        if (!com.succeeded(hr)) return error.Fail;
        return .{ .files = cb.files_written, .bytes = cb.total_written };
    }

    /// Verify a password by test-decrypting a single entry (testMode=1:
    /// full decrypt+CRC in memory, nothing written). Fast entry-level check
    /// for zip-style archives whose headers are readable without a password.
    pub fn testPassword(self: *Archive, index: u32, password: ?[]const u8) bool {
        const cb = self.alloc.create(ExtractCB) catch return false;
        cb.* = .{
            .alloc = self.alloc,
            .io = ioctx.io(),
            .refcount = std.atomic.Value(u32).init(1),
            .out_dir = "",
            .bomb_limit = 0,
            .total_written = 0,
            .files_written = 0,
            .bomb_tripped = false,
            .first_error = null,
            .cur_file = null,
            .cur_pos = 0,
            .entries = &.{},
            .password = password,
            .out_dir_z = self.alloc.dupeZ(u8, "") catch {
                self.alloc.destroy(cb);
                return false;
            },
        };
        defer self.alloc.free(cb.out_dir_z);
        defer self.alloc.destroy(cb);

        var idx = index;
        const hr = self.vt.Extract(self.handle, @ptrCast(&idx), 1, 1, @ptrCast(cb));
        if (cb.first_error != null) return false;
        return com.succeeded(hr);
    }

    pub fn close(self: *Archive) void {
        _ = self.vt.Close(self.handle);
        _ = self.vt.base.Release(self.handle); // 7z drops its stream ref first (CMyComPtr)
        _ = FileInStream.release(@ptrCast(self.stream)); // then we drop ours
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// ExtractCB — COM IArchiveExtractCallback with buffered streaming writes
// ═══════════════════════════════════════════════════════════════════════════
const WRITE_BUF_SIZE = 1 << 25; // 32MB write buffer for large files

const ExtractCB = struct {
    vt: *const com.IArchiveExtractCallbackVt = &extract_cb_vt,
    crypto: CryptoPart = .{},
    refcount: std.atomic.Value(u32),
    alloc: std.mem.Allocator,
    io: std.Io,
    out_dir: []const u8,
    out_dir_z: [:0]const u8,
    bomb_limit: u64,
    total_written: u64,
    files_written: u64,
    bomb_tripped: bool,
    first_error: ?error{ DataError, WrongPassword, Cancelled, Fail },
    cur_file: ?std.Io.File,
    cur_pos: u64,
    entries: []ArchiveEntry,
    password: ?[]const u8 = null,
    write_buf: [WRITE_BUF_SIZE]u8 = undefined,
    write_off: usize = 0,

    const CryptoPart = struct {
        vt: *const com.ICryptoGetTextPasswordVt = &extract_crypto_vt,
    };

    fn qi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        const self: *ExtractCB = @ptrCast(@alignCast(p));
        // COM rule: QI must AddRef the returned interface.
        if (riid.eql(com.IID_IArchiveExtractCallback)) { out.* = p; _ = addRef(p); return com.S_OK; }
        if (riid.eql(com.IID_ICryptoGetTextPassword)) {
            const v: *anyopaque = @ptrCast(&self.crypto);
            out.* = v; _ = cryptoAddRef(v); return com.S_OK;
        }
        out.* = null; return com.E_NOTIMPL;
    }
    fn cryptoQi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        const self: *ExtractCB = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        if (riid.eql(com.IID_ICryptoGetTextPassword)) { out.* = p; _ = cryptoAddRef(p); return com.S_OK; }
        if (riid.eql(com.IID_IArchiveExtractCallback)) { out.* = self; _ = addRef(self); return com.S_OK; }
        out.* = null; return com.E_NOTIMPL;
    }
    fn cryptoAddRef(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *ExtractCB = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        return self.refcount.fetchAdd(1, .monotonic) + 1;
    }
    fn cryptoRelease(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *ExtractCB = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        return self.refcount.fetchSub(1, .monotonic) - 1;
    }
    fn cryptoGetTextPassword(p: *anyopaque, password: *?[*]u16) callconv(com.cc_com) com.HRESULT {
        const self: *ExtractCB = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        password.* = null;
        const pw = self.password orelse {
            return com.E_FAIL;
        };
        const w = std.unicode.utf8ToUtf16LeAllocZ(std.heap.c_allocator, pw) catch return com.E_OUTOFMEMORY;
        defer std.heap.c_allocator.free(w);
        password.* = sysAllocString(w);
        if (password.* == null) return com.E_OUTOFMEMORY;
        return com.S_OK;
    }
    fn addRef(p: *anyopaque) callconv(com.cc_com) u32 {
        return @as(*ExtractCB, @ptrCast(@alignCast(p))).refcount.fetchAdd(1, .monotonic) + 1;
    }
    fn release(p: *anyopaque) callconv(com.cc_com) u32 {
        return @as(*ExtractCB, @ptrCast(@alignCast(p))).refcount.fetchSub(1, .monotonic) - 1;
    }
    fn setTotal(p: *anyopaque, _: u64) callconv(com.cc_com) com.HRESULT { _ = p; return com.S_OK; }
    fn setCompleted(p: *anyopaque, _: *const u64) callconv(com.cc_com) com.HRESULT { _ = p; return com.S_OK; }

    fn getStream(p: *anyopaque, index: u32, outStream: *?*anyopaque, askExtractMode: i32) callconv(com.cc_com) com.HRESULT {
        const self: *ExtractCB = @ptrCast(@alignCast(p));
        outStream.* = null;
        if (askExtractMode != 0) return com.S_OK; // only kExtract

        // Flush previous file buffer
        self.flushBuf() catch {};

        // Close previous file
        if (self.cur_file) |*f| {
            f.close(self.io);
            self.cur_file = null;
        }

        // Look up the entry path by index
        if (index >= self.entries.len) return com.E_FAIL;
        const entry = self.entries[index];

        // Skip directories — 7z handles them via SetOperationResult
        if (entry.is_dir) {
            const full_path = std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ self.out_dir, entry.path }) catch return com.E_OUTOFMEMORY;
            defer self.alloc.free(full_path);
            ioctx.cwd().createDirPath(self.io, full_path) catch {};
            return com.S_OK;
        }

        // Build full output path
        const full_path = std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ self.out_dir, entry.path }) catch return com.E_OUTOFMEMORY;
        defer self.alloc.free(full_path);

        // Ensure parent directory exists
        if (std.fs.path.dirname(full_path)) |d| ioctx.cwd().createDirPath(self.io, d) catch {};

        // Open the output file
        self.cur_file = ioctx.cwd().createFile(self.io, full_path, .{ .truncate = true }) catch return com.E_FAIL;
        self.cur_pos = 0;
        self.write_off = 0;

        // Create the write shim
        const shim = self.alloc.create(WriteShim) catch return com.E_OUTOFMEMORY;
        shim.* = .{ .refcount = std.atomic.Value(u32).init(1), .cb = self, .bytes_written = 0 };
        outStream.* = @ptrCast(shim);
        return com.S_OK;
    }

    fn prepareOp(_: *anyopaque, _: i32) callconv(com.cc_com) com.HRESULT { return com.S_OK; }

    fn setOpResult(p: *anyopaque, opRes: i32) callconv(com.cc_com) com.HRESULT {
        const self: *ExtractCB = @ptrCast(@alignCast(p));
        // Flush buffer
        self.flushBuf() catch {};
        // Close current file
        if (self.cur_file) |*f| {
            f.close(self.io);
            self.cur_file = null;
        }
        const R = com.NExtract.NOperationResult;
        const res: R = @enumFromInt(opRes);
        switch (res) {
            .ok => {},
            .data_error, .unexpected_end, .data_after_end, .is_not_arc, .crc_error => {
                if (self.first_error == null) self.first_error = error.DataError;
            },
            .wrong_password => { if (self.first_error == null) self.first_error = error.WrongPassword; },
            .unsupported_method, .headers_error => { if (self.first_error == null) self.first_error = error.DataError; },
            else => { if (self.first_error == null) self.first_error = error.Fail; },
        }
        self.files_written += 1;
        return if (self.first_error != null) com.E_FAIL else com.S_OK;
    }

    fn flushBuf(self: *ExtractCB) !void {
        if (self.write_off == 0) return;
        if (self.cur_file) |*f| {
            try f.writePositionalAll(self.io, self.write_buf[0..self.write_off], self.cur_pos);
            self.cur_pos += self.write_off;
            self.total_written += self.write_off;
        }
        self.write_off = 0;
    }

    fn writeChunk(self: *ExtractCB, data: []const u8) !void {
        if (self.bomb_limit > 0 and self.total_written + data.len > self.bomb_limit) {
            self.bomb_tripped = true;
            return error.DataError;
        }
        var remaining = data;
        while (remaining.len > 0) {
            const space = WRITE_BUF_SIZE - self.write_off;
            if (remaining.len >= space) {
                @memcpy(self.write_buf[self.write_off..][0..space], remaining[0..space]);
                self.write_off = WRITE_BUF_SIZE;
                try self.flushBuf();
                remaining = remaining[space..];
            } else {
                @memcpy(self.write_buf[self.write_off..][0..remaining.len], remaining);
                self.write_off += remaining.len;
                remaining = &.{};
            }
        }
    }
};

// Static vtable for ExtractCB (COM objects must expose a POINTER to their vtable at offset 0)
const extract_cb_vt = com.IArchiveExtractCallbackVt{
    .base = .{ .QueryInterface = ExtractCB.qi, .AddRef = ExtractCB.addRef, .Release = ExtractCB.release },
    .SetTotal = ExtractCB.setTotal,
    .SetCompleted = ExtractCB.setCompleted,
    .GetStream = ExtractCB.getStream,
    .PrepareOperation = ExtractCB.prepareOp,
    .SetOperationResult = ExtractCB.setOpResult,
};

const extract_crypto_vt = com.ICryptoGetTextPasswordVt{
    .base = .{ .QueryInterface = ExtractCB.cryptoQi, .AddRef = ExtractCB.cryptoAddRef, .Release = ExtractCB.cryptoRelease },
    .CryptoGetTextPassword = ExtractCB.cryptoGetTextPassword,
};

// ═══════════════════════════════════════════════════════════════════════════
// WriteShim — thin COM wrapper that routes Write calls into ExtractCB
// ═══════════════════════════════════════════════════════════════════════════
const WriteShim = struct {
    vt: *const com.ISequentialOutStreamVt = &write_shim_vt,
    refcount: std.atomic.Value(u32),
    cb: *ExtractCB,
    bytes_written: u64,

    fn qi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        if (riid.eql(com.IID_ISequentialOutStream)) { out.* = p; _ = addRef(p); return com.S_OK; }
        out.* = null; return com.E_NOTIMPL;
    }
    fn addRef(p: *anyopaque) callconv(com.cc_com) u32 {
        return @as(*WriteShim, @ptrCast(@alignCast(p))).refcount.fetchAdd(1, .monotonic) + 1;
    }
    fn release(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *WriteShim = @ptrCast(@alignCast(p));
        const n = self.refcount.fetchSub(1, .monotonic) - 1;
        if (n == 0) self.cb.alloc.destroy(self);
        return n;
    }
    fn write(p: *anyopaque, data: [*]const u8, size: u32, processed: ?*u32) callconv(com.cc_com) com.HRESULT {
        const self: *WriteShim = @ptrCast(@alignCast(p));
        self.cb.writeChunk(data[0..size]) catch return com.E_FAIL;
        self.bytes_written += size;
        if (processed) |pp| pp.* = size;
        return com.S_OK;
    }
};

const write_shim_vt = com.ISequentialOutStreamVt{
    .base = .{ .QueryInterface = WriteShim.qi, .AddRef = WriteShim.addRef, .Release = WriteShim.release },
    .Write = WriteShim.write,
};

// ═══════════════════════════════════════════════════════════════════════════
// FileInStream — buffered IInStream for 7z.dll
// ═══════════════════════════════════════════════════════════════════════════
const FileInStream = struct {
    vt: *const com.IInStreamVt = &file_in_stream_vt,
    refcount: std.atomic.Value(u32),
    io: std.Io,
    file: std.Io.File,
    size: u64,
    pos: u64 = 0,
    // Read-ahead buffer: 4MB for large sequential reads
    rbuf: [1 << 22] u8 = undefined,
    rbuf_start: u64 = 0,
    rbuf_len: usize = 0,

    fn create(io: std.Io, file: std.Io.File, size: u64) !*FileInStream {
        const self = try std.heap.c_allocator.create(FileInStream);
        self.* = .{ .refcount = std.atomic.Value(u32).init(1), .io = io, .file = file, .size = size };
        return self;
    }

    fn qi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        // IInStream and ISequentialInStream share our vtable layout.
        if (riid.eql(com.IID_IInStream) or riid.eql(com.IID_ISequentialInStream)) { out.* = p; _ = addRef(p); return com.S_OK; }
        out.* = null; return com.E_NOTIMPL;
    }
    fn addRef(p: *anyopaque) callconv(com.cc_com) u32 {
        return @as(*FileInStream, @ptrCast(@alignCast(p))).refcount.fetchAdd(1, .monotonic) + 1;
    }
    fn release(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *FileInStream = @ptrCast(@alignCast(p));
        const n = self.refcount.fetchSub(1, .monotonic) - 1;
        if (n == 0) { self.file.close(self.io); std.heap.c_allocator.destroy(self); }
        return n;
    }

    fn read(p: *anyopaque, data: [*]u8, size: u32, processed: ?*u32) callconv(com.cc_com) com.HRESULT {
        const self: *FileInStream = @ptrCast(@alignCast(p));
        const want: usize = size;
        var written: usize = 0;

        // Serve from read-ahead buffer if possible
        if (self.rbuf_len > 0 and self.pos >= self.rbuf_start and self.pos < self.rbuf_start + self.rbuf_len) {
            const buf_off = self.pos - self.rbuf_start;
            const avail = self.rbuf_len - buf_off;
            const take = @min(want, avail);
            @memcpy(data[0..take], self.rbuf[buf_off..][0..take]);
            written += take;
            self.pos += take;
        }

        // Direct read for remaining — use large chunks for sequential access
        while (written < want) {
            const chunk = @min(want - written, 1 << 22);
            const n = self.file.readPositional(self.io, &.{data[written..][0..chunk]}, self.pos) catch return com.E_FAIL;
            if (n == 0) break;
            written += n;
            self.pos += n;
        }

        // Pre-fill read-ahead buffer for next call (sequential access pattern)
        if (self.rbuf_len == 0 and self.pos < self.size) {
            const prefetch = @min(self.rbuf.len, self.size - self.pos);
            if (prefetch > 0) {
                const n = self.file.readPositional(self.io, &.{&self.rbuf}, self.pos) catch 0;
                self.rbuf_start = self.pos;
                self.rbuf_len = n;
            }
        }

        if (processed) |pp| pp.* = @intCast(written);
        return com.S_OK;
    }

    fn seek(p: *anyopaque, offset: i64, origin: u32, newPos: ?*u64) callconv(com.cc_com) com.HRESULT {
        const self: *FileInStream = @ptrCast(@alignCast(p));
        switch (origin) {
            0 => self.pos = if (offset >= 0) @intCast(offset) else 0, // STREAM_SEEK_SET
            1 => { // STREAM_SEEK_CUR
                const np = @as(i64, @intCast(self.pos)) + offset;
                self.pos = if (np >= 0) @intCast(np) else 0;
            },
            2 => { // STREAM_SEEK_END
                const np = @as(i64, @intCast(self.size)) + offset;
                self.pos = if (np >= 0) @intCast(np) else 0;
            },
            else => {},
        }
        self.rbuf_len = 0; // invalidate read-ahead on any seek
        if (newPos) |np| np.* = self.pos;
        return com.S_OK;
    }

    pub fn release_ref(self: *FileInStream) void { _ = release(@ptrCast(self)); }
};

const file_in_stream_vt = com.IInStreamVt{
    .base = .{ .base = .{ .QueryInterface = FileInStream.qi, .AddRef = FileInStream.addRef, .Release = FileInStream.release }, .Read = FileInStream.read },
    .Seek = FileInStream.seek,
};

// ═══════════════════════════════════════════════════════════════════════════
// OpenCallback — IArchiveOpenCallback + IArchiveOpenVolumeCallback (multi-volume)
// ═══════════════════════════════════════════════════════════════════════════
const OpenCallback = struct {
    vt: *const com.IArchiveOpenCallbackVt = &open_cb_vt,
    vol: VolPart = .{},
    crypto: CryptoPart = .{},
    refcount: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    alloc: std.mem.Allocator,
    path: []const u8 = "",
    /// Paths of the other volumes in the same logical archive.
    volumes: []const []const u8 = &.{},
    /// Password supplied for encrypted-name archives (null = none).
    password: ?[]const u8 = null,

    const VolPart = struct {
        vt: *const com.IArchiveOpenVolumeCallbackVt = &open_vol_vt,
    };
    const CryptoPart = struct {
        vt: *const com.ICryptoGetTextPasswordVt = &open_crypto_vt,
    };

    fn create(alloc: std.mem.Allocator, path: []const u8, volumes: []const []const u8, password: ?[]const u8) !*OpenCallback {
        const self = try std.heap.c_allocator.create(OpenCallback);
        self.* = .{ .alloc = alloc, .path = path, .volumes = volumes, .password = password };
        return self;
    }

    fn qi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        const self: *OpenCallback = @ptrCast(@alignCast(p));
        if (riid.eql(com.IID_IArchiveOpenCallback)) { out.* = p; _ = addRef(p); return com.S_OK; }
        if (riid.eql(com.IID_IArchiveOpenVolumeCallback)) { const v: *anyopaque = @ptrCast(&self.vol); out.* = v; _ = volAddRef(v); return com.S_OK; }
        if (riid.eql(com.IID_ICryptoGetTextPassword)) { const v: *anyopaque = @ptrCast(&self.crypto); out.* = v; _ = cryptoAddRef(v); return com.S_OK; }
        out.* = null; return com.E_NOTIMPL;
    }
    fn volQi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        const self: *OpenCallback = @fieldParentPtr("vol", @as(*VolPart, @ptrCast(@alignCast(p))));
        if (riid.eql(com.IID_IArchiveOpenVolumeCallback)) { out.* = p; _ = volAddRef(p); return com.S_OK; }
        if (riid.eql(com.IID_IArchiveOpenCallback)) { out.* = self; _ = addRef(self); return com.S_OK; }
        out.* = null; return com.E_NOTIMPL;
    }
    fn addRef(p: *anyopaque) callconv(com.cc_com) u32 { return @as(*OpenCallback, @ptrCast(@alignCast(p))).refcount.fetchAdd(1, .monotonic) + 1; }
    fn volAddRef(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *OpenCallback = @fieldParentPtr("vol", @as(*VolPart, @ptrCast(@alignCast(p))));
        return self.refcount.fetchAdd(1, .monotonic) + 1;
    }
    fn rel(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *OpenCallback = @ptrCast(@alignCast(p));
        const n = self.refcount.fetchSub(1, .monotonic) - 1;
        if (n == 0) std.heap.c_allocator.destroy(self);
        return n;
    }
    fn volRel(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *OpenCallback = @fieldParentPtr("vol", @as(*VolPart, @ptrCast(@alignCast(p))));
        const n = self.refcount.fetchSub(1, .monotonic) - 1;
        if (n == 0) std.heap.c_allocator.destroy(self);
        return n;
    }
    fn setTotal(_: *anyopaque, _: ?*const u64, _: ?*const u64) callconv(com.cc_com) com.HRESULT {
        return com.S_OK;
    }
    fn setCompleted(_: *anyopaque, _: ?*const u64, _: ?*const u64) callconv(com.cc_com) com.HRESULT { return com.S_OK; }

    fn findVolume(self: *OpenCallback, name: [*:0]const u16) ?[]const u8 {
        // Convert requested name (usually just the volume basename) to UTF-8
        var wbuf: [512]u16 = undefined;
        var wlen: usize = 0;
        while (wlen < 512 and name[wlen] != 0) : (wlen += 1) {}
        @memcpy(wbuf[0..wlen], name[0..wlen]);
        const want = std.unicode.utf16LeToUtf8Alloc(self.alloc, wbuf[0..wlen]) catch return null;
        defer self.alloc.free(want);

        for (self.volumes) |v| {
            if (std.mem.eql(u8, v, want)) return v;
            const base = util.basename(v);
            if (util.eqlNoCase(base, want)) return v;
        }
        return null;
    }

    fn volGetStream(p: *anyopaque, name: [*:0]const u16, inStream: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        const self: *OpenCallback = @fieldParentPtr("vol", @as(*VolPart, @ptrCast(@alignCast(p))));
        inStream.* = null;
        if (@intFromPtr(name) < 0x10000) {
            return com.S_FALSE;
        }
        var wl: usize = 0;
        while (wl < 512 and name[wl] != 0) : (wl += 1) {}
        const nm = std.unicode.utf16LeToUtf8Alloc(std.heap.c_allocator, name[0..wl]) catch return com.S_FALSE;
        defer std.heap.c_allocator.free(nm);
        const vol_path = self.findVolume(name) orelse {
            return com.S_FALSE;
        };
        const io = ioctx.io();
        var file = ioctx.cwd().openFile(io, vol_path, .{}) catch return com.S_FALSE;
        const size = (file.stat(io) catch { file.close(io); return com.S_FALSE; }).size;
        const stream = FileInStream.create(io, file, size) catch { file.close(io); return com.E_OUTOFMEMORY; };
        inStream.* = @ptrCast(stream);
        return com.S_OK;
    }

    fn volGetProperty(p: *anyopaque, propID: u32, value: *com.PROPVARIANT) callconv(com.cc_com) com.HRESULT {
        const self: *OpenCallback = @fieldParentPtr("vol", @as(*VolPart, @ptrCast(@alignCast(p))));
        value.vt = 0;
        if (propID == com.kpidName) {
            // 7z derives sibling volume names from the archive name
            const w = std.unicode.utf8ToUtf16LeAllocZ(std.heap.c_allocator, self.path) catch return com.E_OUTOFMEMORY;
            defer std.heap.c_allocator.free(w);
            value.vt = 8; // VT_BSTR
            value.data.bstrVal = sysAllocString(w);
            if (value.data.bstrVal == null) return com.E_OUTOFMEMORY;
        } else if (propID == com.kpidSize) {
            value.vt = 21; // VT_UI8
            value.data.uhVal = 0;
        }
        return com.S_OK;
    }

    fn cryptoQi(p: *anyopaque, riid: *const com.GUID, out: *?*anyopaque) callconv(com.cc_com) com.HRESULT {
        const self: *OpenCallback = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        if (riid.eql(com.IID_ICryptoGetTextPassword)) { out.* = p; return com.S_OK; }
        if (riid.eql(com.IID_IArchiveOpenCallback)) { out.* = self; return com.S_OK; }
        out.* = null; return com.E_NOTIMPL;
    }
    fn cryptoAddRef(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *OpenCallback = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        return self.refcount.fetchAdd(1, .monotonic) + 1;
    }
    fn cryptoRel(p: *anyopaque) callconv(com.cc_com) u32 {
        const self: *OpenCallback = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        const n = self.refcount.fetchSub(1, .monotonic) - 1;
        if (n == 0) std.heap.c_allocator.destroy(self);
        return n;
    }
    fn cryptoGetTextPassword(p: *anyopaque, password: *?[*]u16) callconv(com.cc_com) com.HRESULT {
        const self: *OpenCallback = @fieldParentPtr("crypto", @as(*CryptoPart, @ptrCast(@alignCast(p))));
        password.* = null;
        const pw = self.password orelse {
            return com.E_FAIL;
        }; // no password available
        const w = std.unicode.utf8ToUtf16LeAllocZ(std.heap.c_allocator, pw) catch return com.E_OUTOFMEMORY;
        defer std.heap.c_allocator.free(w);
        password.* = sysAllocString(w);
        if (password.* == null) return com.E_OUTOFMEMORY;
        return com.S_OK;
    }
};

const open_cb_vt = com.IArchiveOpenCallbackVt{
    .base = .{ .QueryInterface = OpenCallback.qi, .AddRef = OpenCallback.addRef, .Release = OpenCallback.rel },
    .SetTotal = OpenCallback.setTotal,
    .SetCompleted = OpenCallback.setCompleted,
};

const open_vol_vt = com.IArchiveOpenVolumeCallbackVt{
    .base = .{ .QueryInterface = OpenCallback.volQi, .AddRef = OpenCallback.volAddRef, .Release = OpenCallback.volRel },
    .GetProperty = OpenCallback.volGetProperty,
    .GetStream = OpenCallback.volGetStream,
};

const open_crypto_vt = com.ICryptoGetTextPasswordVt{
    .base = .{ .QueryInterface = OpenCallback.cryptoQi, .AddRef = OpenCallback.cryptoAddRef, .Release = OpenCallback.cryptoRel },
    .CryptoGetTextPassword = OpenCallback.cryptoGetTextPassword,
};

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════
fn propClear(pv: *com.PROPVARIANT) void {
    if (pv.vt == 8) { if (pv.data.bstrVal) |b| sysFreeString(b); }
    pv.vt = 0;
}
extern "oleaut32" fn SysFreeString(bstr: ?[*]u16) void;
fn sysFreeString(b: ?[*]u16) void { SysFreeString(b); }
extern "oleaut32" fn SysAllocStringLen(str: ?[*]const u16, len: u32) ?[*]u16;
fn sysAllocString(w: []const u16) ?[*]u16 { return SysAllocStringLen(w.ptr, @intCast(w.len)); }

fn parseGuid(s: []const u8) ?com.GUID {
    const hv = struct { fn f(c: u8) ?u4 { return switch (c) { '0'...'9' => @intCast(c - '0'), 'a'...'f' => @intCast(c - 'a' + 10), 'A'...'F' => @intCast(c - 'A' + 10), else => null }; } }.f;
    var t = s;
    if (t.len >= 2 and t[0] == '{') t = t[1 .. t.len - 1];
    if (t.len != 36 or t[8] != '-' or t[13] != '-' or t[18] != '-' or t[23] != '-') return null;
    var g: com.GUID = .{ .data1 = 0, .data2 = 0, .data3 = 0, .data4 = [_]u8{0} ** 8 };
    var shift: i32 = 28; var ii: usize = 0;
    while (ii < 8) : (ii += 1) { g.data1 |= @as(u32, hv(t[ii]) orelse return null) << @intCast(shift); shift -= 4; }
    shift = 12; ii = 9;
    while (ii < 13) : (ii += 1) { g.data2 |= @as(u16, hv(t[ii]) orelse return null) << @intCast(shift); shift -= 4; }
    shift = 12; ii = 14;
    while (ii < 18) : (ii += 1) { g.data3 |= @as(u16, hv(t[ii]) orelse return null) << @intCast(shift); shift -= 4; }
    var j: usize = 0; ii = 19;
    while (j < 4) : (j += 1) { g.data4[j] = (@as(u8, hv(t[ii]) orelse return null) << 4) | (hv(t[ii + 1]) orelse return null); ii += 2; }
    ii = 24;
    while (j < 8) : (j += 1) { g.data4[j] = (@as(u8, hv(t[ii]) orelse return null) << 4) | (hv(t[ii + 1]) orelse return null); ii += 2; }
    return g;
}
