const std = @import("std");
const types = @import("types.zig");
const engine_mod = @import("engine.zig");
const util = @import("util.zig");

const HRD_STATUS_OK = 0;
const HRD_STATUS_ERR_INVALID_ARG = 1;
const HRD_STATUS_ERR_IO = 2;
const HRD_STATUS_ERR_UNSUPPORTED = 3;
const HRD_STATUS_ERR_ENCRYPTED = 4;
const HRD_STATUS_ERR_PASSWORD = 5;
const HRD_STATUS_ERR_BOMB = 6;
const HRD_STATUS_ERR_DEPTH = 7;
const HRD_STATUS_ERR_ARCHIVE = 8;
const HRD_STATUS_ERR_NOMEM = 9;
const HRD_STATUS_ERR_CANCELLED = 10;
const HRD_STATUS_ERR_INTERNAL = 255;

var gpa_storage: ?std.heap.DebugAllocator(.{}) = null;

fn gpa() std.mem.Allocator {
    if (gpa_storage == null) gpa_storage = .{};
    return gpa_storage.?.allocator();
}

const CtxEntry = struct {
    ctx: *engine_mod.Engine,
};

var ctx_map = std.StringHashMap(*engine_mod.Engine).init(undefined);
var ctx_map_init = false;

fn ensureCtxMap() void {
    if (!ctx_map_init) {
        ctx_map = std.StringHashMap(*engine_mod.Engine).init(gpa());
        ctx_map_init = true;
    }
}

fn toStatus(e: anyerror) c_int {
    const val: c_int = switch (e) {
        error.OutOfMemory => HRD_STATUS_ERR_NOMEM,
        error.BackendMissing => HRD_STATUS_ERR_UNSUPPORTED,
        error.OpenFailed, error.NotArchive => HRD_STATUS_ERR_ARCHIVE,
        error.EncryptedHeaders, error.WrongPassword => HRD_STATUS_ERR_ENCRYPTED,
        error.DataError, error.CrcError, error.UndecryptableFile => HRD_STATUS_ERR_ARCHIVE,
        error.Cancelled => HRD_STATUS_ERR_CANCELLED,
        error.Bomb => HRD_STATUS_ERR_BOMB,
        else => HRD_STATUS_ERR_INTERNAL,
    };
    return val;
}

export fn hrd_abi_version() callconv(.c) u32 {
    return 1 << 16 | 0; // v1.0
}

export fn hrd_status_string(st: c_int) callconv(.c) [*:0]const u8 {
    return switch (st) {
        HRD_STATUS_OK => "ok",
        HRD_STATUS_ERR_INVALID_ARG => "invalid argument",
        HRD_STATUS_ERR_IO => "I/O error",
        HRD_STATUS_ERR_UNSUPPORTED => "unsupported format",
        HRD_STATUS_ERR_ENCRYPTED => "encrypted (password needed)",
        HRD_STATUS_ERR_PASSWORD => "wrong password",
        HRD_STATUS_ERR_BOMB => "bomb limit exceeded",
        HRD_STATUS_ERR_DEPTH => "max recursion depth",
        HRD_STATUS_ERR_ARCHIVE => "archive error",
        HRD_STATUS_ERR_NOMEM => "out of memory",
        HRD_STATUS_ERR_CANCELLED => "cancelled",
        else => "unknown error",
    };
}

export fn hrd_ctx_create(opts_ptr: ?*const anyopaque) callconv(.c) ?*anyopaque {
    _ = opts_ptr;
    const alloc = gpa();
    const eng = alloc.create(engine_mod.Engine) catch return null;
    eng.* = engine_mod.Engine.init(alloc, .{}) catch return null;
    ensureCtxMap();
    var buf: [20]u8 = undefined;
    const id = std.fmt.bufPrint(&buf, "{x}", .{@intFromPtr(eng)}) catch return null;
    ctx_map.put(alloc.dupe(u8, id) catch return null, eng) catch return null;
    return @ptrCast(eng);
}

export fn hrd_ctx_destroy(ctx: ?*anyopaque) callconv(.c) void {
    if (ctx) |c| {
        const eng: *engine_mod.Engine = @ptrCast(@alignCast(c));
        eng.deinit();
        gpa().destroy(eng);
    }
}

export fn hrd_process(
    ctx: ?*anyopaque,
    inputs: ?[*]const [*:0]const u8,
    input_count: usize,
    out_dir: ?[*:0]const u8,
    out_report: ?*?[*:0]const u8,
) callconv(.c) c_int {
    if (ctx == null or inputs == null or out_dir == null) return HRD_STATUS_ERR_INVALID_ARG;
    const eng: *engine_mod.Engine = @ptrCast(@alignCast(ctx.?));
    const alloc = gpa();

    const inputs_raw = inputs.?[0..input_count];
    var input_list = std.ArrayList([]const u8).empty;
    defer input_list.deinit(alloc);
    for (inputs_raw) |inp| {
        input_list.append(alloc, std.mem.span(inp)) catch return HRD_STATUS_ERR_NOMEM;
    }
    const od = std.mem.span(out_dir.?);

    const report = eng.process(input_list.items, od) catch |e| return toStatus(e);

    if (out_report) |or_| {
        const r = std.fmt.allocPrint(
            alloc,
            "{{\"archives\":{d},\"delivered_files\":{d},\"delivered_bytes\":{d},\"errors\":{d},\"passwords_used\":{d}}}",
            .{ report.archives, report.delivered_files, report.delivered_bytes, report.errors, report.passwords_used },
        ) catch return HRD_STATUS_ERR_NOMEM;
        or_.* = @ptrCast(r.ptr);
    }
    return HRD_STATUS_OK;
}

export fn hrd_free(p: ?*anyopaque) callconv(.c) void {
    if (p) |ptr| {
        gpa().free(std.mem.span(@as([*:0]const u8, @ptrCast(ptr))));
    }
}
