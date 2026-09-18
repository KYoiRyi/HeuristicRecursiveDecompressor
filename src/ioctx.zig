const std = @import("std");

/// Global IO context: owns one std.Io.Threaded instance for the process.
/// All file operations in hrd go through here (Zig 0.16 explicit-IO style).
var threaded_storage: ?std.Io.Threaded = null;

pub fn init(alloc: std.mem.Allocator) void {
    if (threaded_storage == null) {
        threaded_storage = std.Io.Threaded.init(alloc, .{});
    }
}

pub fn deinit() void {
    if (threaded_storage) |*t| {
        t.deinit();
        threaded_storage = null;
    }
}

pub fn io() std.Io {
    std.debug.assert(threaded_storage != null);
    return threaded_storage.?.io();
}

pub fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

/// getenv via libc (works on every desktop target; we always link libc).
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

pub fn getenvZ(name: [*:0]const u8) ?[]const u8 {
    const v = getenv(name) orelse return null;
    return std.mem.span(v);
}
