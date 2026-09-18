const std = @import("std");
const ioctx = @import("ioctx.zig");
const types = @import("types.zig");

test "ioctx: init/deinit" {
    const alloc = std.testing.allocator;
    ioctx.init(alloc);
    defer ioctx.deinit();
    _ = ioctx.io();
    _ = ioctx.cwd();
}

test "ioctx: file round-trip" {
    const alloc = std.testing.allocator;
    ioctx.init(alloc);
    defer ioctx.deinit();
    const io = ioctx.io();
    const cwd = ioctx.cwd();
    try cwd.createDirPath(io, "_hrd_test_io");
    var f = try cwd.createFile(io, "_hrd_test_io/test.txt", .{ .truncate = true });
    try f.writePositionalAll(io, "hello world", 0);
    f.close(io);
    const data = try cwd.readFileAlloc(io, "_hrd_test_io/test.txt", alloc, @enumFromInt(1 << 20));
    defer alloc.free(data);
    try std.testing.expectEqualStrings("hello world", data);
    try cwd.deleteTree(io, "_hrd_test_io");
}

test "sniffer: zip magic at offset 0" {
    const alloc = std.testing.allocator;
    ioctx.init(alloc);
    defer ioctx.deinit();
    const io = ioctx.io();
    const cwd = ioctx.cwd();
    // Write a minimal valid ZIP local header
    var header: [4]u8 = undefined;
    header[0] = 'P';
    header[1] = 'K';
    header[2] = 3;
    header[3] = 4;
    try cwd.createDirPath(io, "_hrd_test_sniff");
    var f = try cwd.createFile(io, "_hrd_test_sniff/test.zip", .{ .truncate = true });
    try f.writePositionalAll(io, &header, 0);
    f.close(io);
    const sniffer = @import("sniffer.zig");
    const res = try sniffer.sniffFile(alloc, "_hrd_test_sniff/test.zip");
    try std.testing.expect(res != null);
    if (res) |r| {
        try std.testing.expectEqual(types.Format.zip, r.fmt);
        try std.testing.expectEqual(@as(u64, 0), r.offset);
        try std.testing.expectEqual(false, r.disguised);
    }
    try cwd.deleteTree(io, "_hrd_test_sniff");
}

test "sniffer: non-archive returns null" {
    const alloc = std.testing.allocator;
    ioctx.init(alloc);
    defer ioctx.deinit();
    const io = ioctx.io();
    const cwd = ioctx.cwd();
    try cwd.createDirPath(io, "_hrd_test_sniff2");
    var f = try cwd.createFile(io, "_hrd_test_sniff2/readme.txt", .{ .truncate = true });
    try f.writePositionalAll(io, "not an archive", 0);
    f.close(io);
    const sniffer = @import("sniffer.zig");
    const res = try sniffer.sniffFile(alloc, "_hrd_test_sniff2/readme.txt");
    try std.testing.expect(res == null);
    try cwd.deleteTree(io, "_hrd_test_sniff2");
}
