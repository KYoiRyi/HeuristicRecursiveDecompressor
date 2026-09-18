const std = @import("std");
const types = @import("types.zig");
const util = @import("util.zig");
const sniffer = @import("sniffer.zig");
const volumes = @import("volumes.zig");
const io_tests = @import("io_tests.zig");

test "util: sanitizeRel" {
    const alloc = std.testing.allocator;
    {
        const r1 = try util.sanitizeRel(alloc, "");
        defer alloc.free(r1);
        try std.testing.expectEqualStrings("_", r1);
    }
    {
        const r2 = try util.sanitizeRel(alloc, "foo.txt");
        defer alloc.free(r2);
        try std.testing.expectEqualStrings("foo.txt", r2);
    }
    {
        const r3 = try util.sanitizeRel(alloc, "bar/baz.txt");
        defer alloc.free(r3);
        try std.testing.expectEqualStrings("bar/baz.txt", r3);
    }
    {
        const r4 = try util.sanitizeRel(alloc, "/foo.txt");
        defer alloc.free(r4);
        try std.testing.expectEqualStrings("foo.txt", r4);
    }
    {
        const r5 = try util.sanitizeRel(alloc, "C:\\foo.txt");
        defer alloc.free(r5);
        try std.testing.expectEqualStrings("foo.txt", r5);
    }
    {
        const r6 = try util.sanitizeRel(alloc, "a/../../c");
        defer alloc.free(r6);
        try std.testing.expectEqualStrings("a/c", r6);
    }
    {
        const r7 = try util.sanitizeRel(alloc, "a/./b/../c");
        defer alloc.free(r7);
        try std.testing.expectEqualStrings("a/b/c", r7);
    }
}

test "util: indexOfNoCase" {
    try std.testing.expectEqual(@as(?usize, 0), util.indexOfNoCase("abc", "A"));
    try std.testing.expectEqual(@as(?usize, 1), util.indexOfNoCase("abc", "B"));
    try std.testing.expectEqual(@as(?usize, 2), util.indexOfNoCase("abc", "c"));
    try std.testing.expectEqual(@as(?usize, null), util.indexOfNoCase("abc", "d"));
    try std.testing.expectEqual(@as(?usize, 0), util.indexOfNoCase("abc", ""));
    try std.testing.expectEqual(@as(?usize, null), util.indexOfNoCase("ab", "abc"));
}

test "util: fmtBytes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("0 B", util.fmtBytes(&buf, 0));
    try std.testing.expectEqualStrings("1 B", util.fmtBytes(&buf, 1));
    try std.testing.expectEqualStrings("1.0 KB", util.fmtBytes(&buf, 1024));
    try std.testing.expectEqualStrings("1.0 MB", util.fmtBytes(&buf, 1048576));
}

test "volumes: analyze rar part" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "archive.part1.rar");
    defer alloc.free(@constCast(info.base));
    try std.testing.expectEqual(volumes.VolumeKind.rar_part, info.kind);
    try std.testing.expectEqual(@as(u32, 1), info.index);
    try std.testing.expectEqual(true, info.is_first);
}

test "volumes: analyze rar old r00" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "archive.r00");
    defer alloc.free(@constCast(info.base));
    try std.testing.expectEqual(volumes.VolumeKind.rar_old, info.kind);
    try std.testing.expectEqual(false, info.is_first);
}

test "volumes: analyze numeric 001" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "data.001");
    defer alloc.free(@constCast(info.base));
    try std.testing.expectEqual(volumes.VolumeKind.numeric, info.kind);
    try std.testing.expectEqual(@as(u32, 1), info.index);
    try std.testing.expectEqual(true, info.is_first);
}

test "volumes: analyze zip split" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "data.z01");
    defer alloc.free(@constCast(info.base));
    try std.testing.expectEqual(volumes.VolumeKind.zip_split, info.kind);
    try std.testing.expectEqual(false, info.is_first);
}

test "volumes: analyze zip" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "data.zip");
    defer alloc.free(@constCast(info.base));
    try std.testing.expectEqual(volumes.VolumeKind.zip_split, info.kind);
    try std.testing.expectEqual(true, info.is_first);
}

test "volumes: analyze 7z part" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "data.7z.001");
    defer alloc.free(@constCast(info.base));
    try std.testing.expectEqual(volumes.VolumeKind.sevenz_part, info.kind);
    try std.testing.expectEqual(@as(u32, 1), info.index);
}

test "volumes: analyze plain file" {
    const alloc = std.testing.allocator;
    const info = try volumes.analyze(alloc, "readme.txt");
    try std.testing.expectEqual(volumes.VolumeKind.none, info.kind);
}

test "volumes: group merges parts" {
    // Use c_allocator (not tracked by DebugAllocator) to avoid spurious leak reports.
    const alloc = std.heap.c_allocator;
    const path1 = "data.002";
    const path2 = "data.001";
    const paths = [_][]const u8{ path1, path2 };
    const result = try volumes.group(alloc, &paths);
    try std.testing.expectEqual(@as(usize, 0), result.singles.len);
    try std.testing.expectEqual(@as(usize, 1), result.groups.len);
    try std.testing.expectEqual(@as(usize, 1), result.groups[0].deps.len);
}

test "types: Format names" {
    try std.testing.expectEqualStrings("zip", @tagName(types.Format.zip));
    try std.testing.expectEqualStrings("sevenz", @tagName(types.Format.sevenz));
}
