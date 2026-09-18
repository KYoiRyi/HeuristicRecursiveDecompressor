const std = @import("std");
const util = @import("util.zig");

pub const VolumeKind = enum { none, rar_part, rar_old, numeric, zip_split, sevenz_part };

pub const VolumeInfo = struct {
    kind: VolumeKind = .none,
    base: []const u8 = "",
    index: u32 = 0,
    is_first: bool = false,
};

fn makeBase(alloc: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    const printed = try util.allocPrint(alloc, fmt, args);
    defer alloc.free(printed);
    // Lowercase in-place on the newly-allocated copy; no extra dupe needed.
    const out = try alloc.alloc(u8, printed.len);
    for (printed, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

pub fn analyze(alloc: std.mem.Allocator, path: []const u8) !VolumeInfo {
    const name = util.basename(path);
    const dir = util.dirname(path) orelse ".";
    const ext = util.extname(name);
    const stem = if (ext.len > 0) name[0 .. name.len - ext.len] else name;

    var info = VolumeInfo{};
    errdefer if (info.base.len > 0) alloc.free(@constCast(info.base));

    if (util.endsWithNoCase(ext, ".rar")) {
        if (util.indexOfNoCase(stem, ".part")) |pi| {
            const prefix = stem[0..pi];
            const digits = stem[pi + 5 ..];
            if (digits.len > 0 and std.ascii.isDigit(digits[0])) {
                if (std.fmt.parseInt(u32, digits, 10)) |idx| {
                    info.kind = .rar_part;
                    info.index = idx;
                    info.is_first = (idx == 1);
                    info.base = try makeBase(alloc, "{s}/{s}|part.rar", .{ dir, prefix });
                    return info;
                } else |_| {}
            }
        }
        info.kind = .rar_old;
        info.index = 0;
        info.is_first = true;
        info.base = try makeBase(alloc, "{s}/{s}|rxx", .{ dir, stem });
        return info;
    }
    if (ext.len == 4 and (ext[1] == 'r' or ext[1] == 'R') and std.ascii.isDigit(ext[2]) and std.ascii.isDigit(ext[3])) {
        info.kind = .rar_old;
        info.index = std.fmt.parseInt(u32, ext[2..], 10) catch 0;
        info.is_first = false;
        info.base = try makeBase(alloc, "{s}/{s}|rxx", .{ dir, stem });
        return info;
    }
    // 7z split: name.7z.001 — check BEFORE generic numeric
    if (util.endsWithNoCase(stem, ".7z") and ext.len == 4 and std.ascii.isDigit(ext[1])) {
        const idx = std.fmt.parseInt(u32, ext[1..], 10) catch 0;
        info.kind = .sevenz_part;
        info.index = idx;
        info.is_first = (idx == 1);
        const base_stem = stem[0 .. stem.len - 3];
        info.base = try makeBase(alloc, "{s}/{s}|7znnn", .{ dir, base_stem });
        return info;
    }
    if (ext.len == 4 and std.ascii.isDigit(ext[1]) and std.ascii.isDigit(ext[2]) and std.ascii.isDigit(ext[3])) {
        // Generic numeric split (e.g. .001, .002)
        const idx = std.fmt.parseInt(u32, ext[1..], 10) catch 0;
        info.kind = .numeric;
        info.index = idx;
        info.is_first = (idx == 1);
        info.base = try makeBase(alloc, "{s}/{s}|nnn", .{ dir, stem });
        return info;
    }
    if (ext.len == 4 and (ext[1] == 'z' or ext[1] == 'Z') and std.ascii.isDigit(ext[2]) and std.ascii.isDigit(ext[3])) {
        info.kind = .zip_split;
        info.index = std.fmt.parseInt(u32, ext[2..], 10) catch 0;
        info.is_first = false;
        info.base = try makeBase(alloc, "{s}/{s}|zxx", .{ dir, stem });
        return info;
    }
    if (util.endsWithNoCase(ext, ".zip")) {
        info.kind = .zip_split;
        info.index = 999;
        info.is_first = true;
        info.base = try makeBase(alloc, "{s}/{s}|zxx", .{ dir, stem });
        return info;
    }
    return info;
}

pub const Group = struct {
    entry: []const u8,
    deps: [][]const u8,
    display: []const u8,
    multi: bool,
};

pub const GroupResult = struct {
    groups: []Group,
    singles: [][]const u8,
};

const Item = struct { path: []const u8, info: VolumeInfo };

pub fn group(alloc: std.mem.Allocator, paths: []const []const u8) !GroupResult {
    const MapCtx = struct {
        pub fn hash(_: @This(), k: []const u8) u64 {
            return std.hash.Wyhash.hash(0, k);
        }
        pub fn eql(_: @This(), a: []const u8, b: []const u8) bool {
            return std.mem.eql(u8, a, b);
        }
    };
    var map = std.HashMap([]const u8, *std.ArrayList(Item), MapCtx, 75).init(alloc);
    defer {
        var it = map.valueIterator();
        while (it.next()) |v| {
            v.*.deinit(alloc);
            alloc.destroy(v.*);
        }
        var kit = map.keyIterator();
        while (kit.next()) |k| alloc.free(k.*);
        map.deinit();
    }
    var singles = std.ArrayList([]const u8).empty;

    for (paths) |p| {
        const info = try analyze(alloc, p);
        if (info.kind == .none) {
            try singles.append(alloc, p);
            continue;
        }
        const gop = try map.getOrPut(info.base);
        if (!gop.found_existing) {
            const lst = try alloc.create(std.ArrayList(Item));
            lst.* = .empty;
            gop.value_ptr.* = lst;
        } else {
            alloc.free(info.base); // key already owns the first copy
        }
        try gop.value_ptr.*.append(alloc, .{ .path = p, .info = info });
    }

    var groups = std.ArrayList(Group).empty;
    var it = map.iterator();
    while (it.next()) |e| {
        const items = e.value_ptr.*.items;
        std.mem.sort(Item, items, {}, struct {
            fn lt(_: void, a: Item, b: Item) bool {
                return a.info.index < b.info.index;
            }
        }.lt);
        var entry_idx: usize = 0;
        for (items, 0..) |itm, i| {
            if (itm.info.is_first) {
                entry_idx = i;
                break;
            }
        }
        const multi = items.len > 1;
        var deps = std.ArrayList([]const u8).empty;
        for (items, 0..) |itm, i| {
            if (i != entry_idx) try deps.append(alloc, itm.path);
        }
        try groups.append(alloc, .{
            .entry = items[entry_idx].path,
            .deps = try deps.toOwnedSlice(alloc),
            .display = items[entry_idx].path,
            .multi = multi,
        });
    }
    return .{ .groups = try groups.toOwnedSlice(alloc), .singles = try singles.toOwnedSlice(alloc) };
}
