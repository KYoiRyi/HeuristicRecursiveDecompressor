const std = @import("std");
const ioctx = @import("ioctx.zig");

pub fn eqlNoCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

pub fn endsWithNoCase(s: []const u8, suffix: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(s, suffix);
}

pub fn allocPrint(alloc: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return std.fmt.allocPrint(alloc, fmt, args);
}

pub fn basename(path: []const u8) []const u8 {
    return std.fs.path.basename(path);
}

pub fn dirname(path: []const u8) ?[]const u8 {
    return std.fs.path.dirname(path);
}

pub fn extname(path: []const u8) []const u8 {
    return std.fs.path.extension(path);
}

/// True when the file name ends with ".NNN" (3 decimal digits) — numeric split marker.
pub fn endsWithNumericSplit(name: []const u8) bool {
    if (name.len < 4 or name[name.len - 4] != '.') return false;
    for (name[name.len - 3 ..]) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

pub fn join(alloc: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return std.fs.path.join(alloc, parts);
}

/// Sanitize an archive-internal path for safe extraction (zip-slip guard):
/// strips drive letters, leading slashes, `.`/`..` segments.
pub fn sanitizeRel(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    const tokenizer = struct {
        remaining: []const u8,

        fn init(s: []const u8) @This() {
            return .{ .remaining = s };
        }
        fn next(self: *@This()) ?[]const u8 {
            var r = self.remaining;
            while (r.len > 0 and (r[0] == '/' or r[0] == '\\')) r = r[1..];
            if (r.len == 0) return null;
            var end: usize = 0;
            while (end < r.len and r[end] != '/' and r[end] != '\\') end += 1;
        const seg = r[0..end];
        self.remaining = r[end..];
        return seg;
    }
};
    var it = tokenizer.init(raw);
    var first = true;
    while (it.next()) |seg| {
    if (seg.len == 0) continue;
    if ((seg.len == 1 and seg[0] == '.') or (seg.len == 2 and seg[0] == '.' and seg[1] == '.')) continue;
        if (first and seg.len == 2 and seg[1] == ':') continue; // C:
        if (!first) try out.append(alloc, '/');
        try out.appendSlice(alloc, seg);
        first = false;
    }
    if (out.items.len == 0) try out.appendSlice(alloc, "_");
    return out.toOwnedSlice(alloc);
}

pub fn indexOfNoCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (haystack.len < needle.len) return null;
    var i: usize = 0;
    const last = haystack.len - needle.len;
    while (i <= last) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

pub const now_ms = std.time.milliTimestamp;

pub fn fmtBytes(buf: []u8, n: u64) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var v: f64 = @floatFromInt(n);
    var u: usize = 0;
    while (v >= 1024 and u < units.len - 1) : (u += 1) v /= 1024;
    if (u == 0) return std.fmt.bufPrint(buf, "{d} {s}", .{ n, units[u] }) catch buf[0..0];
    return std.fmt.bufPrint(buf, "{d:.1} {s}", .{ v, units[u] }) catch buf[0..0];
}

pub fn tokensFromText(alloc: std.mem.Allocator, text: []const u8, out: *std.ArrayList([]const u8)) !void {
    // Separators include fullwidth CJK punctuation (matched at byte level — the
    // individual UTF-8 bytes of（）：！etc. act as delimiters, which cleanly
    // splits ASCII tokens embedded in CJK text).
    var it = std.mem.tokenizeAny(u8, text, " \t\r\n,;\"'`<>[](){}|" ++
        "\xEF\xBC\x88\xEF\xBC\x89\xEF\xBC\x9A\xEF\xBC\x8C\xEF\xBC\x81\xEF\xBC\x9F" ++ // （）：！？
        "\xE3\x80\x90\xE3\x80\x91\xE3\x80\x82\xE3\x80\x81\xE3\x80\x8A\xE3\x80\x8B" ++ // 【】。、《》
        "\xEF\xBC\x8B\xEF\xBC\x9D\xE3\x80\x9C\xEF\xBD\x9E"); // ＋＝~～
    while (it.next()) |tok0| {
        var tok = tok0;
        while (tok.len > 0 and isTrimPunct(tok[tok.len - 1])) tok = tok[0 .. tok.len - 1];
        while (tok.len > 0 and isTrimPunct(tok[0])) tok = tok[1..];
        if (tok.len == 0 or tok.len > 128) continue;
        if (indexOfNoCase(tok, "password") != null and tok.len > 10) {
            if (std.mem.indexOfScalar(u8, tok, ':')) |ci| {
                const rest = tok[ci + 1 ..];
                if (rest.len > 0 and rest.len <= 128) try out.append(alloc, try alloc.dupe(u8, rest));
            }
            continue;
        }
        try out.append(alloc, try alloc.dupe(u8, tok));
    }
}

fn isTrimPunct(c: u8) bool {
    return switch (c) {
        '.', ',', ';', ':', '!', '?', '"', '\'', '`', ')', '(', '[', ']', '{', '}', '<', '>', '*', '#' => true,
        else => false,
    };
}

pub fn defaultTempRoot(alloc: std.mem.Allocator) ![]u8 {
    if (ioctx.getenvZ("HRD_TMP")) |v| return alloc.dupe(u8, v);
    if (ioctx.getenvZ("TMPDIR")) |v| return alloc.dupe(u8, v);
    if (ioctx.getenvZ("TEMP")) |v| return alloc.dupe(u8, v);
    if (ioctx.getenvZ("TMP")) |v| return alloc.dupe(u8, v);
    return alloc.dupe(u8, "/tmp");
}
