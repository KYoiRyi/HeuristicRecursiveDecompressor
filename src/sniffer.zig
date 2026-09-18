const std = @import("std");
const types = @import("types.zig");
const util = @import("util.zig");
const ioctx = @import("ioctx.zig");

const Format = types.Format;

pub const SniffResult = struct {
    fmt: Format,
    offset: u64,
    disguised: bool,
};

// ── Magic signatures (sorted longest-first for correct matching) ─────────
const SIG_RAR5 = [_]u8{ 'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00 };
const SIG_RAR4 = [_]u8{ 'R', 'a', 'r', '!', 0x1A, 0x07, 0x00 };
const SIG_7Z   = [_]u8{ '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };
const SIG_XZ   = [_]u8{ 0xFD, '7', 'z', 'X', 'Z', 0x00 };
const SIG_ZIP  = [_]u8{ 'P', 'K', 3, 4 };
const SIG_CAB  = [_]u8{ 'M', 'S', 'C', 'F' };
const SIG_BZ2  = [_]u8{ 'B', 'Z', 'h' };
const SIG_GZ   = [_]u8{ 0x1F, 0x8B };
const SIG_EOCD = [_]u8{ 'P', 'K', 5, 6 };

const ALL_SIGS = [_]struct { sig: *const [8]u8, len: u8, fmt: Format }{
    .{ .sig = &[_:0]u8{ 'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00 }, .len = 8, .fmt = .rar5 },
    .{ .sig = &[_:0]u8{ 'R', 'a', 'r', '!', 0x1A, 0x07, 0x00, 0 }, .len = 7, .fmt = .rar4 },
    .{ .sig = &[_:0]u8{ '7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0, 0 }, .len = 6, .fmt = .sevenz },
    .{ .sig = &[_:0]u8{ 0xFD, '7', 'z', 'X', 'Z', 0x00, 0, 0 }, .len = 6, .fmt = .xz },
    .{ .sig = &[_:0]u8{ 'P', 'K', 3, 4, 0, 0, 0, 0 }, .len = 4, .fmt = .zip },
    .{ .sig = &[_:0]u8{ 'M', 'S', 'C', 'F', 0, 0, 0, 0 }, .len = 4, .fmt = .cab },
    .{ .sig = &[_:0]u8{ 'B', 'Z', 'h', 0, 0, 0, 0, 0 }, .len = 3, .fmt = .bz2 },
    .{ .sig = &[_:0]u8{ 0x1F, 0x8B, 0, 0, 0, 0, 0, 0 }, .len = 2, .fmt = .gz },
};

// ── Fast extension pre-filter ──────────────────────────────────────────────
// If extension is a well-known non-archive type, skip the entire scan.
const KNOWN_NON_ARCHIVE = [_][]const u8{
    ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
    ".md", ".rst", ".html", ".css", ".js", ".ts", ".py", ".rs", ".go", ".c",
    ".cpp", ".h", ".hpp", ".java", ".rb", ".sh", ".bat", ".ps1", ".sql",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".opus",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".lib",
    ".iso", ".img", ".vmdk", ".vdi", ".qcow2",
    ".sqlite", ".db",
};

fn isKnownNonArchive(ext: []const u8) bool {
    for (KNOWN_NON_ARCHIVE) |ne| {
        if (util.eqlNoCase(ext, ne)) return true;
    }
    return false;
}

/// Match magic at exact position in buffer.
inline fn matchMagic(buf: []const u8, pos: usize) ?Format {
    for (ALL_SIGS) |s| {
        if (pos + s.len <= buf.len) {
            if (std.mem.eql(u8, buf[pos .. pos + s.len], s.sig[0..s.len])) return s.fmt;
        }
    }
    return null;
}

inline fn matchTar(buf: []const u8, pos: usize) bool {
    if (pos + 262 > buf.len) return false;
    return std.mem.eql(u8, buf[pos + 257 .. pos + 262], "ustar");
}

/// Main sniff entry point.
/// Priority: magic@0 → EOCD tail → skip-scan (non-archive ext fast-path)
pub fn sniffFile(alloc: std.mem.Allocator, path: []const u8) !?SniffResult {
    const io = ioctx.io();
    var f = try ioctx.cwd().openFile(io, path, .{});
    defer f.close(io);
    const size = (try f.stat(io)).size;
    if (size == 0) return null;

    // ── Fast path: check extension to skip non-archive files entirely ──────
    const ext = util.extname(path);
    if (ext.len > 0 and isKnownNonArchive(ext)) return null;

    // ── Read head (8 KiB) ─────────────────────────────────────────────────
    var head_buf: [8192]u8 = undefined;
    const head_n = f.readPositional(io, &.{&head_buf}, 0) catch 0;
    const head = head_buf[0..head_n];

    // ── Check magic at offset 0 ───────────────────────────────────────────
    if (head.len >= 2) {
        if (matchMagic(head, 0)) |fmt| {
            return .{ .fmt = fmt, .offset = 0, .disguised = false };
        }
        if (matchTar(head, 0)) {
            return .{ .fmt = .tar, .offset = 0, .disguised = false };
        }
    }

    // ── EOCD tail scan (ZIP self-locating for 图种 / self-extracting) ─────
    // Only for files > 22 bytes. EOCD max comment = 65535.
    if (size >= 22) {
        const tail_sz: u64 = @min(size, (1 << 16) + 22);
        var stack_buf: [65558]u8 = undefined; // 64KB + 22 on stack
        const tail: []u8 = if (tail_sz <= stack_buf.len)
            stack_buf[0..@intCast(tail_sz)]
        else
            try alloc.alloc(u8, @intCast(tail_sz));
        defer if (tail_sz > stack_buf.len) alloc.free(tail);
        _ = f.readPositional(io, &.{tail}, size - tail_sz) catch 0;

        var pos: isize = @intCast(tail.len - 22);
        while (pos >= 0) : (pos -= 1) {
            const ui: usize = @intCast(pos);
            if (!std.mem.eql(u8, tail[ui .. ui + 4], &SIG_EOCD)) continue;
            const comment_len = std.mem.readInt(u16, tail[ui + 20 ..][0..2], .little);
            if (ui + 22 + @as(usize, comment_len) != tail.len) continue;
            const cd_size = std.mem.readInt(u32, tail[ui + 12 ..][0..4], .little);
            const cd_off = std.mem.readInt(u32, tail[ui + 16 ..][0..4], .little);
            const eocd_abs = size - tail_sz + ui;
            if (@as(u64, cd_off) + cd_size > eocd_abs) continue;
            const arc_start: u64 = eocd_abs - cd_size - cd_off;
            // Verify the local file header at arc_start
            if (arc_start < size) {
                var sig: [4]u8 = undefined;
                _ = f.readPositional(io, &.{&sig}, arc_start) catch 0;
                if (std.mem.eql(u8, &sig, &SIG_ZIP)) {
                    return .{ .fmt = .zip, .offset = arc_start, .disguised = arc_start != 0 };
                }
            }
            if (arc_start == eocd_abs) {
                return .{ .fmt = .zip, .offset = arc_start, .disguised = arc_start != 0 };
            }
        }
    }

    // ── Sliding window scan (for disguised files) ─────────────────────────
    // Use 4MB chunks with 8-byte overlap for signature boundary crossing.
    const CHUNK: usize = 4 << 20;
    const scan_limit: u64 = @min(size, 64 << 20); // 64MB max scan
    var pos: u64 = 0;
    var buf = try alloc.alloc(u8, CHUNK + 8);
    defer alloc.free(buf);
    var carry: usize = 0;

    while (pos < scan_limit) {
        const want: usize = @intCast(@min(@as(u64, CHUNK), scan_limit - pos));
        const n = f.readPositional(io, &.{buf[carry .. carry + want]}, pos) catch break;
        if (n == 0) break;
        const valid = buf[0 .. carry + n];

        // Scan with 2-byte stride minimum (GZ is 2 bytes)
        var i: usize = 0;
        while (i + 2 <= valid.len) : (i += 1) {
            if (matchMagic(valid, i)) |fmt| {
                const abs = pos + i - carry;
                return .{ .fmt = fmt, .offset = abs, .disguised = abs != 0 };
            }
            if (matchTar(valid, i)) {
                const abs = pos + i - carry;
                return .{ .fmt = .tar, .offset = abs, .disguised = abs != 0 };
            }
        }
        carry = @min(8, valid.len);
        std.mem.copyForwards(u8, buf[0..carry], valid[valid.len - carry ..]);
        pos += n;
    }
    return null;
}

/// Materialize bytes [offset, EOF) of src into dst_dir/tag. Caller owns result.
pub fn sliceToFile(alloc: std.mem.Allocator, src_path: []const u8, offset: u64, dst_dir: []const u8, tag: []const u8) ![]u8 {
    const io = ioctx.io();
    var src = try ioctx.cwd().openFile(io, src_path, .{});
    defer src.close(io);
    try ioctx.cwd().createDirPath(io, dst_dir);
    const name = try util.join(alloc, &.{ dst_dir, tag });
    errdefer alloc.free(name);
    var dst = try ioctx.cwd().createFile(io, name, .{ .truncate = true });
    defer dst.close(io);
    var buf: [1 << 16]u8 = undefined;
    var pos = offset;
    while (true) {
        const n = try src.readPositional(io, &.{&buf}, pos);
        if (n == 0) break;
        try dst.writePositionalAll(io, buf[0..n], pos - offset);
        pos += n;
    }
    return name;
}
