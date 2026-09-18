const std = @import("std");
const util = @import("util.zig");
const ioctx = @import("ioctx.zig");

pub const PasswordBook = struct {
    alloc: std.mem.Allocator,
    candidates: std.ArrayList([]const u8),
    seen: std.StringHashMap(void),
    db_path: ?[]const u8,
    used_count: u64 = 0,

    pub fn init(alloc: std.mem.Allocator) PasswordBook {
        return .{
            .alloc = alloc,
            .candidates = .empty,
            .seen = std.StringHashMap(void).init(alloc),
            .db_path = null,
        };
    }

    pub fn deinit(self: *PasswordBook) void {
        for (self.candidates.items) |c| self.alloc.free(@constCast(c));
        self.candidates.deinit(self.alloc);
        self.seen.deinit();
        if (self.db_path) |p| self.alloc.free(@constCast(p));
    }

    fn push(self: *PasswordBook, pw: []const u8) !void {
        if (pw.len == 0 or pw.len > 256) return;
        if (self.seen.contains(pw)) return;
        const owned = try self.alloc.dupe(u8, pw);
        errdefer self.alloc.free(owned);
        try self.seen.put(owned, {});
        try self.candidates.append(self.alloc, owned);
    }

    pub fn loadDefaultDb(self: *PasswordBook, extra_db: ?[]const u8) !void {
        const io = ioctx.io();
        const default_name = "hrd_passwords.txt";
        const primary = extra_db orelse default_name;
        if (ioctx.cwd().readFileAlloc(io, primary, self.alloc, @enumFromInt(1 << 20))) |data| {
            defer self.alloc.free(data);
            var it = std.mem.tokenizeAny(u8, data, "\r\n");
            while (it.next()) |line| try self.push(line);
        } else |_| {}
        self.db_path = try self.alloc.dupe(u8, primary);
        if (extra_db != null) {
            if (ioctx.cwd().readFileAlloc(io, default_name, self.alloc, @enumFromInt(1 << 20))) |data| {
                defer self.alloc.free(data);
                var it = std.mem.tokenizeAny(u8, data, "\r\n");
                while (it.next()) |line| try self.push(line);
            } else |_| {}
        }
        for ([_][]const u8{ "123456", "password", "12345678", "123456789", "12345", "qwerty", "abc123", "111111", "000000", "iloveyou", "acgs", "绮梦", "qym" }) |p| try self.push(p);
    }

    pub fn gatherContext(self: *PasswordBook, archive_path: []const u8) !void {
        const io = ioctx.io();
        const dir_path = util.dirname(archive_path) orelse ".";
        var dir = ioctx.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return;
        defer dir.close(io);
        var it = dir.iterate();
        while (it.next(io) catch null) |ent| {
            if (ent.kind != .file) continue;
            const n = ent.name;
            const looks_hint = util.indexOfNoCase(n, "pass") != null or
                util.indexOfNoCase(n, "readme") != null or
                util.indexOfNoCase(n, "\xe5\xaf\x86\xe7\xa0\x81") != null or // 密码
                util.indexOfNoCase(n, "\xe5\x8f\xa3\xe4\xbb\xa4") != null or // 口令
                util.indexOfNoCase(n, "\xe8\xaf\xb4\xe6\x98\x8e") != null or // 说明
                util.indexOfNoCase(n, "key") != null or
                util.endsWithNoCase(n, ".nfo") or
                util.endsWithNoCase(n, ".txt");
            if (!looks_hint) continue;
            const data = dir.readFileAlloc(io, n, self.alloc, @enumFromInt(1 << 20)) catch continue;
            defer self.alloc.free(data);
            try util.tokensFromText(self.alloc, data, &self.candidates);
        }
        self.dedupeInPlace();
    }

    fn dedupeInPlace(self: *PasswordBook) void {
        // Local seen: self.seen already contains every legit candidate pushed via
        // push(), so checking against it would delete all of them.
        var local_seen = std.StringHashMap(void).init(self.alloc);
        defer local_seen.deinit();
        var i: usize = 0;
        while (i < self.candidates.items.len) {
            const c = self.candidates.items[i];
            if (c.len == 0 or c.len > 256) {
                self.alloc.free(@constCast(c));
                _ = self.candidates.orderedRemove(i);
                continue;
            }
            if (local_seen.contains(c)) {
                self.alloc.free(@constCast(c));
                _ = self.candidates.orderedRemove(i);
                continue;
            }
            local_seen.put(c, {}) catch {};
            i += 1;
        }
    }

    pub fn learn(self: *PasswordBook, pw: []const u8) !void {
        if (self.seen.contains(pw)) return;
        try self.push(pw);
        const io = ioctx.io();
        const path = self.db_path orelse "hrd_passwords.txt";
        var f = ioctx.cwd().createFile(io, path, .{ .truncate = false }) catch return;
        defer f.close(io);
        const sz = (f.stat(io) catch null) orelse return;
        var buf: [300]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "{s}\n", .{pw}) catch return;
        f.writePositionalAll(io, line, sz.size) catch return;
        self.used_count += 1;
    }
};
