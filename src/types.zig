const std = @import("std");

pub const Format = enum(u8) {
    none = 0,
    zip = 1,
    rar4 = 2,
    rar5 = 3,
    sevenz = 4,
    gz = 5,
    bz2 = 6,
    xz = 7,
    tar = 8,
    cab = 9,

    pub fn name(self: Format) []const u8 {
        return @tagName(self);
    }
};

pub const HrdError = error{
    InvalidArg,
    Io,
    Unsupported,
    Encrypted,
    Password,
    Bomb,
    Depth,
    Archive,
    NoMem,
    Cancelled,
    Internal,
};

pub const Options = struct {
    max_depth: u32 = 8,
    max_ratio: u32 = 100, // 0 disables
    max_total_bytes: u64 = 32 << 30, // 0 disables
    flatten: bool = false,
    overwrite: bool = false,
    interactive: bool = true,
    password_db: ?[]const u8 = null,
    temp_dir: ?[]const u8 = null,
};

pub const Event = enum(u8) {
    grouped = 1,
    sniffed = 2,
    probe = 3,
    extracting = 4,
    extracted = 5,
    delivered = 6,
    kept = 7,
    circuit = 8,
};

pub const EventInfo = struct {
    event: Event,
    path: []const u8,
    depth: u32,
    fmt: Format,
    aux: u64,
};

pub const Callbacks = struct {
    /// Return password into provided buffer, or null to cancel/skip.
    need_password: ?*const fn (archive_path: []const u8, buf: []u8, user: ?*anyopaque) ?[]const u8 = null,
    event: ?*const fn (info: EventInfo, user: ?*anyopaque) void = null,
    user: ?*anyopaque = null,
};

pub const Carrier = struct {
    /// On-disk path to the byte stream that holds the archive (first volume).
    path: []const u8,
    /// Byte offset inside `path` where the archive begins (0 for plain archives).
    offset: u64,
    /// Detected archive format.
    fmt: Format,
    /// True when the carrier file is not itself an archive at offset 0
    /// (e.g. mp4/png with an archive appended). The extractor materializes
    /// the sliced bytes to a temp file before opening.
    disguised: bool,
    /// Non-first volumes belonging to the same logical archive.
    deps: [][]const u8,
    /// Display name (original input path of the first volume).
    display: []const u8,
};

pub const Report = struct {
    processed: u64 = 0,
    archives: u64 = 0,
    kept: u64 = 0,
    delivered_files: u64 = 0,
    delivered_bytes: u64 = 0,
    errors: u64 = 0,
    passwords_used: u64 = 0,
};
