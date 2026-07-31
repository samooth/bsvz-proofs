const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Thread-safe, process-wide ChaCha20 CSPRNG seeded from the OS.
var csprng: std.Random.DefaultCsprng = undefined;
var seeded: bool = false;
var lock: std.atomic.Mutex = .unlocked;

/// Test-only hook: inject a deterministic `std.Random` (e.g. `Xoshiro256`)
/// used for reproducible proofs in tests. Passing `null` restores the CSPRNG.
/// Not thread-safe; intended for single-threaded tests only.
var test_rng: ?*std.Random = null;

pub fn setRandomForTesting(rng: ?*std.Random) void {
    test_rng = rng;
}

/// Fill `out` with cryptographically secure random bytes.
pub fn bytes(out: []u8) void {
    if (test_rng) |rng| {
        std.Random.bytes(rng.*, out);
        return;
    }
    lockBytes();
    defer unlockBytes();
    if (!seeded) {
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        osEntropy(&seed);
        csprng = std.Random.DefaultCsprng.init(seed);
        seeded = true;
    }
    csprng.fill(out);
}

fn lockBytes() void {
    while (!lock.tryLock()) {
        std.atomic.spinLoopHint();
    }
}

fn unlockBytes() void {
    lock.unlock();
}

fn osEntropy(out: []u8) void {
    if (builtin.link_libc and @TypeOf(posix.system.arc4random_buf) != void) {
        posix.system.arc4random_buf(out.ptr, out.len);
        return;
    }
    if (@TypeOf(posix.system.getrandom) != void) {
        getrandomLoop(out);
        return;
    }
    if (builtin.os.tag == .linux) {
        var i: usize = 0;
        while (i < out.len) {
            const rc = std.os.linux.getrandom(out[i..].ptr, out[i..].len, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => i += @intCast(rc),
                .INTR => {},
                else => @panic("secure entropy unavailable"),
            }
        }
        return;
    }
    if (builtin.os.tag == .windows) {
        @panic("secure entropy unavailable: no Windows getrandom binding");
    }
    const file = std.fs.openFileAbsolute("/dev/urandom", .{}) catch @panic("secure entropy unavailable");
    defer file.close();
    file.reader().readNoEof(out) catch @panic("secure entropy unavailable");
}

fn getrandomLoop(out: []u8) void {
    var i: usize = 0;
    while (i < out.len) {
        const rc = posix.system.getrandom(out[i..].ptr, out[i..].len, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => i += @intCast(rc),
            .INTR => {},
            else => @panic("secure entropy unavailable"),
        }
    }
}
