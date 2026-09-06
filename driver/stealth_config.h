#pragma once
// Shared build-time stealth configuration for WhosWho.
//
// Both the kernel driver (WhosWho) and the user-mode client (driver/comm.h)
// include this header so the device name, symlink, and IOCTL function base
// stay in sync for a given build. Rotating AIDA_STEALTH_SEED per release
// changes all three, defeating static blacklists keyed on the historical
// fixed values (\Device\WhosWho, \DosDevices\Global\WhosWho, IOCTL base 0x800).
//
// This is OPSEC for the *target* not detecting the analysis driver; it is not
// self-protection/anti-tamper of AiDA's own binary (which AGENTS.md forbids).

#include <cstdint>

#ifndef AIDA_STEALTH_SEED
#define AIDA_STEALTH_SEED "AiDA-WhosWho-2026-08-31"
#endif

namespace aida_stealth {

constexpr std::uint64_t fnv1a64(const char* text) {
    std::uint64_t h = 14695981039346656037ull;
    while (*text) {
        h ^= static_cast<unsigned char>(*text);
        h *= 1099511628211ull;
        ++text;
    }
    return h;
}

constexpr std::uint64_t kSeedHash = fnv1a64(AIDA_STEALTH_SEED);

// IOCTL function base derived from the seed. Kept in 0x100..0x7FF so that
// base + max_offset (62) never overflows the 12-bit function field of the
// CTL_CODE layout (0x00220000 | (function << 2)).
constexpr std::uint32_t kIoctlFunctionBase =
    0x100u + static_cast<std::uint32_t>((kSeedHash >> 32) & 0x6FFu);

// Device/symlink leaf name: 12 uppercase hex chars from the seed hash.
constexpr char kDeviceLeafHex[13] = {
    "0123456789ABCDEF"[(kSeedHash >> 60) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 56) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 52) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 48) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 44) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 40) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 36) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 32) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 28) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 24) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 20) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 16) & 0xF],
    '\0'
};

// SplitMix64 finalizer used for the challenge/response handshake. Identical
// on both sides so the client can reproduce the driver's expected response.
__forceinline std::uint64_t mix64(std::uint64_t x) {
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}

// Expected authentication response for a given boot nonce + client PID.
__forceinline std::uint64_t auth_response(std::uint64_t boot_nonce, std::uint64_t pid) {
    return mix64(kSeedHash ^ boot_nonce ^ pid);
}

} // namespace aida_stealth
