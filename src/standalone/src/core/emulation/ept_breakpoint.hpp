#pragma once
// EPT (Extended Page Tables) breakpoint scaffold for AiDA.
//
// Hardware debug registers (dr0-dr7) and software int3 are both trivially
// detected by EAC/BattlEye, which poll their own threads' debug registers and
// scan for 0xCC. The stealth-correct answer for live RE is an EPT-based
// breakpoint: mark the target page non-present (or non-executable) in the
// guest's EPT, let the access/execute fault trap to the hypervisor, emulate
// or single-step, then restore.
//
// This header defines the *interface* and the page-fault classification logic
// that a type-2 hypervisor (Bluepill/CR3Swapper-class) consumes. It does not
// implement the VMX root itself — that lives in the operator's hypervisor
// (see the Ophion fork). It is intentionally self-contained and dependency-
// free so it can be shared between the usermode tooling and the VMM.

#include <cstdint>
#include <cstring>

namespace aida_ept {

// Breakpoint types.
enum class bp_type_t : std::uint32_t {
    execute = 0, // trap on instruction fetch
    read    = 1, // trap on data read
    write   = 2, // trap on data write
    rw      = 3, // trap on read or write
};

// A single EPT breakpoint.
struct ept_breakpoint_t {
    std::uint64_t guest_physical = 0; // guest physical address of the page
    std::uint64_t guest_virtual  = 0; // guest virtual address (for reporting)
    bp_type_t     type           = bp_type_t::execute;
    std::uint32_t slot           = 0; // index into the breakpoint table
    bool          active         = false;
    bool          single_step    = false; // currently in single-step emulation
};

// Maximum number of concurrent EPT breakpoints.
constexpr std::uint32_t kMaxBreakpoints = 64;

// EPT entry flags (Intel SDM Vol 3C, Table 28-6).
constexpr std::uint64_t kEptRead        = 1ull << 0;
constexpr std::uint64_t kEptWrite       = 1ull << 1;
constexpr std::uint64_t kEptExecute     = 1ull << 2;
constexpr std::uint64_t kEptMemoryType  = 0x7ull << 3;
constexpr std::uint64_t kEptIgnorePat   = 1ull << 6;
constexpr std::uint64_t kEptPresent     = kEptRead | kEptWrite | kEptExecute;

// VM-exit qualification for EPT violations (Intel SDM Vol 3C, 28.2.1).
constexpr std::uint64_t kEptViolationRead    = 1ull << 0;
constexpr std::uint64_t kEptViolationWrite   = 1ull << 1;
constexpr std::uint64_t kEptViolationExecute = 1ull << 2;
constexpr std::uint64_t kEptViolationEptEntry = 1ull << 7;

// Classify an EPT-violation exit qualification into a breakpoint type match.
// Returns true if the qualification indicates an access that a breakpoint of
// `type` should trap.
inline bool qualification_matches(std::uint64_t qualification, bp_type_t type) {
    const bool is_read    = (qualification & kEptViolationRead) != 0;
    const bool is_write   = (qualification & kEptViolationWrite) != 0;
    const bool is_execute = (qualification & kEptViolationExecute) != 0;
    switch (type) {
    case bp_type_t::execute: return is_execute;
    case bp_type_t::read:    return is_read;
    case bp_type_t::write:   return is_write;
    case bp_type_t::rw:      return is_read || is_write;
    }
    return false;
}

// A breakpoint table the VMM maintains. The usermode tooling mirrors this to
// know which guest-physical pages are currently armed.
struct breakpoint_table_t {
    ept_breakpoint_t entries[kMaxBreakpoints];
    std::uint32_t count = 0;
};

// Find a free slot, or return -1.
inline int find_free_slot(const breakpoint_table_t& table) {
    for (std::uint32_t i = 0; i < kMaxBreakpoints; ++i) {
        if (!table.entries[i].active) return static_cast<int>(i);
    }
    return -1;
}

// Compute the EPT entry value that arms a breakpoint: present with the
// trapped access type cleared. For an execute breakpoint, clear the execute
// bit; for a read/write breakpoint, clear the corresponding data bit(s).
inline std::uint64_t arm_entry(bp_type_t type) {
    std::uint64_t entry = kEptPresent;
    switch (type) {
    case bp_type_t::execute:
        entry &= ~kEptExecute;
        break;
    case bp_type_t::read:
        entry &= ~kEptRead;
        break;
    case bp_type_t::write:
        entry &= ~kEptWrite;
        break;
    case bp_type_t::rw:
        entry &= ~(kEptRead | kEptWrite);
        break;
    }
    return entry;
}

// The value to restore when the breakpoint is disarmed (full present).
inline std::uint64_t disarm_entry() {
    return kEptPresent;
}

} // namespace aida_ept
