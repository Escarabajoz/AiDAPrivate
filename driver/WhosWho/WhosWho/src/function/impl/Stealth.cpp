#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../KernelLayout.h"
#include "../Struct.h"

// Stealth handlers: kernel callback enumeration/removal (DKOM) and
// module/thread hiding. These let the analysis driver defeat the
// process/image/thread/object callbacks that EAC and BattlEye register to
// observe the cheat process, and to unlink a module or thread from the
// structures those callbacks walk.
//
// All routines are defensive: PASSIVE_LEVEL only, SEH around every deref,
// address validation, and fail-closed returns.

namespace stealth_impl {

    // EX_CALLBACK_ROUTINE_BLOCK layout (undocumented, stable across builds).
    struct ex_callback_routine_block_t {
        UINT64 rundown_protect;
        UINT64 function;
        UINT64 context;
    };
    static_assert(sizeof(ex_callback_routine_block_t) == 24, "ex_callback_routine_block_t must be 24 bytes");

    constexpr ULONG kProcessNotifyMax = 64;
    constexpr ULONG kThreadNotifyMax  = 64;
    constexpr ULONG kImageNotifyMax   = 64;

    // Callback kinds (mirrored in comm.h).
    constexpr UINT32 kKindProcess = 1;
    constexpr UINT32 kKindThread  = 2;
    constexpr UINT32 kKindImage   = 3;
    constexpr UINT32 kKindObject  = 4;

    __forceinline BOOLEAN is_kernel_ptr(UINT64 v) {
        return v >= 0xFFFF800000000000ULL;
    }

    // Resolve a routine by name and scan its prologue for a RIP-relative LEA
    // that references a global array. Returns the array base, or 0.
    __forceinline UINT64 resolve_array_via_lea(const wchar_t* routine_name) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return 0;
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, routine_name);
        PVOID fn = MmGetSystemRoutineAddress(&name);
        if (!fn) return 0;

        UINT64 base = reinterpret_cast<UINT64>(fn);
        __try {
            // Scan up to 0x80 bytes for: 48 8D xx disp32  (LEA r64, [rip+disp32])
            for (ULONG i = 0; i < 0x80; ++i) {
                UINT8* p = reinterpret_cast<UINT8*>(base + i);
                if (p[0] == 0x48 && p[1] == 0x8D) {
                    UINT8 modrm = p[2];
                    if ((modrm & 0xC7) == 0x05) { // mod=00, rm=101 => RIP-relative
                        INT32 disp = *reinterpret_cast<INT32*>(p + 3);
                        UINT64 target = base + i + 7 + disp;
                        if (is_kernel_ptr(target)) return target;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        return 0;
    }

    // Enumerate a flat array of EX_CALLBACK_ROUTINE_BLOCK.
    __forceinline ULONG enum_flat_array(UINT64 array_base, ULONG max_entries,
                                        CALLBACK_ENTRY* out, ULONG out_cap, UINT32 kind) {
        if (!array_base || !out || out_cap == 0) return 0;
        ULONG written = 0;
        __try {
            for (ULONG i = 0; i < max_entries && written < out_cap; ++i) {
                auto* block = reinterpret_cast<ex_callback_routine_block_t*>(array_base + i * sizeof(ex_callback_routine_block_t));
                UINT64 fn = block->function;
                if (fn == 0) continue;
                if (!is_kernel_ptr(fn)) continue;
                out[written].callback_address = fn;
                out[written].module_base = 0;
                out[written].kind = kind;
                out[written].index = i;
                out[written].active = 1;
                out[written].padding = 0;
                ++written;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // keep what we have
        }
        return written;
    }

    // Unlink a single entry from a flat array by zeroing its function pointer.
    __forceinline BOOLEAN unlink_flat_array(UINT64 array_base, ULONG max_entries,
                                            UINT32 index, UINT64 expected_fn) {
        if (!array_base || index >= max_entries) return FALSE;
        __try {
            auto* block = reinterpret_cast<ex_callback_routine_block_t*>(array_base + index * sizeof(ex_callback_routine_block_t));
            if (expected_fn != 0 && block->function != expected_fn) return FALSE;
            block->function = 0;
            block->context = 0;
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
    }

    // Resolve the process/thread/image notify arrays once and cache.
    inline volatile LONG g_arrays_resolved = 0;
    inline UINT64 g_process_array = 0;
    inline UINT64 g_thread_array = 0;
    inline UINT64 g_image_array = 0;

    __forceinline void resolve_arrays() {
        if (_InterlockedCompareExchange(&g_arrays_resolved, 0, 0) != 0) return;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
        g_process_array = resolve_array_via_lea(L"PsSetCreateProcessNotifyRoutineEx");
        g_thread_array  = resolve_array_via_lea(L"PsSetCreateThreadNotifyRoutine");
        g_image_array   = resolve_array_via_lea(L"PsSetLoadImageNotifyRoutine");
        _InterlockedExchange(&g_arrays_resolved, 1);
    }

    __forceinline UINT64 array_for_kind(UINT32 kind) {
        resolve_arrays();
        switch (kind) {
        case kKindProcess: return g_process_array;
        case kKindThread:  return g_thread_array;
        case kKindImage:   return g_image_array;
        default: return 0;
        }
    }

    __forceinline ULONG max_for_kind(UINT32 kind) {
        switch (kind) {
        case kKindProcess: return kProcessNotifyMax;
        case kKindThread:  return kThreadNotifyMax;
        case kKindImage:   return kImageNotifyMax;
        default: return 0;
        }
    }

    // Module hiding: unlink a module from the target process's PEB LDR lists.
    // Walks the three InLoadOrder/InMemoryOrder/InInitializationOrder lists and
    // splices out the entry whose DllBase matches module_base.
    __forceinline BOOLEAN hide_module_in_peb(UINT32 pid, UINT64 module_base) {
        if (pid == 0 || module_base == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;
        if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb || !_ObfDereferenceObject) return FALSE;

        PEPROCESS process = nullptr;
        NTSTATUS st = _PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &process);
        if (!NT_SUCCESS(st) || !process) return FALSE;

        BOOLEAN result = FALSE;
        __try {
            PVOID peb = _PsGetProcessPeb(process);
            if (!peb) { _ObfDereferenceObject(process); return FALSE; }

            // PEB->Ldr at offset 0x18 (x64).
            PVOID ldr = *reinterpret_cast<PVOID*>(reinterpret_cast<UINT8*>(peb) + 0x18);
            if (!ldr) { _ObfDereferenceObject(process); return FALSE; }

            // PEB_LDR_DATA: InLoadOrderModuleList at 0x10, InMemoryOrderModuleList at 0x20,
            // InInitializationOrderModuleList at 0x30. Each is a LIST_ENTRY.
            const UINT64 list_offsets[3] = { 0x10, 0x20, 0x30 };
            for (ULONG li = 0; li < 3; ++li) {
                UINT64 head = reinterpret_cast<UINT64>(ldr) + list_offsets[li];
                UINT64 entry = *reinterpret_cast<UINT64*>(head); // Flink
                while (entry && entry != head) {
                    // LDR_DATA_TABLE_ENTRY: DllBase at offset 0x30 (x64).
                    UINT64 dll_base = *reinterpret_cast<UINT64*>(entry + 0x30);
                    if (dll_base == module_base) {
                        UINT64 flink = *reinterpret_cast<UINT64*>(entry);
                        UINT64 blink = *reinterpret_cast<UINT64*>(entry + 8);
                        *reinterpret_cast<UINT64*>(blink) = flink;
                        *reinterpret_cast<UINT64*>(flink + 8) = blink;
                        result = TRUE;
                        break;
                    }
                    entry = *reinterpret_cast<UINT64*>(entry);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            result = FALSE;
        }

        _ObfDereferenceObject(process);
        return result;
    }

    // Thread hiding: remove a thread from the process's thread list by
    // unlinking its ETHREAD ThreadListEntry. This makes the thread invisible
    // to PsGetNextProcessThread and to thread-notify callbacks that walk the
    // process thread list.
    __forceinline BOOLEAN hide_thread(UINT32 pid, UINT32 tid) {
        if (pid == 0 || tid == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL) return FALSE;
        if (!_PsLookupThreadByThreadId || !_ObfDereferenceObject) return FALSE;

        PETHREAD thread = nullptr;
        NTSTATUS st = _PsLookupThreadByThreadId(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(tid)), &thread);
        if (!NT_SUCCESS(st) || !thread) return FALSE;

        BOOLEAN result = FALSE;
        __try {
            // ETHREAD.ThreadListEntry is at offset 0x2F8 on Win10 2004+ and
            // 0x2E8 on Win11 24H2. Use the layout table.
            SIZE_T off = 0;
            ULONG build = whoswho_kernel_layout::build_number();
            if (build >= 26100) off = 0x2E8;
            else if (build >= 19041) off = 0x2F8;
            else off = 0x2F8;

            UINT64 entry = reinterpret_cast<UINT64>(thread) + off;
            UINT64 flink = *reinterpret_cast<UINT64*>(entry);
            UINT64 blink = *reinterpret_cast<UINT64*>(entry + 8);
            if (flink && blink) {
                *reinterpret_cast<UINT64*>(blink) = flink;
                *reinterpret_cast<UINT64*>(flink + 8) = blink;
                // Self-point to avoid dangling.
                *reinterpret_cast<UINT64*>(entry) = entry;
                *reinterpret_cast<UINT64*>(entry + 8) = entry;
                result = TRUE;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            result = FALSE;
        }

        _ObfDereferenceObject(thread);
        return result;
    }
}

NTSTATUS functions::handle_callback_enum(p_callback_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    request->entry_count = 0;
    request->total_count = 0;

    UINT32 kind = request->kind;
    if (kind == stealth_impl::kKindObject) {
        // Object callbacks (ObRegisterCallbacks) are not enumerated here; they
        // live in a linked list of OB_CALLBACK objects and require a different
        // walk. Report zero rather than fabricate entries.
        return STATUS_SUCCESS;
    }

    UINT64 array = stealth_impl::array_for_kind(kind);
    ULONG max_entries = stealth_impl::max_for_kind(kind);
    if (!array || max_entries == 0) return STATUS_NOT_FOUND;

    request->entry_count = stealth_impl::enum_flat_array(
        array, max_entries, request->entries, MAX_CALLBACK_ENTRIES, kind);
    request->total_count = request->entry_count;
    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_callback_unlink(p_callback_unlink request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    request->removed = 0;

    UINT32 kind = request->kind;
    if (kind == stealth_impl::kKindObject) {
        return STATUS_NOT_SUPPORTED;
    }

    UINT64 array = stealth_impl::array_for_kind(kind);
    ULONG max_entries = stealth_impl::max_for_kind(kind);
    if (!array || max_entries == 0) return STATUS_NOT_FOUND;

    BOOLEAN ok = stealth_impl::unlink_flat_array(
        array, max_entries, request->index, request->callback_address);
    request->removed = ok ? 1u : 0u;
    return ok ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS functions::handle_module_hide(p_module_hide request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    request->result = 0;
    BOOLEAN ok = stealth_impl::hide_module_in_peb(request->pid, request->module_base);
    request->result = ok ? 1u : 0u;
    request->hidden = ok ? 1u : 0u;
    return ok ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS functions::handle_thread_hide(p_thread_hide request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    request->result = 0;
    BOOLEAN ok = stealth_impl::hide_thread(request->pid, request->tid);
    request->result = ok ? 1u : 0u;
    request->hidden = ok ? 1u : 0u;
    return ok ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
