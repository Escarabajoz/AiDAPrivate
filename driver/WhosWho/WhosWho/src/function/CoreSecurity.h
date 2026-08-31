#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "../../../../stealth_config.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

namespace device_names {

    // Randomized per-build device/symlink names derived from AIDA_STEALTH_SEED.
    // The leaf is 12 uppercase hex chars; the full names are assembled at
    // runtime so no fixed "\Device\WhosWho" string survives in the image.
    inline wchar_t g_device_name[80] = {};
    inline wchar_t g_symlink_name[80] = {};

    __forceinline BOOLEAN initialize_names() {
        const char* leaf = aida_stealth::kDeviceLeafHex;
        wchar_t* dev = g_device_name;
        wchar_t* sym = g_symlink_name;

        const wchar_t dev_prefix[] = L"\\Device\\";
        const wchar_t sym_prefix[] = L"\\DosDevices\\Global\\";
        for (const wchar_t* p = dev_prefix; *p; ++p) *dev++ = *p;
        for (const wchar_t* p = sym_prefix; *p; ++p) *sym++ = *p;
        for (int i = 0; i < 12 && leaf[i]; ++i) {
            *dev++ = static_cast<wchar_t>(leaf[i]);
            *sym++ = static_cast<wchar_t>(leaf[i]);
        }
        *dev = L'\0';
        *sym = L'\0';
        return TRUE;
    }

    __forceinline const wchar_t* get_device_name() {
        return g_device_name;
    }

    __forceinline const wchar_t* get_symlink_name() {
        return g_symlink_name;
    }

}

namespace caller_validation {

    // Challenge/response handshake. The client must prove it knows the build
    // seed by answering a challenge derived from a per-boot nonce and its PID.
    // This replaces the old single-global-PID check, which any process could
    // satisfy by simply opening the device.
    inline volatile HANDLE g_registered_client_pid = nullptr;
    inline volatile LONG g_authenticated = 0;
    inline volatile UINT64 g_boot_nonce = 0;
    inline volatile LONG g_nonce_init = 0;

    __forceinline UINT64 boot_nonce() {
        if (_InterlockedCompareExchange(&g_nonce_init, 0, 0) == 0) {
            LARGE_INTEGER perf = {};
            KeQuerySystemTime(&perf);
            UINT64 seed = static_cast<UINT64>(perf.QuadPart)
                ^ (static_cast<UINT64>(__rdtsc()) << 1)
                ^ static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            UINT64 nonce = aida_stealth::mix64(seed);
            if (nonce == 0) nonce = 0x9E3779B97F4A7C15ull;
            _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_boot_nonce),
                static_cast<LONG64>(nonce));
            _InterlockedExchange(&g_nonce_init, 1);
        }
        return g_boot_nonce;
    }

    __forceinline UINT64 expected_response(HANDLE pid) {
        return aida_stealth::auth_response(
            boot_nonce(),
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)));
    }

    __forceinline BOOLEAN register_client() {
        HANDLE pid = PsGetCurrentProcessId();
        _InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), pid);
        _InterlockedExchange(&g_authenticated, 0);
        WW_LOG("CLIENT_REGISTER pid=%llu nonce=0x%llx",
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)),
            static_cast<unsigned long long>(boot_nonce()));
        return TRUE;
    }

    __forceinline void unregister_client() {
        HANDLE prev = reinterpret_cast<HANDLE>(_InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), nullptr));
        _InterlockedExchange(&g_authenticated, 0);
        if (prev != nullptr) {
            WW_LOG("CLIENT_UNREGISTER pid=%llu",
                static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(prev)));
        }
    }

    __forceinline BOOLEAN is_registered_client(HANDLE pid) {
        return pid != nullptr && pid == g_registered_client_pid;
    }

    __forceinline BOOLEAN is_authenticated() {
        return _InterlockedCompareExchange(&g_authenticated, 0, 0) != 0;
    }

    // Verifies a challenge response supplied by the client. Returns TRUE only
    // when the response matches the expected value for the caller's PID.
    __forceinline BOOLEAN verify_response(HANDLE pid, UINT64 response) {
        if (pid == nullptr) return FALSE;
        if (response != expected_response(pid)) return FALSE;
        _InterlockedExchange(&g_authenticated, 1);
        return TRUE;
    }
}
