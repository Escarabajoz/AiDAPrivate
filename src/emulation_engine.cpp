#ifdef __NT__

#include "emulation_engine.hpp"
#include "../driver/comm.h"
#include "standalone/src/core/mcp/mcp_standalone.hpp"
#include "standalone/src/helpers/diag_log.hpp"

#pragma warning(push)
#pragma warning(disable: 4005)
#pragma warning(disable: 4018)
#pragma warning(disable: 4267)
#include <pro.h>
#include <kernwin.hpp>
#pragma warning(pop)

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <cstring>
#include <chrono>
#include <mutex>

extern std::unique_ptr<voyager::device_t> device;

namespace emulation {


static ZydisDecoder     g_decoder;
static ZydisFormatter   g_formatter;
static bool             g_zydis_initialized = false;
static std::once_flag   g_zydis_init_flag;

static std::uint64_t emu_now_ms()
{
    return static_cast<std::uint64_t>(GetTickCount64());
}

static bool emu_cancelled(const emulation_config_t* config, const char* phase)
{
    const bool cancel = mcp_standalone::current_call_cancelled();
    const bool deadline = config && config->deadline_ms != 0 && emu_now_ms() >= config->deadline_ms;
    if (cancel || deadline) {
        diag::log_tagged_fmt("emulation",
            "cancelled phase=%s cancel_token=%d deadline=%d now_ms=%llu deadline_ms=%llu",
            phase ? phase : "<null>",
            cancel ? 1 : 0,
            deadline ? 1 : 0,
            static_cast<unsigned long long>(emu_now_ms()),
            static_cast<unsigned long long>(config ? config->deadline_ms : 0));
        return true;
    }
    return false;
}

static std::uint64_t emu_deadline_remaining_ms(const emulation_config_t* config)
{
    if (!config || config->deadline_ms == 0)
        return 0;
    const std::uint64_t now = emu_now_ms();
    return now < config->deadline_ms ? config->deadline_ms - now : 0;
}

static std::recursive_timed_mutex& unicorn_native_lane_mutex()
{
    static std::recursive_timed_mutex m;
    return m;
}

static bool acquire_unicorn_native_lane(const emulation_config_t* config,
                                        const char* op,
                                        std::uint64_t base,
                                        std::uint64_t size,
                                        std::unique_lock<std::recursive_timed_mutex>& lane,
                                        std::string& failure)
{
    if (emu_cancelled(config, op)) {
        failure = "deadline or cancellation before Unicorn native call";
        return false;
    }
    const std::uint64_t remaining = emu_deadline_remaining_ms(config);
    const std::uint64_t wait_ms = remaining != 0 ? remaining : 30000;
    const std::uint64_t wait_begin = emu_now_ms();
    lane = std::unique_lock<std::recursive_timed_mutex>(unicorn_native_lane_mutex(), std::defer_lock);
    if (!lane.try_lock_for(std::chrono::milliseconds(wait_ms))) {
        failure = "timed out waiting for Unicorn native lane";
        diag::log_tagged_fmt("emulation",
            "unicorn_native_lane_timeout op=%s diag_id=%s tool=%s base=0x%llX size=0x%llX wait_ms=%llu deadline_remaining_ms=%llu tid=%lu",
            op ? op : "<null>",
            mcp_standalone::current_call_diag_id(),
            mcp_standalone::current_call_tool_name(),
            static_cast<unsigned long long>(base),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(emu_now_ms() - wait_begin),
            static_cast<unsigned long long>(remaining),
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    return true;
}

static bool unicorn_mem_map_checked(uc_engine* uc,
                                    std::uint64_t base,
                                    std::uint64_t size,
                                    std::uint32_t prot,
                                    const emulation_config_t* config,
                                    const char* phase,
                                    uc_err& err,
                                    std::string& failure)
{
    std::unique_lock<std::recursive_timed_mutex> lane;
    if (!acquire_unicorn_native_lane(config, phase, base, size, lane, failure))
        return false;
    const std::uint64_t begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "unicorn_map_begin diag_id=%s tool=%s phase=%s base=0x%llX size=0x%llX prot=0x%X deadline_remaining_ms=%llu tid=%lu begin_tick=%llu expected_end_marker=unicorn_map_end residual_native_uninterruptible=1",
        mcp_standalone::current_call_diag_id(),
        mcp_standalone::current_call_tool_name(),
        phase ? phase : "<null>",
        static_cast<unsigned long long>(base),
        static_cast<unsigned long long>(size),
        prot,
        static_cast<unsigned long long>(emu_deadline_remaining_ms(config)),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(begin));
    err = uc_mem_map(uc, base, static_cast<size_t>(size), prot);
    diag::log_tagged_fmt("emulation",
        "unicorn_map_end diag_id=%s tool=%s phase=%s base=0x%llX size=0x%llX err=%u text='%s' elapsed_ms=%llu deadline_remaining_ms=%llu tid=%lu",
        mcp_standalone::current_call_diag_id(),
        mcp_standalone::current_call_tool_name(),
        phase ? phase : "<null>",
        static_cast<unsigned long long>(base),
        static_cast<unsigned long long>(size),
        static_cast<unsigned>(err),
        uc_strerror(err),
        static_cast<unsigned long long>(emu_now_ms() - begin),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(config)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

static bool unicorn_mem_write_checked(uc_engine* uc,
                                      std::uint64_t base,
                                      const void* data,
                                      std::size_t size,
                                      const emulation_config_t* config,
                                      const char* phase,
                                      uc_err& err,
                                      std::string& failure)
{
    std::unique_lock<std::recursive_timed_mutex> lane;
    if (!acquire_unicorn_native_lane(config, phase, base, static_cast<std::uint64_t>(size), lane, failure))
        return false;
    const std::uint64_t begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "unicorn_write_begin diag_id=%s tool=%s phase=%s base=0x%llX size=%zu deadline_remaining_ms=%llu tid=%lu begin_tick=%llu expected_end_marker=unicorn_write_end residual_native_uninterruptible=1",
        mcp_standalone::current_call_diag_id(),
        mcp_standalone::current_call_tool_name(),
        phase ? phase : "<null>",
        static_cast<unsigned long long>(base),
        size,
        static_cast<unsigned long long>(emu_deadline_remaining_ms(config)),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(begin));
    err = uc_mem_write(uc, base, data, size);
    diag::log_tagged_fmt("emulation",
        "unicorn_write_end diag_id=%s tool=%s phase=%s base=0x%llX size=%zu err=%u text='%s' elapsed_ms=%llu deadline_remaining_ms=%llu tid=%lu",
        mcp_standalone::current_call_diag_id(),
        mcp_standalone::current_call_tool_name(),
        phase ? phase : "<null>",
        static_cast<unsigned long long>(base),
        size,
        static_cast<unsigned>(err),
        uc_strerror(err),
        static_cast<unsigned long long>(emu_now_ms() - begin),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(config)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

static bool unicorn_emu_start_checked(uc_engine* uc,
                                      std::uint64_t begin_addr,
                                      std::uint64_t until_addr,
                                      std::uint64_t timeout_us,
                                      std::uint32_t count,
                                      const emulation_config_t* config,
                                      uc_err& err,
                                      std::string& failure)
{
    std::unique_lock<std::recursive_timed_mutex> lane;
    if (!acquire_unicorn_native_lane(config, "unicorn_emu_start", begin_addr, until_addr, lane, failure))
        return false;
    const std::uint64_t begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "unicorn_start_begin diag_id=%s tool=%s start=0x%llX stop=0x%llX timeout_us=%llu max_instructions=%u deadline_remaining_ms=%llu tid=%lu begin_tick=%llu expected_end_marker=unicorn_start_end residual_native_uninterruptible=1",
        mcp_standalone::current_call_diag_id(),
        mcp_standalone::current_call_tool_name(),
        static_cast<unsigned long long>(begin_addr),
        static_cast<unsigned long long>(until_addr),
        static_cast<unsigned long long>(timeout_us),
        count,
        static_cast<unsigned long long>(emu_deadline_remaining_ms(config)),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(begin));
    err = uc_emu_start(uc, begin_addr, until_addr, timeout_us, count);
    diag::log_tagged_fmt("emulation",
        "unicorn_start_end diag_id=%s tool=%s err=%u text='%s' elapsed_ms=%llu deadline_remaining_ms=%llu tid=%lu",
        mcp_standalone::current_call_diag_id(),
        mcp_standalone::current_call_tool_name(),
        static_cast<unsigned>(err),
        uc_strerror(err),
        static_cast<unsigned long long>(emu_now_ms() - begin),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(config)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    return true;
}

static const char* uc_mem_type_name(uc_mem_type type)
{
    switch (type) {
    case UC_MEM_READ_UNMAPPED: return "read_unmapped";
    case UC_MEM_WRITE_UNMAPPED: return "write_unmapped";
    case UC_MEM_FETCH_UNMAPPED: return "fetch_unmapped";
    default: return "other";
    }
}

static void ensure_zydis_init()
{
    std::call_once(g_zydis_init_flag, []() {
        ZydisDecoderInit(&g_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&g_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        ZydisFormatterSetProperty(&g_formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_FALSE);
        ZydisFormatterSetProperty(&g_formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_FALSE);
        g_zydis_initialized = true;
    });
}

decoded_insn_t disassemble_one(
    const std::uint8_t* data,
    std::size_t         data_size,
    std::uint64_t       runtime_address)
{
    ensure_zydis_init();

    decoded_insn_t result;
    result.address = runtime_address;

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &g_decoder, data, data_size, &instruction, operands)))
    {
        result.length   = 1;
        result.mnemonic = "db";
        result.full_text = "db ??";
        return result;
    }

    result.length   = instruction.length;
    result.category = instruction.meta.category;

    const char* mnemonic_str = ZydisMnemonicGetString(instruction.mnemonic);
    result.mnemonic = mnemonic_str ? mnemonic_str : "???";

    char full_buf[256] = {};
    ZydisFormatterFormatInstruction(&g_formatter, &instruction, operands,
                                    instruction.operand_count_visible,
                                    full_buf, sizeof(full_buf),
                                    runtime_address, ZYAN_NULL);
    result.full_text = full_buf;


    const char* space = std::strchr(full_buf, ' ');
    result.operands_text = space ? (space + 1) : "";


    switch (instruction.meta.category)
    {
    case ZYDIS_CATEGORY_CALL:
        result.is_call = true;
        break;
    case ZYDIS_CATEGORY_RET:
        result.is_ret = true;
        break;
    case ZYDIS_CATEGORY_COND_BR:
    case ZYDIS_CATEGORY_UNCOND_BR:
        result.is_branch = true;
        break;
    case ZYDIS_CATEGORY_NOP:
        result.is_nop = true;
        break;
    default:
        break;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_SYSTEM ||
        instruction.meta.category == ZYDIS_CATEGORY_INTERRUPT)
        result.is_privileged = true;

    return result;
}

std::vector<decoded_insn_t> disassemble_range(
    const std::uint8_t* data,
    std::size_t         data_size,
    std::uint64_t       runtime_address,
    std::uint32_t       max_instructions)
{
    ensure_zydis_init();

    std::vector<decoded_insn_t> results;
    results.reserve(std::min<std::uint32_t>(max_instructions, 4096u));

    std::size_t offset = 0;
    std::uint32_t count = 0;

    while (offset < data_size && count < max_instructions)
    {
        auto insn = disassemble_one(
            data + offset,
            data_size - offset,
            runtime_address + offset);

        offset += insn.length;
        ++count;
        results.push_back(std::move(insn));
    }

    return results;
}

std::vector<std::uint8_t> driver_read_bytes(
    std::uint64_t  address,
    std::size_t    size)
{
    diag::log_tagged_fmt("emulation",
        "driver_read_bytes entry address=0x%llX size=%zu pid=%u",
        static_cast<unsigned long long>(address),
        size,
        device ? device->get_process_id() : 0);
    if (!device || !device->is_connected())
        return {};

    const bool kernel_addr = address >= 0xFFFF800000000000ULL;

    if (!kernel_addr && device->get_process_id() == 0)
        return {};

    if (size == 0 || size > 64ULL * 1024 * 1024)
        return {};

    std::vector<std::uint8_t> buffer(size, 0);
    constexpr std::size_t CHUNK_SIZE = 65536;
    std::size_t total_read = 0;
    for (std::size_t offset = 0; offset < size; offset += CHUNK_SIZE)
    {
        if (mcp_standalone::current_call_cancelled()) {
            diag::log_tagged_fmt("emulation",
                "driver_read_bytes cancelled address=0x%llX offset=%zu total_read=%zu",
                static_cast<unsigned long long>(address),
                offset,
                total_read);
            break;
        }
        std::size_t chunk = std::min(CHUNK_SIZE, size - offset);
        std::size_t bytes_read = 0;
        diag::log_tagged_fmt("emulation",
            "driver_read_bytes chunk_begin address=0x%llX offset=%zu chunk=%zu kernel=%d",
            static_cast<unsigned long long>(address),
            offset,
            chunk,
            kernel_addr ? 1 : 0);
        if (kernel_addr)
            bytes_read = device->read_kernel_raw(address + offset, buffer.data() + offset, chunk);
        else
            bytes_read = device->read_raw(address + offset, buffer.data() + offset, chunk);
        diag::log_tagged_fmt("emulation",
            "driver_read_bytes chunk_end address=0x%llX offset=%zu requested=%zu read=%zu",
            static_cast<unsigned long long>(address),
            offset,
            chunk,
            bytes_read);
        if (bytes_read == 0)
            break;
        if (bytes_read > chunk)
            bytes_read = chunk;
        total_read += bytes_read;
        if (bytes_read < chunk)
            break;
    }
    if (total_read == 0)
        return {};
    buffer.resize(total_read);
    diag::log_tagged_fmt("emulation",
        "driver_read_bytes exit address=0x%llX total_read=%zu",
        static_cast<unsigned long long>(address),
        total_read);
    return buffer;
}

std::vector<decoded_insn_t> driver_disassemble_range(
    std::uint64_t  address,
    std::uint32_t  size,
    std::uint32_t  max_instructions)
{
    auto bytes = driver_read_bytes(address, size);
    if (bytes.empty())
        return {};

    return disassemble_range(bytes.data(), bytes.size(), address, max_instructions);
}


process_snapshot_t driver_snapshot(
    std::uint32_t pid,
    std::uint32_t tid,
    std::uint64_t region_base,
    std::uint64_t region_size,
    const emulation_config_t* config)
{
    process_snapshot_t snap;
    snap.pid = pid;
    snap.tid = tid;
    const bool explicit_region = region_base != 0 && region_size != 0;
    const bool neutral_allowed = explicit_region && config && config->allow_neutral_thread_context;
    diag::log_tagged_fmt("emulation",
        "driver_snapshot entry pid=%u tid=%u region_base=0x%llX region_size=0x%llX neutral_allowed=%d deadline_ms=%llu",
        pid,
        tid,
        static_cast<unsigned long long>(region_base),
        static_cast<unsigned long long>(region_size),
        neutral_allowed ? 1 : 0,
        static_cast<unsigned long long>(config ? config->deadline_ms : 0));

    if (!device || !device->is_connected())
    {
        snap.error = "Driver not connected";
        diag::log_tagged_fmt("emulation", "driver_snapshot error reason='%s'", snap.error.c_str());
        return snap;
    }

    voyager::device_t::thread_context ctx{};
    bool did_suspend = false;
    struct suspend_guard_t {
        voyager::device_t* dev = nullptr;
        std::uint32_t tid = 0;
        bool active = false;
        ~suspend_guard_t()
        {
            if (active && dev) {
                diag::log_tagged_fmt("emulation", "driver_snapshot resume_begin tid=%u", tid);
                const bool ok = dev->resume_thread(tid);
                diag::log_tagged_fmt("emulation", "driver_snapshot resume_end tid=%u ok=%d", tid, ok ? 1 : 0);
            }
        }
        void dismiss() noexcept { active = false; }
    } suspend_guard{device.get(), tid, false};

    if (neutral_allowed && tid == 0) {
        ctx.rip = config && config->start_address != 0 ? config->start_address : region_base;
        ctx.rsp = 0;
        ctx.rbp = 0;
        ctx.rflags = 0x202;
        diag::log_tagged_fmt("emulation",
            "driver_snapshot neutral_context pid=%u tid=%u rip=0x%llX",
            pid,
            tid,
            static_cast<unsigned long long>(ctx.rip));
    } else {
        if (emu_cancelled(config, "snapshot_before_suspend")) {
            snap.error = "Cancelled before suspending target thread";
            return snap;
        }
        std::uint32_t prev_count = 0;
        diag::log_tagged_fmt("emulation", "driver_snapshot suspend_begin tid=%u", tid);
        did_suspend = device->suspend_thread(tid, &prev_count);
        suspend_guard.active = did_suspend;
        diag::log_tagged_fmt("emulation",
            "driver_snapshot suspend_end tid=%u ok=%d prev_count=%u",
            tid,
            did_suspend ? 1 : 0,
            prev_count);
        if (emu_cancelled(config, "snapshot_after_suspend")) {
            snap.error = "Cancelled after suspending target thread";
            return snap;
        }
        diag::log_tagged_fmt("emulation", "driver_snapshot get_context_begin tid=%u", tid);
        const bool got_context = device->get_thread_context(tid, ctx);
        diag::log_tagged_fmt("emulation", "driver_snapshot get_context_end tid=%u ok=%d", tid, got_context ? 1 : 0);
        if (!got_context)
        {
            if (!explicit_region)
            {
                snap.error = "Failed to read thread context for TID " + std::to_string(tid);
                diag::log_tagged_fmt("emulation", "driver_snapshot error reason='%s'", snap.error.c_str());
                return snap;
            }
            ctx.rip = config && config->start_address != 0 ? config->start_address : region_base;
            ctx.rsp = 0;
            ctx.rbp = 0;
            ctx.rflags = 0x202;
            diag::log_tagged_fmt("emulation",
                "driver_snapshot fallback_neutral_context tid=%u rip=0x%llX explicit_region=%d",
                tid,
                static_cast<unsigned long long>(ctx.rip),
                explicit_region ? 1 : 0);
        }
    }

    snap.rax = ctx.rax; snap.rbx = ctx.rbx; snap.rcx = ctx.rcx; snap.rdx = ctx.rdx;
    snap.rsi = ctx.rsi; snap.rdi = ctx.rdi; snap.rbp = ctx.rbp; snap.rsp = ctx.rsp;
    snap.r8  = ctx.r8;  snap.r9  = ctx.r9;  snap.r10 = ctx.r10; snap.r11 = ctx.r11;
    snap.r12 = ctx.r12; snap.r13 = ctx.r13; snap.r14 = ctx.r14; snap.r15 = ctx.r15;
    snap.rip = ctx.rip;  snap.rflags = ctx.rflags;


    std::vector<voyager::detail::region_entry> regions;
    if (explicit_region)
    {
        if (emu_cancelled(config, "snapshot_before_region_enum_explicit")) {
            snap.error = "Cancelled before explicit region enumeration";
            return snap;
        }
        diag::log_tagged_fmt("emulation",
            "driver_snapshot region_enum_begin mode=explicit base=0x%llX end=0x%llX",
            static_cast<unsigned long long>(region_base),
            static_cast<unsigned long long>(region_size > UINT64_MAX - region_base ? UINT64_MAX : region_base + region_size));
        const std::uint64_t region_end = region_size > UINT64_MAX - region_base ? UINT64_MAX : region_base + region_size;
        regions = device->enumerate_memory_regions(region_base, region_end, false);
        diag::log_tagged_fmt("emulation",
            "driver_snapshot region_enum_end mode=explicit count=%zu",
            regions.size());
    }
    else
    {

        struct snapshot_range { std::uint64_t base; std::uint64_t size; };
        std::vector<snapshot_range> ranges_to_capture;


        constexpr std::uint64_t RIP_WINDOW = 0x200000;
        std::uint64_t rip_start = (ctx.rip > RIP_WINDOW) ? (ctx.rip - RIP_WINDOW) : 0x10000;
        ranges_to_capture.push_back({rip_start, RIP_WINDOW * 2});


        constexpr std::uint64_t RSP_WINDOW = 0x100000;
        std::uint64_t rsp_start = (ctx.rsp > RSP_WINDOW) ? (ctx.rsp - RSP_WINDOW) : 0x10000;
        ranges_to_capture.push_back({rsp_start, RSP_WINDOW * 2});


        if (emu_cancelled(config, "snapshot_before_region_enum_full")) {
            snap.error = "Cancelled before full region enumeration";
            return snap;
        }
        diag::log_tagged_fmt("emulation", "driver_snapshot region_enum_begin mode=full");
        auto all_regions = device->enumerate_memory_regions(0x10000, 0x7FFFFFFFFFFF, false);
        diag::log_tagged_fmt("emulation", "driver_snapshot region_enum_end mode=full count=%zu", all_regions.size());
        for (const auto& r : all_regions)
        {
            if (emu_cancelled(config, "snapshot_region_filter")) {
                snap.error = "Cancelled while filtering memory regions";
                return snap;
            }

            if (r.state == 0x1000 && r.type == 0x1000000)
            {
                regions.push_back(r);
                continue;
            }


            if (r.state == 0x1000)
            {
                for (const auto& range : ranges_to_capture)
                {
                    std::uint64_t range_end = range.base + range.size;
                    std::uint64_t reg_end = r.base + r.size;
                    if (r.base < range_end && reg_end > range.base)
                    {
                        regions.push_back(r);
                        break;
                    }
                }
            }
        }
    }


    constexpr std::uint64_t MAX_SNAPSHOT_BYTES = 256ULL * 1024 * 1024;
    std::uint64_t total_bytes = 0;

    for (const auto& r : regions)
    {
        if (emu_cancelled(config, "snapshot_region_loop")) {
            snap.error = "Cancelled before reading memory region";
            return snap;
        }
        std::uint64_t capture_base = r.base;
        std::uint64_t capture_size = r.size;
        if (explicit_region) {
            const std::uint64_t requested_end = region_size > UINT64_MAX - region_base ? UINT64_MAX : region_base + region_size;
            const std::uint64_t region_end = r.size > UINT64_MAX - r.base ? UINT64_MAX : r.base + r.size;
            const std::uint64_t clipped_base = std::max(region_base, r.base);
            const std::uint64_t clipped_end = std::min(requested_end, region_end);
            if (clipped_end <= clipped_base)
                continue;
            capture_base = clipped_base;
            capture_size = clipped_end - clipped_base;
        }
        if (capture_size == 0 || capture_size > MAX_SNAPSHOT_BYTES - total_bytes)
            break;

        memory_snapshot_region_t region;
        region.base    = capture_base;
        region.size    = capture_size;
        region.protect = r.protect;
        region.data.resize(static_cast<std::size_t>(capture_size), 0);

        diag::log_tagged_fmt("emulation",
            "driver_snapshot read_region_begin base=0x%llX size=0x%llX source_base=0x%llX source_size=0x%llX protect=0x%X state=0x%X total_before=%llu",
            static_cast<unsigned long long>(capture_base),
            static_cast<unsigned long long>(capture_size),
            static_cast<unsigned long long>(r.base),
            static_cast<unsigned long long>(r.size),
            r.protect,
            r.state,
            static_cast<unsigned long long>(total_bytes));

        constexpr std::size_t CHUNK_SIZE = 65536;
        for (std::uint64_t offset = 0; offset < capture_size; offset += CHUNK_SIZE)
        {
            if (emu_cancelled(config, "snapshot_read_chunk")) {
                snap.error = "Cancelled while reading memory snapshot";
                return snap;
            }
            std::size_t chunk = static_cast<std::size_t>(
                std::min<std::uint64_t>(CHUNK_SIZE, capture_size - offset));
            diag::log_tagged_fmt("emulation",
                "driver_snapshot read_chunk_begin base=0x%llX offset=0x%llX chunk=%zu",
                static_cast<unsigned long long>(capture_base),
                static_cast<unsigned long long>(offset),
                chunk);
            const std::size_t bytes_read = device->read_raw(capture_base + offset, region.data.data() + offset, chunk);
            diag::log_tagged_fmt("emulation",
                "driver_snapshot read_chunk_end base=0x%llX offset=0x%llX requested=%zu read=%zu",
                static_cast<unsigned long long>(capture_base),
                static_cast<unsigned long long>(offset),
                chunk,
                bytes_read);
        }

        total_bytes += capture_size;
        snap.regions.push_back(std::move(region));
        diag::log_tagged_fmt("emulation",
            "driver_snapshot read_region_end base=0x%llX total=%llu regions=%zu",
            static_cast<unsigned long long>(capture_base),
            static_cast<unsigned long long>(total_bytes),
            snap.regions.size());
    }

    snap.total_snapshot_bytes = total_bytes;


    if (did_suspend)
        suspend_guard.dismiss();
    if (did_suspend) {
        diag::log_tagged_fmt("emulation", "driver_snapshot resume_begin tid=%u", tid);
        const bool resumed = device->resume_thread(tid);
        diag::log_tagged_fmt("emulation", "driver_snapshot resume_end tid=%u ok=%d", tid, resumed ? 1 : 0);
    }

    snap.success = true;
    diag::log_tagged_fmt("emulation",
        "driver_snapshot exit pid=%u tid=%u success=1 regions=%zu total_snapshot_bytes=%llu rip=0x%llX",
        pid,
        tid,
        snap.regions.size(),
        static_cast<unsigned long long>(snap.total_snapshot_bytes),
        static_cast<unsigned long long>(snap.rip));
    return snap;
}


struct uc_trace_ctx_t {
    uc_engine*                  uc          = nullptr;
    const emulation_config_t*   config      = nullptr;
    std::vector<trace_entry_t>* trace       = nullptr;
    std::vector<mem_write_t>*   mem_writes  = nullptr;
    std::vector<mem_read_t>*    mem_reads   = nullptr;
    std::uint32_t               insn_count  = 0;
    std::uint64_t               current_rip = 0;
    bool                        hit_ret     = false;
    bool                        hit_bp      = false;
    const std::uint8_t*         mapped_code = nullptr;
    std::size_t                 mapped_code_size = 0;
    std::uint64_t               mapped_code_base = 0;
    std::uint32_t               invalid_page_maps = 0;
    bool                        cancelled = false;
    bool                        hook_failure = false;
};

static void uc_read_regs(uc_engine* uc, trace_entry_t& entry)
{
    uc_reg_read(uc, UC_X86_REG_RAX, &entry.rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &entry.rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &entry.rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &entry.rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &entry.rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &entry.rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &entry.rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &entry.rsp);
    uc_reg_read(uc, UC_X86_REG_R8,  &entry.r8);
    uc_reg_read(uc, UC_X86_REG_R9,  &entry.r9);
    uc_reg_read(uc, UC_X86_REG_R10, &entry.r10);
    uc_reg_read(uc, UC_X86_REG_R11, &entry.r11);
    uc_reg_read(uc, UC_X86_REG_R12, &entry.r12);
    uc_reg_read(uc, UC_X86_REG_R13, &entry.r13);
    uc_reg_read(uc, UC_X86_REG_R14, &entry.r14);
    uc_reg_read(uc, UC_X86_REG_R15, &entry.r15);
    uc_reg_read(uc, UC_X86_REG_RIP, &entry.rip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &entry.rflags);
}

static bool is_kernel_address(std::uint64_t address)
{
    return address >= 0xFFFF800000000000ULL;
}

static void add_synthetic_stack(process_snapshot_t& snapshot, bool kernel_mode)
{
    constexpr std::uint64_t KERNEL_STACK_BASE = 0xFFFFFAFF00000000ULL;
    constexpr std::uint64_t USER_STACK_BASE = 0x000000007FFD0000ULL;
    constexpr std::uint64_t STACK_SIZE = 0x20000ULL;
    const std::uint64_t stack_base = kernel_mode ? KERNEL_STACK_BASE : USER_STACK_BASE;
    const std::uint64_t stack_top = stack_base + STACK_SIZE - 0x1000ULL;

    for (const auto& region : snapshot.regions)
    {
        if (stack_top >= region.base && stack_top + 8 <= region.base + region.size)
        {
            snapshot.rsp = stack_top;
            if (snapshot.rbp == 0)
                snapshot.rbp = stack_top + 0x100ULL;
            return;
        }
    }

    memory_snapshot_region_t stack_region;
    stack_region.base = stack_base;
    stack_region.size = STACK_SIZE;
    stack_region.data.resize(static_cast<std::size_t>(STACK_SIZE), 0);
    snapshot.regions.push_back(std::move(stack_region));
    snapshot.rsp = stack_top;
    if (snapshot.rbp == 0)
        snapshot.rbp = stack_top + 0x100ULL;
}

static void prepare_snapshot_for_config(process_snapshot_t& snapshot, const emulation_config_t& config)
{
    if (config.start_address != 0)
        snapshot.rip = config.start_address;
    if (snapshot.rflags == 0)
        snapshot.rflags = 0x202;
    if (snapshot.rsp == 0)
        add_synthetic_stack(snapshot, is_kernel_address(snapshot.rip));
}

static void hook_code_cb(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    try
    {
    ctx->current_rip = address;
    ctx->insn_count++;

    if (emu_cancelled(ctx->config, "unicorn_hook_code"))
    {
        ctx->cancelled = true;
        uc_emu_stop(uc);
        return;
    }

    if (ctx->insn_count > ctx->config->max_instructions)
    {
        uc_emu_stop(uc);
        return;
    }


    if (!ctx->config->breakpoint_addresses.empty() &&
        ctx->config->breakpoint_addresses.count(address))
    {
        ctx->hit_bp = true;
        uc_emu_stop(uc);
        return;
    }


    if (ctx->config->stop_address != 0 && address == ctx->config->stop_address)
    {
        uc_emu_stop(uc);
        return;
    }

    decoded_insn_t decoded;
    bool decoded_current = false;
    if (ctx->mapped_code && address >= ctx->mapped_code_base)
    {
        std::uint64_t off = address - ctx->mapped_code_base;
        if (off < ctx->mapped_code_size)
        {
            decoded = disassemble_one(
                ctx->mapped_code + off,
                ctx->mapped_code_size - static_cast<std::size_t>(off),
                address);
            decoded_current = true;
            if (decoded.is_ret)
                ctx->hit_ret = true;
        }
    }

    if (ctx->trace && ctx->trace->size() < ctx->config->max_trace_entries)
    {
        trace_entry_t entry;
        entry.address   = address;
        entry.insn_size = size;


        if (decoded_current)
            entry.disasm = decoded.full_text;

        if (ctx->config->record_registers)
            uc_read_regs(uc, entry);

        ctx->trace->push_back(std::move(entry));
    }


    if (ctx->hit_ret)
        uc_emu_stop(uc);
    }
    catch (...)
    {
        diag::log_tagged_fmt("emulation", "unicorn_hook_code_exception address=0x%llX",
            static_cast<unsigned long long>(address));
        if (ctx)
        {
            ctx->cancelled = true;
            ctx->hook_failure = true;
        }
        uc_emu_stop(uc);
    }
}

static void hook_mem_write_cb(uc_engine* , uc_mem_type ,
                              uint64_t address, int size,
                              int64_t value, void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    if (emu_cancelled(ctx->config, "unicorn_hook_mem_write")) {
        ctx->cancelled = true;
        if (ctx->uc)
            uc_emu_stop(ctx->uc);
        return;
    }
    if (!ctx->config->record_mem_writes || !ctx->mem_writes)
        return;

    mem_write_t w;
    w.address      = address;
    w.size         = static_cast<std::uint64_t>(size);
    w.insn_address = ctx->current_rip;
    w.data.resize(size);
    std::memcpy(w.data.data(), &value, std::min<int>(size, 8));
    ctx->mem_writes->push_back(std::move(w));
}

static bool hook_mem_invalid_cb(uc_engine* uc, uc_mem_type type,
                                uint64_t address, int size,
                                int64_t , void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    if (!ctx)
        return false;
    if (emu_cancelled(ctx->config, "unicorn_hook_mem_invalid")) {
        ctx->cancelled = true;
        uc_emu_stop(uc);
        return false;
    }
    if (ctx->invalid_page_maps >= ctx->config->max_invalid_page_maps) {
        diag::log_tagged_fmt("emulation",
            "unicorn_invalid_map_cap type=%s address=0x%llX size=%d maps=%u cap=%u",
            uc_mem_type_name(type),
            static_cast<unsigned long long>(address),
            size,
            ctx->invalid_page_maps,
            ctx->config->max_invalid_page_maps);
        uc_emu_stop(uc);
        return false;
    }
    diag::log_tagged_fmt("emulation",
        "unicorn_invalid_memory type=%s address=0x%llX size=%d current_rip=0x%llX maps=%u cap=%u",
        uc_mem_type_name(type),
        static_cast<unsigned long long>(address),
        size,
        static_cast<unsigned long long>(ctx->current_rip),
        ctx->invalid_page_maps,
        ctx->config->max_invalid_page_maps);

    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_FETCH_UNMAPPED)
    {
        std::uint64_t aligned = address & ~0xFFFULL;
        std::vector<std::uint8_t> zeros(0x2000, 0);
        uc_err err = UC_ERR_OK;
        std::string failure;
        if (!unicorn_mem_map_checked(uc, aligned, 0x2000, UC_PROT_ALL, ctx->config, "invalid_memory_map", err, failure)) {
            diag::log_tagged_fmt("emulation", "unicorn_invalid_memory_map_aborted failure='%s'", failure.c_str());
            return false;
        }
        if (err != UC_ERR_OK)
            return false;
        if (!unicorn_mem_write_checked(uc, aligned, zeros.data(), zeros.size(), ctx->config, "invalid_memory_zero_fill", err, failure)) {
            diag::log_tagged_fmt("emulation", "unicorn_invalid_memory_write_aborted failure='%s'", failure.c_str());
            return false;
        }
        if (err != UC_ERR_OK)
            return false;
        ++ctx->invalid_page_maps;
        return true;
    }

    if (type == UC_MEM_WRITE_UNMAPPED)
    {
        std::uint64_t aligned = address & ~0xFFFULL;
        uc_err err = UC_ERR_OK;
        std::string failure;
        if (!unicorn_mem_map_checked(uc, aligned, 0x2000, UC_PROT_ALL, ctx->config, "invalid_write_map", err, failure)) {
            diag::log_tagged_fmt("emulation", "unicorn_invalid_write_map_aborted failure='%s'", failure.c_str());
            return false;
        }
        if (err != UC_ERR_OK)
            return false;
        ++ctx->invalid_page_maps;
        return true;
    }

    (void)size;
    return false;
}

static void hook_mem_read_cb(uc_engine* , uc_mem_type ,
                             uint64_t address, int size,
                             int64_t , void* user_data)
{
    auto* ctx = static_cast<uc_trace_ctx_t*>(user_data);
    if (emu_cancelled(ctx->config, "unicorn_hook_mem_read")) {
        ctx->cancelled = true;
        if (ctx->uc)
            uc_emu_stop(ctx->uc);
        return;
    }
    if (!ctx->config->record_mem_reads || !ctx->mem_reads)
        return;

    mem_read_t r;
    r.address      = address;
    r.size         = static_cast<std::uint64_t>(size);
    r.insn_address = ctx->current_rip;
    ctx->mem_reads->push_back(std::move(r));
}

emulation_result_t emulate_from_snapshot(
    const process_snapshot_t& snapshot,
    const emulation_config_t& config)
{
    emulation_result_t result;
    result.start_address = config.start_address != 0 ? config.start_address : snapshot.rip;
    diag::log_tagged_fmt("emulation",
        "emulate_from_snapshot entry pid=%u tid=%u start=0x%llX regions=%zu max_instructions=%u max_trace=%u timeout_us=%llu deadline_ms=%llu invalid_cap=%u",
        snapshot.pid,
        snapshot.tid,
        static_cast<unsigned long long>(result.start_address),
        snapshot.regions.size(),
        config.max_instructions,
        config.max_trace_entries,
        static_cast<unsigned long long>(config.timeout_us),
        static_cast<unsigned long long>(config.deadline_ms),
        config.max_invalid_page_maps);

    if (snapshot.regions.empty())
    {
        result.error = "Snapshot has no memory regions";
        diag::log_tagged_fmt("emulation", "emulate_from_snapshot error reason='%s'", result.error.c_str());
        return result;
    }

    if (emu_cancelled(&config, "emulate_before_uc_open")) {
        result.error = "Emulation cancelled before Unicorn initialization";
        return result;
    }

    uc_engine* uc = nullptr;
    diag::log_tagged_fmt("emulation", "unicorn_open_begin");
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    diag::log_tagged_fmt("emulation", "unicorn_open_end err=%u text='%s'", static_cast<unsigned>(err), uc_strerror(err));
    if (err != UC_ERR_OK)
    {
        result.error = std::string("Unicorn init failed: ") + uc_strerror(err);
        return result;
    }


    struct uc_guard_t {
        uc_engine* engine;
        ~uc_guard_t() { if (engine) uc_close(engine); }
    } uc_guard{uc};


    struct merged_region_t {
        std::uint64_t base;
        std::uint64_t size;
    };
    std::vector<merged_region_t> to_map;

    for (const auto& region : snapshot.regions)
    {
        if (emu_cancelled(&config, "unicorn_prepare_map")) {
            result.error = "Emulation cancelled while preparing memory map";
            return result;
        }

        std::uint64_t aligned_base = region.base & ~0xFFFULL;
        std::uint64_t aligned_end  = (region.base + region.size + 0xFFF) & ~0xFFFULL;
        if (aligned_end > aligned_base)
            to_map.push_back({aligned_base, aligned_end - aligned_base});
    }

    std::sort(to_map.begin(), to_map.end(),
        [](const merged_region_t& a, const merged_region_t& b) { return a.base < b.base; });

    std::vector<merged_region_t> coalesced;
    coalesced.reserve(to_map.size());
    for (const auto& m : to_map)
    {
        if (!coalesced.empty())
        {
            std::uint64_t back_end = coalesced.back().base + coalesced.back().size;
            std::uint64_t m_end = m.base + m.size;
            if (m.base <= back_end)
            {
                if (m_end > back_end)
                    coalesced.back().size = m_end - coalesced.back().base;
                continue;
            }
        }
        coalesced.push_back(m);
    }
    to_map = std::move(coalesced);


    for (const auto& m : to_map)
    {
        if (emu_cancelled(&config, "unicorn_map_loop")) {
            result.error = "Emulation cancelled before mapping memory";
            return result;
        }
        std::string failure;
        if (!unicorn_mem_map_checked(uc, m.base, m.size, UC_PROT_ALL, &config, "snapshot_region_map", err, failure)) {
            result.error = failure;
            return result;
        }
        if (err != UC_ERR_OK)
        {
            std::ostringstream addr;
            addr << std::hex << m.base;
            result.error = std::string("uc_mem_map failed at 0x") + addr.str() + ": " + uc_strerror(err);
            return result;
        }
    }


    const std::uint8_t* code_at_rip = nullptr;
    std::size_t          code_at_rip_size = 0;
    std::uint64_t        code_at_rip_base = 0;

    struct written_range_t { std::uint64_t base; std::uint64_t end; };
    std::vector<written_range_t> written_ranges;
    written_ranges.reserve(snapshot.regions.size());

    auto record_coverage = [&](std::uint64_t base, std::uint64_t end)
    {
        std::uint64_t merged_base = base;
        std::uint64_t merged_end = end;
        while (true)
        {
            bool grew = false;
            for (auto& wr : written_ranges)
            {
                if (merged_base <= wr.end && wr.base <= merged_end)
                {
                    merged_base = std::min(merged_base, wr.base);
                    merged_end = std::max(merged_end, wr.end);
                    wr = written_ranges.back();
                    written_ranges.pop_back();
                    grew = true;
                    break;
                }
            }
            if (!grew)
                break;
        }
        written_ranges.push_back({merged_base, merged_end});
    };

    auto write_region_payload = [&](const memory_snapshot_region_t& region, uc_err& out_err) -> bool
    {
        std::vector<std::pair<std::uint64_t, std::uint64_t>> uncovered;
        std::uint64_t cursor = region.base;
        const std::uint64_t region_end = region.base + region.data.size();
        for (const auto& wr : written_ranges)
        {
            if (wr.end <= cursor || wr.base >= region_end)
                continue;
            if (wr.base > cursor)
                uncovered.push_back({cursor, std::min<std::uint64_t>(wr.base, region_end)});
            cursor = std::max<std::uint64_t>(cursor, wr.end);
        }
        if (cursor < region_end)
            uncovered.push_back({cursor, region_end});

        for (const auto& chunk : uncovered)
        {
            const std::uint64_t offset = chunk.first - region.base;
            const std::uint64_t length = chunk.second - chunk.first;
            std::string failure;
            if (!unicorn_mem_write_checked(uc, chunk.first, region.data.data() + offset, static_cast<std::size_t>(length), &config, "snapshot_region_write", out_err, failure)) {
                result.error = failure;
                return false;
            }
            if (out_err != UC_ERR_OK) {
                result.error = std::string("uc_mem_write failed: ") + uc_strerror(out_err);
                return false;
            }
        }
        if (region_end > region.base)
            record_coverage(region.base, region_end);
        return true;
    };

    for (const auto& region : snapshot.regions)
    {
        if (emu_cancelled(&config, "unicorn_write_loop")) {
            result.error = "Emulation cancelled before writing memory";
            return result;
        }
        if (!region.data.empty())
        {
            if (!write_region_payload(region, err))
                return result;
        }


        std::uint64_t start = result.start_address;
        if (code_at_rip == nullptr && start >= region.base && start < region.base + region.size)
        {
            code_at_rip      = region.data.data();
            code_at_rip_size = region.data.size();
            code_at_rip_base = region.base;
        }
    }


    uc_reg_write(uc, UC_X86_REG_RAX, &snapshot.rax);
    uc_reg_write(uc, UC_X86_REG_RBX, &snapshot.rbx);
    uc_reg_write(uc, UC_X86_REG_RCX, &snapshot.rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &snapshot.rdx);
    uc_reg_write(uc, UC_X86_REG_RSI, &snapshot.rsi);
    uc_reg_write(uc, UC_X86_REG_RDI, &snapshot.rdi);
    uc_reg_write(uc, UC_X86_REG_RBP, &snapshot.rbp);
    uc_reg_write(uc, UC_X86_REG_RSP, &snapshot.rsp);
    uc_reg_write(uc, UC_X86_REG_R8,  &snapshot.r8);
    uc_reg_write(uc, UC_X86_REG_R9,  &snapshot.r9);
    uc_reg_write(uc, UC_X86_REG_R10, &snapshot.r10);
    uc_reg_write(uc, UC_X86_REG_R11, &snapshot.r11);
    uc_reg_write(uc, UC_X86_REG_R12, &snapshot.r12);
    uc_reg_write(uc, UC_X86_REG_R13, &snapshot.r13);
    uc_reg_write(uc, UC_X86_REG_R14, &snapshot.r14);
    uc_reg_write(uc, UC_X86_REG_R15, &snapshot.r15);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &snapshot.rflags);
    diag::log_tagged_fmt("emulation",
        "unicorn_registers_written rip=0x%llX rsp=0x%llX rflags=0x%llX",
        static_cast<unsigned long long>(result.start_address),
        static_cast<unsigned long long>(snapshot.rsp),
        static_cast<unsigned long long>(snapshot.rflags));


    std::uint64_t start_rip = result.start_address;


    uc_trace_ctx_t trace_ctx;
    trace_ctx.uc               = uc;
    trace_ctx.config           = &config;
    trace_ctx.mapped_code      = code_at_rip;
    trace_ctx.mapped_code_size = code_at_rip_size;
    trace_ctx.mapped_code_base = code_at_rip_base;

    std::vector<trace_entry_t> trace_log;
    std::vector<mem_write_t>   write_log;
    std::vector<mem_read_t>    read_log;
    trace_log.reserve(std::min<std::uint32_t>(config.max_trace_entries, 16384u));

    trace_ctx.trace      = &trace_log;
    trace_ctx.mem_writes = &write_log;
    trace_ctx.mem_reads  = &read_log;


    trace_entry_t initial_regs;
    initial_regs.rax = snapshot.rax; initial_regs.rbx = snapshot.rbx;
    initial_regs.rcx = snapshot.rcx; initial_regs.rdx = snapshot.rdx;
    initial_regs.rsi = snapshot.rsi; initial_regs.rdi = snapshot.rdi;
    initial_regs.rbp = snapshot.rbp; initial_regs.rsp = snapshot.rsp;
    initial_regs.r8  = snapshot.r8;  initial_regs.r9  = snapshot.r9;
    initial_regs.r10 = snapshot.r10; initial_regs.r11 = snapshot.r11;
    initial_regs.r12 = snapshot.r12; initial_regs.r13 = snapshot.r13;
    initial_regs.r14 = snapshot.r14; initial_regs.r15 = snapshot.r15;
    initial_regs.rip = snapshot.rip; initial_regs.rflags = snapshot.rflags;


    uc_hook h_code, h_mem_write, h_mem_read, h_mem_invalid;

    err = uc_hook_add(uc, &h_code, UC_HOOK_CODE,
                reinterpret_cast<void*>(&hook_code_cb), &trace_ctx, 1, 0);
    diag::log_tagged_fmt("emulation", "unicorn_hook_add code err=%u text='%s'", static_cast<unsigned>(err), uc_strerror(err));

    if (config.record_mem_writes)
    {
        err = uc_hook_add(uc, &h_mem_write, UC_HOOK_MEM_WRITE,
                    reinterpret_cast<void*>(&hook_mem_write_cb), &trace_ctx, 1, 0);
        diag::log_tagged_fmt("emulation", "unicorn_hook_add mem_write err=%u text='%s'", static_cast<unsigned>(err), uc_strerror(err));
    }

    if (config.record_mem_reads)
    {
        err = uc_hook_add(uc, &h_mem_read, UC_HOOK_MEM_READ,
                    reinterpret_cast<void*>(&hook_mem_read_cb), &trace_ctx, 1, 0);
        diag::log_tagged_fmt("emulation", "unicorn_hook_add mem_read err=%u text='%s'", static_cast<unsigned>(err), uc_strerror(err));
    }


    err = uc_hook_add(uc, &h_mem_invalid,
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                reinterpret_cast<void*>(&hook_mem_invalid_cb), &trace_ctx, 1, 0);
    diag::log_tagged_fmt("emulation", "unicorn_hook_add mem_invalid err=%u text='%s'", static_cast<unsigned>(err), uc_strerror(err));

    if (emu_cancelled(&config, "unicorn_before_start")) {
        result.error = "Emulation cancelled before start";
        return result;
    }
    std::string start_failure;
    if (!unicorn_emu_start_checked(uc, start_rip, config.stop_address ? config.stop_address : 0xFFFFFFFFFFFFFFFFULL,
                                   config.timeout_us, config.max_instructions, &config, err, start_failure)) {
        result.error = start_failure;
        return result;
    }
    diag::log_tagged_fmt("emulation",
        "unicorn_start_result err=%u text='%s' cancelled=%d insn_count=%u invalid_maps=%u hit_ret=%d hit_bp=%d",
        static_cast<unsigned>(err),
        uc_strerror(err),
        trace_ctx.cancelled ? 1 : 0,
        trace_ctx.insn_count,
        trace_ctx.invalid_page_maps,
        trace_ctx.hit_ret ? 1 : 0,
        trace_ctx.hit_bp ? 1 : 0);


    std::uint64_t final_rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &final_rip);

    result.end_address        = final_rip;
    result.total_instructions = trace_ctx.insn_count;
    result.trace              = std::move(trace_log);
    result.mem_writes         = std::move(write_log);
    result.mem_reads          = std::move(read_log);
    result.hit_ret            = trace_ctx.hit_ret;
    result.hit_breakpoint     = trace_ctx.hit_bp;


    trace_entry_t final_regs;
    uc_read_regs(uc, final_regs);

    auto add_delta = [&](const char* name, std::uint64_t before, std::uint64_t after) {
        if (before != after)
            result.reg_deltas.push_back({name, before, after});
    };

    add_delta("RAX", initial_regs.rax, final_regs.rax);
    add_delta("RBX", initial_regs.rbx, final_regs.rbx);
    add_delta("RCX", initial_regs.rcx, final_regs.rcx);
    add_delta("RDX", initial_regs.rdx, final_regs.rdx);
    add_delta("RSI", initial_regs.rsi, final_regs.rsi);
    add_delta("RDI", initial_regs.rdi, final_regs.rdi);
    add_delta("RBP", initial_regs.rbp, final_regs.rbp);
    add_delta("RSP", initial_regs.rsp, final_regs.rsp);
    add_delta("R8",  initial_regs.r8,  final_regs.r8);
    add_delta("R9",  initial_regs.r9,  final_regs.r9);
    add_delta("R10", initial_regs.r10, final_regs.r10);
    add_delta("R11", initial_regs.r11, final_regs.r11);
    add_delta("R12", initial_regs.r12, final_regs.r12);
    add_delta("R13", initial_regs.r13, final_regs.r13);
    add_delta("R14", initial_regs.r14, final_regs.r14);
    add_delta("R15", initial_regs.r15, final_regs.r15);
    add_delta("RFLAGS", initial_regs.rflags, final_regs.rflags);


    if (config.analyze_effective_ops)
    {
        auto analysis = analyze_vm_trace(result);
        result.effective_ops          = std::move(analysis.effective_ops);
        result.junk_instruction_count = analysis.junk_instructions;
    }

    if (trace_ctx.cancelled || emu_cancelled(&config, "unicorn_after_start"))
    {
        result.error = "Emulation cancelled";
        result.success = false;
        diag::log_tagged_fmt("emulation",
            "emulate_from_snapshot exit success=0 cancelled=1 total=%u trace=%zu reads=%zu writes=%zu",
            result.total_instructions,
            result.trace.size(),
            result.mem_reads.size(),
            result.mem_writes.size());
        return result;
    }

    if (err != UC_ERR_OK && !trace_ctx.hit_ret && !trace_ctx.hit_bp &&
        trace_ctx.insn_count < config.max_instructions)
    {
        result.error = std::string("Emulation stopped: ") + uc_strerror(err);
    }

    result.success = true;
    diag::log_tagged_fmt("emulation",
        "emulate_from_snapshot exit success=1 end=0x%llX total=%u trace=%zu reads=%zu writes=%zu reg_deltas=%zu error='%s'",
        static_cast<unsigned long long>(result.end_address),
        result.total_instructions,
        result.trace.size(),
        result.mem_reads.size(),
        result.mem_writes.size(),
        result.reg_deltas.size(),
        result.error.c_str());
    return result;
}

emulation_result_t driver_snapshot_and_emulate(
    std::uint32_t pid,
    std::uint32_t tid,
    const emulation_config_t& config,
    std::uint64_t snapshot_base,
    std::uint64_t snapshot_size)
{
    const std::uint64_t total_begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate entry pid=%u tid=%u snapshot_base=0x%llX snapshot_size=0x%llX start=0x%llX deadline_ms=%llu",
        pid,
        tid,
        static_cast<unsigned long long>(snapshot_base),
        static_cast<unsigned long long>(snapshot_size),
        static_cast<unsigned long long>(config.start_address),
        static_cast<unsigned long long>(config.deadline_ms));
    if (emu_cancelled(&config, "snapshot_and_emulate_entry")) {
        emulation_result_t fail;
        fail.error = "Cancelled before snapshot";
        return fail;
    }
    const std::uint64_t snapshot_begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate snapshot_begin pid=%u tid=%u deadline_remaining_ms=%llu",
        pid,
        tid,
        static_cast<unsigned long long>(emu_deadline_remaining_ms(&config)));
    auto snapshot = driver_snapshot(pid, tid, snapshot_base, snapshot_size, &config);
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate snapshot_end pid=%u tid=%u success=%d regions=%zu bytes=%llu elapsed_ms=%llu deadline_remaining_ms=%llu error='%s'",
        pid,
        tid,
        snapshot.success ? 1 : 0,
        snapshot.regions.size(),
        static_cast<unsigned long long>(snapshot.total_snapshot_bytes),
        static_cast<unsigned long long>(emu_now_ms() - snapshot_begin),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(&config)),
        snapshot.error.c_str());
    if (!snapshot.success)
    {
        emulation_result_t fail;
        fail.error = "Snapshot failed: " + snapshot.error;
        diag::log_tagged_fmt("emulation", "driver_snapshot_and_emulate snapshot_failed error='%s'", fail.error.c_str());
        return fail;
    }

    if (emu_cancelled(&config, "snapshot_and_emulate_before_prepare")) {
        emulation_result_t fail;
        fail.error = "Cancelled before snapshot preparation";
        return fail;
    }
    const std::uint64_t prepare_begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate prepare_begin regions=%zu deadline_remaining_ms=%llu",
        snapshot.regions.size(),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(&config)));
    prepare_snapshot_for_config(snapshot, config);
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate prepare_end regions=%zu bytes=%llu elapsed_ms=%llu deadline_remaining_ms=%llu",
        snapshot.regions.size(),
        static_cast<unsigned long long>(snapshot.total_snapshot_bytes),
        static_cast<unsigned long long>(emu_now_ms() - prepare_begin),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(&config)));
    if (emu_cancelled(&config, "snapshot_and_emulate_before_unicorn")) {
        emulation_result_t fail;
        fail.error = "Cancelled after snapshot";
        return fail;
    }
    const std::uint64_t emulate_begin = emu_now_ms();
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate unicorn_begin start=0x%llX deadline_remaining_ms=%llu",
        static_cast<unsigned long long>(config.start_address),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(&config)));
    auto result = emulate_from_snapshot(snapshot, config);
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate unicorn_end success=%d error='%s' total=%u trace=%zu elapsed_ms=%llu deadline_remaining_ms=%llu",
        result.success ? 1 : 0,
        result.error.c_str(),
        result.total_instructions,
        result.trace.size(),
        static_cast<unsigned long long>(emu_now_ms() - emulate_begin),
        static_cast<unsigned long long>(emu_deadline_remaining_ms(&config)));
    diag::log_tagged_fmt("emulation",
        "driver_snapshot_and_emulate exit success=%d error='%s' total=%u trace=%zu elapsed_ms=%llu",
        result.success ? 1 : 0,
        result.error.c_str(),
        result.total_instructions,
        result.trace.size(),
        static_cast<unsigned long long>(emu_now_ms() - total_begin));
    return result;
}


vm_analysis_result_t analyze_vm_trace(const emulation_result_t& result)
{
    vm_analysis_result_t analysis;
    analysis.total_instructions = result.total_instructions;

    if (result.trace.empty())
    {
        analysis.summary = "Empty trace";
        return analysis;
    }


    std::unordered_set<std::string> globally_changed_regs;
    for (const auto& d : result.reg_deltas)
        globally_changed_regs.insert(d.name);


    std::unordered_set<std::uint64_t> net_write_addresses;
    for (const auto& w : result.mem_writes)
        net_write_addresses.insert(w.address);


    ensure_zydis_init();

    std::uint32_t junk_count = 0;
    std::uint32_t effective_count = 0;


    auto is_junk_pattern = [](const std::string& disasm) -> bool {
        if (disasm.empty()) return false;


        if (disasm.find("nop") == 0) return true;


        if (disasm == "xchg eax, eax") return true;


        if (disasm.find("lea") == 0 && disasm.find("+0x0]") != std::string::npos)
            return true;


        if (disasm.find("mov") == 0)
        {
            auto comma = disasm.find(',');
            if (comma != std::string::npos)
            {
                std::string dest = disasm.substr(4, comma - 4);
                std::string src  = disasm.substr(comma + 2);

                while (!dest.empty() && dest.back() == ' ') dest.pop_back();
                while (!src.empty() && src.front() == ' ') src.erase(src.begin());
                if (dest == src) return true;
            }
        }

        return false;
    };

    for (const auto& entry : result.trace)
    {
        if (is_junk_pattern(entry.disasm))
        {
            ++junk_count;
        }
        else
        {
            ++effective_count;


            if (analysis.effective_ops.size() < 256)
            {
                std::ostringstream ss;
                ss << "0x" << std::hex << entry.address << ": " << entry.disasm;
                analysis.effective_ops.push_back(ss.str());
            }
        }
    }

    analysis.junk_instructions      = junk_count;
    analysis.effective_instructions = effective_count;
    analysis.net_reg_changes        = result.reg_deltas;
    analysis.net_mem_writes         = result.mem_writes;


    std::ostringstream summary;
    summary << "Traced " << analysis.total_instructions << " instructions: "
            << analysis.effective_instructions << " effective, "
            << analysis.junk_instructions << " junk ("
            << (analysis.total_instructions > 0
                ? static_cast<int>(100.0 * analysis.junk_instructions / analysis.total_instructions)
                : 0)
            << "% noise). ";

    if (!result.reg_deltas.empty())
    {
        summary << "Net register changes: ";
        for (std::size_t i = 0; i < result.reg_deltas.size(); ++i)
        {
            if (i > 0) summary << ", ";
            summary << result.reg_deltas[i].name
                    << " (0x" << std::hex << result.reg_deltas[i].before
                    << " -> 0x" << result.reg_deltas[i].after << ")";
        }
        summary << ". ";
    }

    if (!result.mem_writes.empty())
    {
        summary << std::dec << result.mem_writes.size() << " memory write(s) to "
                << net_write_addresses.size() << " unique address(es).";
    }

    analysis.summary = summary.str();
    return analysis;
}

}

#endif
