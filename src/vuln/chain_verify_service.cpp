#include "chain_verify_service.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <deque>
#include <exception>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <auto.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <xref.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "../ida_utils.hpp"
#include "aida_ipc.hpp"
#include "chain_report_view.hpp"
#include "chain_state_contracts.hpp"
#include "chain_verification_engine.hpp"
#include "ida_gateway.hpp"

namespace aida
{
namespace vuln
{
namespace
{

constexpr const char* k_journal_node = "$ AiDA.chain.verify.service.v1";
constexpr nodeidx_t k_journal_blob_index = 1;
constexpr uchar k_journal_blob_tag = 'J';
constexpr std::size_t k_max_queue_depth = 4;
constexpr std::size_t k_max_document_bytes = 4 * 1024 * 1024;
constexpr std::size_t k_max_result_bytes = 16 * 1024 * 1024;
constexpr std::size_t k_max_events = 64;
constexpr std::uint32_t k_gateway_fast_deadline_ms = 1500;
constexpr std::uint32_t k_gateway_read_deadline_ms = 5000;
constexpr std::uint32_t k_gateway_write_deadline_ms = 5000;

std::uint64_t wall_ms()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::uint64_t steady_ms()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::string format_ea(ea_t ea)
{
    if (ea == BADADDR)
        return {};
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << static_cast<std::uint64_t>(ea);
    return oss.str();
}

std::string qstr_to_string(const qstring& value)
{
    return value.c_str() == nullptr ? std::string() : std::string(value.c_str());
}

std::string json_string_or_empty(const nlohmann::json& value, const char* key)
{
    if (!value.is_object() || !value.contains(key) || !value.at(key).is_string())
        return {};
    return value.at(key).get<std::string>();
}

std::uint64_t json_u64_or_zero(const nlohmann::json& value, const char* key)
{
    if (!value.is_object() || !value.contains(key))
        return 0;
    const nlohmann::json& item = value.at(key);
    if (item.is_number_unsigned())
        return item.get<std::uint64_t>();
    if (item.is_number_integer())
        return static_cast<std::uint64_t>(std::max<std::int64_t>(0, item.get<std::int64_t>()));
    return 0;
}

bool json_bool_or_false(const nlohmann::json& value, const char* key)
{
    return value.is_object() && value.contains(key) && value.at(key).is_boolean() && value.at(key).get<bool>();
}

chain::verification_module_snapshot_t module_snapshot_from_json(const nlohmann::json& value)
{
    chain::verification_module_snapshot_t snapshot;
    snapshot.snapshot_id = json_string_or_empty(value, "snapshot_id");
    snapshot.root_filename = json_string_or_empty(value, "root_filename");
    snapshot.input_path = json_string_or_empty(value, "input_path");
    snapshot.sha256 = json_string_or_empty(value, "sha256");
    snapshot.image_base = json_u64_or_zero(value, "image_base");
    snapshot.min_ea = json_u64_or_zero(value, "min_ea");
    snapshot.max_ea = json_u64_or_zero(value, "max_ea");
    snapshot.pointer_width_bits = static_cast<std::uint32_t>(json_u64_or_zero(value, "pointer_width_bits"));
    snapshot.processor = json_string_or_empty(value, "processor");
    snapshot.endianness = json_string_or_empty(value, "endianness");
    snapshot.dll = json_bool_or_false(value, "dll");
    snapshot.kernel_mode = json_bool_or_false(value, "kernel_mode");
    snapshot.valid = json_bool_or_false(value, "valid");
    snapshot.error = json_string_or_empty(value, "error");
    return snapshot;
}

struct function_capture_result_t
{
    bool ok = false;
    std::string error;
    std::string display;
    std::string chain_id;
    nlohmann::json document = nlohmann::json::object();
};

function_capture_result_t capture_function_document(ea_t requested_ea, const ida_gateway_context_t& ctx)
{
    function_capture_result_t out;
    ea_t ea = requested_ea != BADADDR ? requested_ea : get_screen_ea();
    if (ea == BADADDR)
    {
        out.error = "no_current_address";
        return out;
    }

    func_t* fn = get_func(ea);
    if (fn == nullptr)
    {
        out.error = "current_address_not_in_function";
        return out;
    }

    qstring function_name;
    get_func_name(&function_name, fn->start_ea);
    if (function_name.empty())
        function_name.sprnt("sub_%a", fn->start_ea);

    segment_t* seg = getseg(fn->start_ea);
    qstring seg_name;
    qstring seg_class;
    if (seg != nullptr)
    {
        get_segm_name(&seg_name, seg);
        get_segm_class(&seg_class, seg);
    }

    tinfo_t type_info;
    std::string declaration;
    if (get_tinfo(&type_info, fn->start_ea))
    {
        const char* type_text = type_info.dstr();
        if (type_text != nullptr)
            declaration = type_text;
    }

    std::size_t xrefs_from = 0;
    std::size_t xrefs_to = 0;
    nlohmann::json sample_xrefs = nlohmann::json::array();
    func_item_iterator_t fii(fn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        xrefblk_t xb;
        for (bool xok = xb.first_from(fii.current(), XREF_ALL); xok && xrefs_from < 512; xok = xb.next_from())
        {
            if (sample_xrefs.size() < 32)
                sample_xrefs.push_back({{"from", format_ea(fii.current())}, {"to", format_ea(xb.to)}, {"type", xb.type}, {"iscode", xb.iscode != 0}});
            ++xrefs_from;
        }
        if (xrefs_from >= 512)
            break;
    }
    xrefblk_t xb_to;
    for (bool ok = xb_to.first_to(fn->start_ea, XREF_ALL); ok && xrefs_to < 512; ok = xb_to.next_to())
        ++xrefs_to;

    char root[MAXSTR] = {};
    char input_path[QMAXPATH] = {};
    char proc[IDAINFO_PROCNAME_SIZE] = {};
    get_root_filename(root, sizeof(root));
    get_input_file_path(input_path, sizeof(input_path));
    inf_get_procname(proc, sizeof(proc));

    const std::string ea_text = format_ea(fn->start_ea);
    const std::string end_text = format_ea(fn->end_ea);
    const std::string function_text = qstr_to_string(function_name);
    out.chain_id = "ui_current_function_" + chain::stable_hash_hex(function_text + ea_text + std::to_string(ctx.idb_generation));
    out.display = function_text + " " + ea_text;

    nlohmann::json evidence = {
        {"source", "ida_plugin_chain_verify_panel"},
        {"function", function_text},
        {"start_ea", ea_text},
        {"end_ea", end_text},
        {"segment", qstr_to_string(seg_name)},
        {"segment_class", qstr_to_string(seg_class)},
        {"declaration", declaration},
        {"xrefs_from_capped", xrefs_from},
        {"xrefs_to_capped", xrefs_to},
        {"sample_xrefs", sample_xrefs},
        {"auto_analysis_ready", auto_is_ok()},
        {"idb_generation", ctx.idb_generation},
        {"hexrays_generation", ctx.hexrays_generation}
    };

    out.document = {
        {"schema", "aida_chain_document_v2"},
        {"chain_id", out.chain_id},
        {"title", "Current function chain seed: " + function_text},
        {"target", {
            {"architecture", proc},
            {"platform", inf_is_kernel_mode() ? "kernel_mode" : "user_mode"},
            {"pointer_width_bits", inf_is_64bit() ? 64 : (inf_is_32bit_exactly() ? 32 : 16)}
        }},
        {"corpus", nlohmann::json::array({
            {
                {"corpus_id", "current_idb"},
                {"kind", "binary"},
                {"availability", "loaded"},
                {"identity", {
                    {"root_filename", root},
                    {"input_path", input_path},
                    {"image_base", format_ea(get_imagebase())},
                    {"min_ea", format_ea(inf_get_min_ea())},
                    {"max_ea", format_ea(inf_get_max_ea())}
                }},
                {"trust", "ida_current_idb"},
                {"chain_critical", false}
            }
        })},
        {"facts", nlohmann::json::array({
            {
                {"id", "current_function_exists"},
                {"kind", "address_fact"},
                {"subject", "current_function"},
                {"predicate", "exists"},
                {"value", {{"ea", ea_text}, {"function", function_text}}},
                {"proof_state", "proven"},
                {"criticality", "chain_critical"}
            }
        })},
        {"links", nlohmann::json::array({
            {
                {"id", "current_function_link"},
                {"role", "function_context"},
                {"source_evidence", evidence},
                {"postconditions", nlohmann::json::array({
                    {
                        {"id", "current_function_captured"},
                        {"kind", "objective_fact"},
                        {"subject", "current_function"},
                        {"predicate", "captured"},
                        {"value", {{"achieved", true}, {"ea", ea_text}, {"function", function_text}}},
                        {"proof_state", "proven"},
                        {"criticality", "objective_critical"}
                    }
                })}
            }
        })},
        {"objectives", nlohmann::json::array({
            {
                {"id", "current_function_captured"},
                {"dimension", "final_objective"},
                {"subject", "current_function"},
                {"predicate", "captured"},
                {"required", {{"achieved", true}}}
            }
        })},
        {"policies", {
            {"source", "nonmodal_ida_plugin_panel"},
            {"legacy_wait_box_allowed", false},
            {"require_gateway_ida_access", true}
        }}
    };
    out.ok = true;
    return out;
}

struct service_idb_listener_t;

}

struct chain_verifier_service_t::impl_t : public std::enable_shared_from_this<chain_verifier_service_t::impl_t>
{
    struct job_t
    {
        std::string job_id;
        std::string chain_id;
        nlohmann::json document = nlohmann::json::object();
        std::shared_ptr<std::atomic_bool> cancel_flag = std::make_shared<std::atomic_bool>(false);
        chain::cancellation_token_t chain_cancel;
        std::uint64_t idb_generation = 0;
        std::uint64_t hexrays_generation = 0;
        std::uint64_t submitted_ms = 0;
    };

    ida_gateway_t gateway;
    chain_report_view_t view;
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::deque<job_t> queue;
    std::thread worker;
    qtimer_t timer = nullptr;
    service_idb_listener_t* idb_listener = nullptr;
    std::atomic_bool started_flag{false};
    std::atomic_bool stopping{false};
    std::atomic_bool running{false};
    std::atomic_bool has_draft_flag{false};
    std::atomic_bool has_result_flag{false};
    std::atomic_bool dirty{true};
    bool idb_hooked = false;
    bool hexrays_hooked = false;
    bool late_worker = false;
    std::string status = "idle";
    std::string phase = "idle";
    std::string current_function;
    std::string active_job_id;
    std::string active_chain_id;
    std::string verdict;
    std::string error;
    nlohmann::json draft_document = nlohmann::json::object();
    nlohmann::json last_result = nlohmann::json::object();
    nlohmann::json last_journal = nlohmann::json::object();
    std::shared_ptr<std::atomic_bool> active_cancel;
    chain::cancellation_token_t active_chain_cancel;
    std::uint64_t job_idb_generation = 0;
    std::uint64_t job_hexrays_generation = 0;
    std::uint64_t job_started_steady_ms = 0;
    std::size_t progress_current = 0;
    std::size_t progress_total = 0;
    std::vector<std::string> events;

    void mark_dirty()
    {
        dirty.store(true, std::memory_order_release);
    }

    void push_event_locked(const std::string& event)
    {
        events.push_back(std::to_string(wall_ms()) + " " + event);
        if (events.size() > k_max_events)
            events.erase(events.begin(), events.begin() + static_cast<std::ptrdiff_t>(events.size() - k_max_events));
        mark_dirty();
    }

    nlohmann::json make_journal_locked(const char* reason) const
    {
        return nlohmann::json{
            {"schema", "aida.ida.chain_verify.service_journal.v1"},
            {"reason", reason ? reason : "state"},
            {"updated_ms", wall_ms()},
            {"status", status},
            {"phase", phase},
            {"job_id", active_job_id},
            {"chain_id", active_chain_id},
            {"current_function", current_function},
            {"verdict", verdict},
            {"error", error},
            {"running", running.load(std::memory_order_acquire)},
            {"stopping", stopping.load(std::memory_order_acquire)},
            {"cancelled", active_cancel && active_cancel->load(std::memory_order_acquire)},
            {"idb_generation", gateway.idb_generation()},
            {"hexrays_generation", gateway.hexrays_generation()},
            {"job_idb_generation", job_idb_generation},
            {"job_hexrays_generation", job_hexrays_generation},
            {"progress", {{"current", progress_current}, {"total", progress_total}}},
            {"has_draft", has_draft_flag.load(std::memory_order_acquire)},
            {"has_result", has_result_flag.load(std::memory_order_acquire)},
            {"draft_hash", draft_document.is_object() && !draft_document.empty() ? chain::canonical_json_hash(draft_document) : std::string()},
            {"result_hash", last_result.is_object() && !last_result.empty() ? chain::canonical_json_hash(last_result) : std::string()},
            {"events", events}
        };
    }

    chain_report_view_snapshot_t snapshot_for_view()
    {
        std::lock_guard<std::mutex> lock(mutex);
        chain_report_view_snapshot_t snapshot;
        snapshot.stopping = stopping.load(std::memory_order_acquire);
        snapshot.running = running.load(std::memory_order_acquire);
        snapshot.has_draft = has_draft_flag.load(std::memory_order_acquire);
        snapshot.has_result = has_result_flag.load(std::memory_order_acquire);
        snapshot.status = status;
        snapshot.phase = phase;
        snapshot.job_id = active_job_id;
        snapshot.chain_id = active_chain_id;
        snapshot.current_function = current_function;
        snapshot.verdict = verdict;
        snapshot.error = error;
        snapshot.idb_generation = gateway.idb_generation();
        snapshot.hexrays_generation = gateway.hexrays_generation();
        snapshot.job_idb_generation = job_idb_generation;
        snapshot.job_hexrays_generation = job_hexrays_generation;
        snapshot.elapsed_ms = job_started_steady_ms == 0 ? 0 : steady_ms() - job_started_steady_ms;
        snapshot.queue_depth = queue.size();
        snapshot.pending_gateway_requests = gateway.pending_request_ids().size();
        snapshot.progress_current = progress_current;
        snapshot.progress_total = progress_total;
        snapshot.events = events;
        snapshot.result = last_result;
        snapshot.journal = last_journal;
        snapshot.gateway_metrics = gateway.metrics_json();
        snapshot.stale = snapshot.running && (
            (job_idb_generation != 0 && job_idb_generation != snapshot.idb_generation) ||
            (job_hexrays_generation != 0 && job_hexrays_generation != snapshot.hexrays_generation));
        return snapshot;
    }

    void persist_journal(const char* reason)
    {
        nlohmann::json journal;
        {
            std::lock_guard<std::mutex> lock(mutex);
            journal = make_journal_locked(reason);
            last_journal = journal;
        }
        const std::string packed = journal.dump();
        if (packed.size() > k_max_document_bytes)
            return;

        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::netnode;
        request.phase = "journal";
        request.operation = "write_service_journal";
        request.mff_flags = MFF_WRITE;
        request.deadline_ms = k_gateway_write_deadline_ms;
        gateway.execute(request, [packed](const ida_gateway_context_t&) {
            netnode nn(k_journal_node, 0, true);
            if (nn == BADNODE)
                return nlohmann::json{{"ok", false}, {"error", "netnode_open_failed"}};
            const bool ok = nn.setblob(packed.data(), packed.size(), k_journal_blob_index, k_journal_blob_tag);
            return nlohmann::json{{"ok", ok}, {"bytes", packed.size()}};
        });
    }

    void load_journal()
    {
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::netnode;
        request.phase = "journal";
        request.operation = "load_service_journal";
        request.mff_flags = MFF_READ;
        request.deadline_ms = k_gateway_read_deadline_ms;
        ida_gateway_result_t result = gateway.execute(request, [](const ida_gateway_context_t&) {
            netnode nn(k_journal_node, 0, false);
            if (nn == BADNODE)
                return nlohmann::json{{"found", false}};
            size_t size = nn.blobsize(k_journal_blob_index, k_journal_blob_tag);
            if (size == 0 || size > k_max_document_bytes)
                return nlohmann::json{{"found", false}, {"bytes", size}};
            void* blob = nn.getblob(nullptr, &size, k_journal_blob_index, k_journal_blob_tag);
            if (blob == nullptr)
                return nlohmann::json{{"found", false}, {"error", "blob_read_failed"}};
            const std::unique_ptr<void, decltype(&qfree)> blob_guard(blob, &qfree);
            std::string text(static_cast<const char*>(blob_guard.get()),
                             static_cast<const char*>(blob_guard.get()) + size);
            try
            {
                return nlohmann::json{{"found", true}, {"journal", nlohmann::json::parse(text)}, {"bytes", size}};
            }
            catch (...)
            {
                return nlohmann::json{{"found", false}, {"error", "journal_parse_failed"}, {"bytes", size}};
            }
        });
        if (!result.ok || !result.data.value("found", false))
            return;
        std::lock_guard<std::mutex> lock(mutex);
        last_journal = result.data.value("journal", nlohmann::json::object());
        status = "recovered";
        phase = "journal_loaded";
        push_event_locked("recovery_journal_loaded");
    }

    void update_action_states()
    {
        const bool is_stopping = stopping.load(std::memory_order_acquire);
        const bool is_running = running.load(std::memory_order_acquire);
        const bool has_draft = has_draft_flag.load(std::memory_order_acquire);
        const bool has_result = has_result_flag.load(std::memory_order_acquire);
        bool has_queue = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            has_queue = !queue.empty();
        }
        update_action_state("aida:chain_verify_open_panel", is_stopping ? AST_DISABLE : AST_ENABLE);
        update_action_state("aida:chain_verify_current_function_as_link", is_stopping ? AST_DISABLE : AST_ENABLE);
        update_action_state("aida:chain_verify_start",
            (!is_stopping && has_draft && !is_running) ? AST_ENABLE : AST_DISABLE);
        update_action_state("aida:chain_verify_cancel",
            (!is_stopping && (is_running || has_queue)) ? AST_ENABLE : AST_DISABLE);
        update_action_state("aida:chain_verify_copy_result_json",
            has_result ? AST_ENABLE : AST_DISABLE);
    }

    bool open_panel()
    {
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::ui;
        request.phase = "ui";
        request.operation = "open_chain_verify_panel";
        request.mff_flags = MFF_FAST;
        request.deadline_ms = k_gateway_fast_deadline_ms;
        ida_gateway_result_t result = gateway.execute(request, [this](const ida_gateway_context_t&) {
            const bool ok = view.open();
            if (ok)
                view.render(snapshot_for_view());
            return nlohmann::json{{"ok", ok}};
        });
        std::lock_guard<std::mutex> lock(mutex);
        if (!result.ok)
        {
            status = result.deferred ? "deferred" : "error";
            phase = "open_panel";
            error = result.error;
            push_event_locked("panel_open_failed " + result.error);
            return false;
        }
        status = "ready";
        phase = "panel";
        error.clear();
        push_event_locked("panel_opened");
        return true;
    }

    bool capture_current_function(ea_t ea)
    {
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::function;
        request.phase = "capture";
        request.operation = "current_function_as_link";
        request.mff_flags = MFF_READ;
        request.deadline_ms = k_gateway_read_deadline_ms;
        request.expected_idb_generation = gateway.idb_generation();
        request.expected_hexrays_generation = gateway.hexrays_generation();
        ida_gateway_result_t result = gateway.execute(request, [ea](const ida_gateway_context_t& ctx) {
            function_capture_result_t captured = capture_function_document(ea, ctx);
            return nlohmann::json{
                {"ok", captured.ok},
                {"error", captured.error},
                {"display", captured.display},
                {"chain_id", captured.chain_id},
                {"document", captured.document}
            };
        });

        std::lock_guard<std::mutex> lock(mutex);
        phase = "capture";
        if (!result.ok || !result.data.value("ok", false))
        {
            status = result.deferred ? "deferred" : "error";
            error = result.error.empty() ? result.data.value("error", std::string("capture_failed")) : result.error;
            push_event_locked("capture_failed " + error);
            return false;
        }

        draft_document = result.data.value("document", nlohmann::json::object());
        active_chain_id = result.data.value("chain_id", std::string());
        current_function = result.data.value("display", std::string());
        has_draft_flag.store(!draft_document.empty(), std::memory_order_release);
        status = "draft_ready";
        error.clear();
        push_event_locked("current_function_captured " + current_function);
        return true;
    }

    bool enqueue_start()
    {
        job_t job;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (stopping.load(std::memory_order_acquire))
                return false;
            if (!has_draft_flag.load(std::memory_order_acquire) || draft_document.empty())
            {
                status = "idle";
                phase = "start";
                error = "no_chain_draft";
                push_event_locked("start_rejected no_chain_draft");
                return false;
            }
            const std::string dump = draft_document.dump();
            if (dump.size() > k_max_document_bytes)
            {
                status = "resource_exhausted";
                phase = "admission";
                error = "chain_document_exceeds_limit";
                push_event_locked("start_rejected document_too_large");
                return false;
            }
            if (running.load(std::memory_order_acquire) || queue.size() >= k_max_queue_depth)
            {
                status = "busy";
                phase = "admission";
                error = "verifier_queue_busy";
                push_event_locked("start_rejected busy");
                return false;
            }
            job.document = draft_document;
            job.chain_id = active_chain_id.empty() ? draft_document.value("chain_id", std::string("chain")) : active_chain_id;
            job.job_id = "ui_job_" + chain::stable_hash_hex(job.chain_id + std::to_string(wall_ms()));
            job.idb_generation = gateway.idb_generation();
            job.hexrays_generation = gateway.hexrays_generation();
            job.submitted_ms = wall_ms();
            queue.push_back(job);
            status = "queued";
            phase = "queued";
            active_job_id = job.job_id;
            active_chain_id = job.chain_id;
            error.clear();
            push_event_locked("job_queued " + job.job_id);
        }
        cv.notify_all();
        persist_journal("job_queued");
        return true;
    }

    void cancel_active()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (active_cancel)
                active_cancel->store(true, std::memory_order_release);
            active_chain_cancel.cancel();
            for (job_t& job : queue)
            {
                job.cancel_flag->store(true, std::memory_order_release);
                job.chain_cancel.cancel();
            }
            queue.clear();
            status = running.load(std::memory_order_acquire) ? "cancelling" : "cancelled";
            phase = "cancel";
            push_event_locked("cancel_requested");
        }
        gateway.cancel_all();
        cv.notify_all();
        persist_journal("cancel_requested");
    }

    void copy_result_json()
    {
        nlohmann::json copied;
        {
            std::lock_guard<std::mutex> lock(mutex);
            copied = last_result.empty() ? last_journal : last_result;
        }
        if (copied.empty())
        {
            std::lock_guard<std::mutex> lock(mutex);
            status = "idle";
            phase = "copy";
            error = "no_result_to_copy";
            push_event_locked("copy_result_rejected no_result");
            return;
        }
        const std::string text = copied.dump(2);
        ida_gateway_request_t request;
        request.domain = ida_gateway_domain_t::ui;
        request.phase = "ui";
        request.operation = "copy_result_json";
        request.mff_flags = MFF_FAST;
        request.deadline_ms = k_gateway_fast_deadline_ms;
        ida_gateway_result_t result = gateway.execute(request, [text](const ida_gateway_context_t&) {
            const bool ok = ida_utils::set_clipboard_text(qstring(text.c_str()));
            return nlohmann::json{{"ok", ok}, {"bytes", text.size()}};
        });
        std::lock_guard<std::mutex> lock(mutex);
        if (!result.ok || !result.data.value("ok", false))
        {
            status = "error";
            phase = "copy";
            error = result.error.empty() ? "clipboard_write_failed" : result.error;
            push_event_locked("copy_result_failed " + error);
            return;
        }
        status = "copied";
        phase = "copy";
        error.clear();
        push_event_locked("result_json_copied");
    }

    void process_job(job_t job)
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            running.store(true, std::memory_order_release);
            active_cancel = job.cancel_flag;
            active_chain_cancel = job.chain_cancel;
            active_job_id = job.job_id;
            active_chain_id = job.chain_id;
            job_idb_generation = job.idb_generation;
            job_hexrays_generation = job.hexrays_generation;
            job_started_steady_ms = steady_ms();
            progress_current = 0;
            progress_total = job.document.contains("links") && job.document["links"].is_array() ? job.document["links"].size() + 3 : 3;
            status = "running";
            phase = "snapshot";
            verdict.clear();
            error.clear();
            push_event_locked("job_started " + job.job_id);
        }
        persist_journal("job_started");

        if (job.idb_generation != gateway.idb_generation() || job.hexrays_generation != gateway.hexrays_generation())
        {
            nlohmann::json stale_result = {
                {"schema", "aida.ida.chain_verify.stale_job.v1"},
                {"job_id", job.job_id},
                {"chain_id", job.chain_id},
                {"submitted_idb_generation", job.idb_generation},
                {"submitted_hexrays_generation", job.hexrays_generation},
                {"current_idb_generation", gateway.idb_generation()},
                {"current_hexrays_generation", gateway.hexrays_generation()},
                {"error", "generation_changed_before_execution"}
            };
            {
                std::lock_guard<std::mutex> lock(mutex);
                last_result = stale_result;
                has_result_flag.store(true, std::memory_order_release);
                verdict = "stale_generation";
                status = "abandoned";
                phase = "stale_generation";
                error = "generation_changed_before_execution";
                running.store(false, std::memory_order_release);
                active_cancel.reset();
                job_started_steady_ms = 0;
                push_event_locked("job_abandoned_stale_generation " + job.job_id);
            }
            persist_journal("job_abandoned_stale_generation");
            return;
        }

        ida_gateway_result_t snapshot_result = gateway.capture_idb_snapshot(job.cancel_flag, k_gateway_read_deadline_ms);
        chain::verification_module_snapshot_t module_snapshot;
        if (snapshot_result.ok)
            module_snapshot = module_snapshot_from_json(snapshot_result.data);

        {
            std::lock_guard<std::mutex> lock(mutex);
            progress_current = 1;
            phase = "verify";
            if (!snapshot_result.ok)
                push_event_locked("snapshot_unavailable " + snapshot_result.error);
            else
                push_event_locked("snapshot_captured " + module_snapshot.snapshot_id);
        }

        chain::verification_request_t request;
        request.document = job.document;
        request.capture_idb_snapshot = false;
        request.cancellation = job.chain_cancel;
        if (job.cancel_flag->load(std::memory_order_acquire))
            request.cancellation.cancel();

        chain::verification_report_t report;
        try
        {
            report = chain::engine().verify(request);
            if (module_snapshot.valid)
                report.module_snapshot = module_snapshot;
        }
        catch (const std::exception& ex)
        {
            report.chain_id = job.chain_id;
            report.job.job_id = job.job_id;
            report.job.chain_id = job.chain_id;
            report.job.status = "exception";
            report.verdict = chain::chain_verdict_t::unsupported;
            report.diagnostics["exception"] = ex.what();
        }
        catch (...)
        {
            report.chain_id = job.chain_id;
            report.job.job_id = job.job_id;
            report.job.chain_id = job.chain_id;
            report.job.status = "exception";
            report.verdict = chain::chain_verdict_t::unsupported;
            report.diagnostics["exception"] = "unknown_exception";
        }

        if (job.cancel_flag->load(std::memory_order_acquire))
        {
            report.job.status = "cancelled";
            report.job.partial = true;
            report.diagnostics["cancelled_by_service"] = true;
        }

        const bool stale_publish = job.idb_generation != gateway.idb_generation() || job.hexrays_generation != gateway.hexrays_generation();
        if (stale_publish)
        {
            report.job.status = "abandoned";
            report.job.partial = true;
            report.diagnostics["stale_generation"] = true;
        }

        nlohmann::json result_json = chain::to_json(report);
        result_json["service"] = {
            {"job_id", job.job_id},
            {"submitted_ms", job.submitted_ms},
            {"completed_ms", wall_ms()},
            {"idb_generation", job.idb_generation},
            {"hexrays_generation", job.hexrays_generation},
            {"gateway_snapshot", snapshot_result.data},
            {"gateway_snapshot_error", snapshot_result.error},
            {"legacy_wait_box_allowed", false}
        };

        const std::string dumped = result_json.dump();
        {
            std::lock_guard<std::mutex> lock(mutex);
            progress_current = progress_total;
            phase = "report";
            if (dumped.size() > k_max_result_bytes)
            {
                last_result = {
                    {"schema", "aida.ida.chain_verify.result_overflow.v1"},
                    {"job_id", job.job_id},
                    {"chain_id", job.chain_id},
                    {"bytes", dumped.size()},
                    {"error", "result_exceeds_memory_limit"}
                };
                verdict = "resource_exhausted";
                status = "resource_exhausted";
                error = "result_exceeds_memory_limit";
                push_event_locked("job_result_too_large " + job.job_id);
            }
            else
            {
                last_result = result_json;
                verdict = result_json.value("verdict", std::string());
                status = stale_publish ? "abandoned" : (job.cancel_flag->load(std::memory_order_acquire) ? "cancelled" : "completed");
                error = stale_publish ? "generation_changed_before_publish" : std::string();
                push_event_locked("job_completed " + job.job_id + " verdict=" + verdict);
            }
            has_result_flag.store(true, std::memory_order_release);
            running.store(false, std::memory_order_release);
            active_cancel.reset();
            job_started_steady_ms = 0;
        }
        persist_journal(job.cancel_flag->load(std::memory_order_acquire) ? "job_cancelled" : "job_completed");
    }

    void worker_loop()
    {
        for (;;)
        {
            job_t job;
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [this]() { return stopping.load(std::memory_order_acquire) || !queue.empty(); });
                if (stopping.load(std::memory_order_acquire) && queue.empty())
                    break;
                job = queue.front();
                queue.pop_front();
            }
            if (job.cancel_flag->load(std::memory_order_acquire))
                continue;
            process_job(job);
        }
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (running.load(std::memory_order_acquire))
                running.store(false, std::memory_order_release);
            status = stopping.load(std::memory_order_acquire) ? "stopped" : status;
            phase = stopping.load(std::memory_order_acquire) ? "stopped" : phase;
            push_event_locked("worker_exit");
        }
    }

    void handle_generation_event(bool idb, const char* reason)
    {
        const std::uint64_t generation = idb ? gateway.bump_idb_generation(reason) : gateway.bump_hexrays_generation(reason);
        bool should_cancel = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (running.load(std::memory_order_acquire))
            {
                should_cancel = true;
                if (active_cancel)
                    active_cancel->store(true, std::memory_order_release);
                active_chain_cancel.cancel();
                status = "abandoning";
                phase = idb ? "idb_generation_changed" : "hexrays_generation_changed";
            }
            if (!queue.empty())
            {
                for (job_t& job : queue)
                {
                    job.cancel_flag->store(true, std::memory_order_release);
                    job.chain_cancel.cancel();
                }
                queue.clear();
                should_cancel = true;
                status = "abandoning";
                phase = idb ? "idb_generation_changed" : "hexrays_generation_changed";
            }
            push_event_locked(std::string(idb ? "idb_generation " : "hexrays_generation ") + reason + "=" + std::to_string(generation));
        }
        if (should_cancel)
        {
            gateway.cancel_all();
            cv.notify_all();
            persist_journal(idb ? "idb_generation_changed" : "hexrays_generation_changed");
        }
    }

    ssize_t on_idb_event(ssize_t code)
    {
        switch (static_cast<idb_event::event_code_t>(code))
        {
        case idb_event::closebase:
            stopping.store(true, std::memory_order_release);
            cancel_active();
            handle_generation_event(true, "closebase");
            break;
        case idb_event::auto_empty:
        case idb_event::auto_empty_finally:
            handle_generation_event(true, "auto_empty");
            break;
        case idb_event::ti_changed:
        case idb_event::op_ti_changed:
        case idb_event::op_type_changed:
        case idb_event::segm_added:
        case idb_event::segm_deleted:
        case idb_event::segm_start_changed:
        case idb_event::segm_end_changed:
        case idb_event::segm_name_changed:
        case idb_event::segm_class_changed:
        case idb_event::segm_attrs_updated:
        case idb_event::segm_moved:
        case idb_event::allsegs_moved:
        case idb_event::func_added:
        case idb_event::func_updated:
        case idb_event::deleting_func:
        case idb_event::func_deleted:
        case idb_event::func_tail_appended:
        case idb_event::func_tail_deleted:
        case idb_event::tail_owner_changed:
        case idb_event::func_noret_changed:
        case idb_event::stkpnts_changed:
        case idb_event::make_code:
        case idb_event::make_data:
        case idb_event::destroyed_items:
        case idb_event::renamed:
        case idb_event::byte_patched:
        case idb_event::cmt_changed:
        case idb_event::range_cmt_changed:
        case idb_event::extra_cmt_changed:
        case idb_event::local_types_changed:
        case idb_event::frame_created:
        case idb_event::frame_deleted:
        case idb_event::frame_udm_created:
        case idb_event::frame_udm_deleted:
        case idb_event::frame_udm_renamed:
        case idb_event::frame_udm_changed:
        case idb_event::frame_expanded:
            handle_generation_event(true, "idb_mutation");
            break;
        default:
            break;
        }
        return 0;
    }

    void on_hexrays_event(hexrays_event_t)
    {
        handle_generation_event(false, "hexrays_event");
    }
};

namespace
{

struct service_idb_listener_t : event_listener_t
{
    std::weak_ptr<chain_verifier_service_t::impl_t> owner;

    ssize_t idaapi on_event(ssize_t code, va_list) override
    {
        std::shared_ptr<chain_verifier_service_t::impl_t> impl = owner.lock();
        return impl ? impl->on_idb_event(code) : 0;
    }
};

ssize_t idaapi chain_hexrays_callback(void* ud, hexrays_event_t event, va_list)
{
    auto* impl = static_cast<chain_verifier_service_t::impl_t*>(ud);
    if (impl != nullptr)
        impl->on_hexrays_event(event);
    return 0;
}

int idaapi chain_service_timer(void* ud)
{
    auto* impl = static_cast<chain_verifier_service_t::impl_t*>(ud);
    if (impl == nullptr || impl->stopping.load(std::memory_order_acquire))
        return -1;
    chain_report_view_snapshot_t snapshot = impl->snapshot_for_view();
    ida_gateway_request_t request;
    request.domain = ida_gateway_domain_t::ui;
    request.phase = "ui";
    request.operation = "progress_drain";
    request.mff_flags = MFF_FAST;
    request.deadline_ms = k_gateway_fast_deadline_ms;
    impl->gateway.execute(request, [impl, snapshot](const ida_gateway_context_t&) {
        if (impl->view.is_open())
            impl->view.render(snapshot);
        impl->update_action_states();
        return nlohmann::json{{"ok", true}};
    });
    impl->dirty.store(false, std::memory_order_release);
    return 200;
}

}

chain_verifier_service_t::chain_verifier_service_t()
    : m_impl(std::make_shared<impl_t>())
{
    auto* listener = new service_idb_listener_t();
    listener->owner = m_impl;
    m_impl->idb_listener = listener;
}

chain_verifier_service_t::~chain_verifier_service_t()
{
    stop(4000);
    delete m_impl->idb_listener;
    m_impl->idb_listener = nullptr;
}

bool chain_verifier_service_t::start()
{
    if (m_impl->started_flag.load(std::memory_order_acquire))
        return true;
    m_impl->stopping.store(false, std::memory_order_release);
    m_impl->gateway.start();
    m_impl->load_journal();

    if (m_impl->idb_listener != nullptr && ::hook_event_listener(HT_IDB, m_impl->idb_listener, nullptr))
        m_impl->idb_hooked = true;

    if (init_hexrays_plugin() && install_hexrays_callback(chain_hexrays_callback, m_impl.get()))
        m_impl->hexrays_hooked = true;

    try
    {
        std::shared_ptr<impl_t> keepalive = m_impl;
        m_impl->worker = std::thread([keepalive]() {
            try
            {
                keepalive->worker_loop();
            }
            catch (const std::exception& ex)
            {
                std::lock_guard<std::mutex> lock(keepalive->mutex);
                keepalive->running.store(false, std::memory_order_release);
                keepalive->status = "worker_exception";
                keepalive->phase = "worker";
                keepalive->error = ex.what();
                keepalive->push_event_locked("worker_exception");
            }
            catch (...)
            {
                std::lock_guard<std::mutex> lock(keepalive->mutex);
                keepalive->running.store(false, std::memory_order_release);
                keepalive->status = "worker_exception";
                keepalive->phase = "worker";
                keepalive->error = "unknown_exception";
                keepalive->push_event_locked("worker_unknown_exception");
            }
        });
    }
    catch (const std::exception& ex)
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->status = "start_failed";
        m_impl->phase = "worker_start";
        m_impl->error = ex.what();
        m_impl->push_event_locked("worker_start_failed");
        return false;
    }
    catch (...)
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->status = "start_failed";
        m_impl->phase = "worker_start";
        m_impl->error = "unknown_exception";
        m_impl->push_event_locked("worker_start_unknown_failed");
        return false;
    }

    m_impl->timer = register_timer(200, chain_service_timer, m_impl.get());
    if (m_impl->timer == nullptr)
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->status = "start_failed";
        m_impl->phase = "timer";
        m_impl->error = "register_timer_failed";
        m_impl->push_event_locked("timer_start_failed");
        return false;
    }
    m_impl->started_flag.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->status = "ready";
        m_impl->phase = "idle";
        m_impl->push_event_locked("service_started");
    }
    m_impl->persist_journal("service_started");
    return true;
}

void chain_verifier_service_t::stop(std::uint32_t join_timeout_ms)
{
    const bool was_started = m_impl->started_flag.exchange(false, std::memory_order_acq_rel);
    if (!was_started
        && !m_impl->worker.joinable()
        && m_impl->timer == nullptr
        && !m_impl->idb_hooked
        && !m_impl->hexrays_hooked)
    {
        m_impl->gateway.stop();
        return;
    }

    m_impl->stopping.store(true, std::memory_order_release);
    m_impl->cancel_active();

    if (m_impl->timer != nullptr)
    {
        unregister_timer(m_impl->timer);
        m_impl->timer = nullptr;
    }

    if (m_impl->hexrays_hooked)
    {
        remove_hexrays_callback(chain_hexrays_callback, m_impl.get());
        m_impl->hexrays_hooked = false;
    }
    if (m_impl->idb_hooked && m_impl->idb_listener != nullptr)
    {
        unhook_event_listener(HT_IDB, m_impl->idb_listener);
        m_impl->idb_hooked = false;
    }

    ida_gateway_request_t request;
    request.domain = ida_gateway_domain_t::ui;
    request.phase = "ui";
    request.operation = "service_stop_detach_panel";
    request.mff_flags = MFF_FAST;
    request.deadline_ms = k_gateway_fast_deadline_ms;
    request.modal_policy = ida_gateway_modal_policy_t::allow_modal;
    m_impl->gateway.execute(request, [this](const ida_gateway_context_t&) {
        m_impl->update_action_states();
        m_impl->view.detach();
        return nlohmann::json{{"ok", true}};
    });

    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        m_impl->status = "stopping";
        m_impl->phase = "join";
        m_impl->push_event_locked("service_stop_join_begin");
    }
    m_impl->cv.notify_all();

    if (m_impl->worker.joinable())
    {
#ifdef _WIN32
        HANDLE thread_handle = static_cast<HANDLE>(m_impl->worker.native_handle());
        DWORD wait_rc = WaitForSingleObject(thread_handle, join_timeout_ms);
        if (wait_rc == WAIT_OBJECT_0)
        {
            m_impl->worker.join();
            std::lock_guard<std::mutex> lock(m_impl->mutex);
            m_impl->late_worker = false;
            m_impl->status = "stopped";
            m_impl->phase = "stopped";
            m_impl->push_event_locked("service_stop_join_done");
        }
        else
        {
            m_impl->late_worker = true;
            m_impl->worker.detach();
            std::lock_guard<std::mutex> lock(m_impl->mutex);
            m_impl->status = "late_worker_preserved";
            m_impl->phase = "stopped";
            m_impl->push_event_locked("service_stop_join_timeout");
        }
#else
        m_impl->worker.join();
#endif
    }
    m_impl->persist_journal("service_stopped");
    m_impl->gateway.stop();
}

bool chain_verifier_service_t::started() const
{
    return m_impl->started_flag.load(std::memory_order_acquire);
}

action_state_t chain_verifier_service_t::action_state(chain_verify_action_kind_t kind, const action_update_ctx_t* ctx) const
{
    if (!m_impl->started_flag.load(std::memory_order_acquire) || m_impl->stopping.load(std::memory_order_acquire))
        return AST_DISABLE;

    switch (kind)
    {
    case chain_verify_action_kind_t::open_panel:
        return AST_ENABLE;
    case chain_verify_action_kind_t::current_function_as_link:
        if (ctx != nullptr && (ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE))
            return AST_ENABLE;
        return AST_DISABLE;
    case chain_verify_action_kind_t::start:
        return (m_impl->has_draft_flag.load(std::memory_order_acquire) && !m_impl->running.load(std::memory_order_acquire)) ? AST_ENABLE : AST_DISABLE;
    case chain_verify_action_kind_t::cancel:
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        return (m_impl->running.load(std::memory_order_acquire) || !m_impl->queue.empty()) ? AST_ENABLE : AST_DISABLE;
    }
    case chain_verify_action_kind_t::copy_result_json:
        return m_impl->has_result_flag.load(std::memory_order_acquire) ? AST_ENABLE : AST_DISABLE;
    default:
        return AST_DISABLE;
    }
}

void chain_verifier_service_t::activate(chain_verify_action_kind_t kind, action_activation_ctx_t* ctx)
{
    if (!m_impl->started_flag.load(std::memory_order_acquire) || m_impl->stopping.load(std::memory_order_acquire))
        return;

    switch (kind)
    {
    case chain_verify_action_kind_t::open_panel:
        m_impl->open_panel();
        break;
    case chain_verify_action_kind_t::current_function_as_link:
        m_impl->open_panel();
        m_impl->capture_current_function(ctx != nullptr ? ctx->cur_ea : BADADDR);
        m_impl->persist_journal("draft_captured");
        break;
    case chain_verify_action_kind_t::start:
        if (!m_impl->has_draft_flag.load(std::memory_order_acquire) && ctx != nullptr)
            m_impl->capture_current_function(ctx->cur_ea);
        m_impl->enqueue_start();
        break;
    case chain_verify_action_kind_t::cancel:
        m_impl->cancel_active();
        break;
    case chain_verify_action_kind_t::copy_result_json:
        m_impl->copy_result_json();
        break;
    default:
        break;
    }
    m_impl->mark_dirty();
}

int chain_verifier_service_t::timer_tick()
{
    return chain_service_timer(m_impl.get());
}

}
}
