#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "standalone_compat.hpp"
#include "game_protocol.hpp"
#include "helpers/diag_log.hpp"
#include "executor_status.hpp"
#include "../runtime/standalone_driver.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace gameproto_tools {
namespace {

int current_wsa_last_error()
{
    HMODULE ws2 = GetModuleHandleW(L"Ws2_32.dll");
    if (!ws2)
        return 0;
    using wsa_get_last_error_fn = int(__stdcall*)();
    auto fn = reinterpret_cast<wsa_get_last_error_fn>(GetProcAddress(ws2, "WSAGetLastError"));
    return fn ? fn() : 0;
}

bool process_alive_for_protocol_status(std::uint32_t pid)
{
    if (pid == 0)
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!h)
        return false;
    const DWORD wait = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return wait == WAIT_TIMEOUT;
}

std::optional<std::uint64_t> u64_from_protocol_params(const json& params, const char* name)
{
    if (!name || !params.contains(name))
        return std::nullopt;
    const auto& v = params[name];
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
        const auto n = v.get<std::int64_t>();
        if (n >= 0)
            return static_cast<std::uint64_t>(n);
    }
    if (v.is_string()) {
        std::string s = v.get<std::string>();
        char* end = nullptr;
        errno = 0;
        const unsigned long long raw = std::strtoull(s.c_str(), &end, 0);
        if (errno == 0 && end != s.c_str() && *end == '\0')
            return static_cast<std::uint64_t>(raw);
    }
    return std::nullopt;
}

std::string hex_protocol_address(std::uint64_t value)
{
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << value;
    return os.str();
}

json protocol_va_contract(const json& params, std::initializer_list<const char*> names)
{
    json out;
    out["present"] = false;
    out["field"] = nullptr;
    out["value"] = nullptr;
    out["normalized"] = nullptr;
    for (const char* name : names) {
        if (!name || !params.contains(name))
            continue;
        out["present"] = true;
        out["field"] = name;
        out["value"] = params[name];
        if (auto v = u64_from_protocol_params(params, name))
            out["normalized"] = hex_protocol_address(*v);
        return out;
    }
    return out;
}

void attach_protocol_reemit_contract(json& result, const json& params, const game_protocol::capture_options_t& options, const char* operation)
{
    if (!result.is_object())
        result = json::object();
    json c;
    c["operation"] = operation ? operation : "";
    c["descriptor_va"] = protocol_va_contract(params, {"descriptor_va", "descriptor", "protocol_descriptor_va"});
    c["emitter_va"] = protocol_va_contract(params, {"emitter_va", "emit_fn_va", "deterministic_emit_fn_va", "replay_emitter_va"});
    c["serializer_va"] = protocol_va_contract(params, {"serializer_va", "serializer_fn_va", "serialize_va"});
    c["target_pid"] = options.pid;
    c["protocol"] = options.protocol;
    c["capture_ms"] = options.capture_ms;
    c["max_packets"] = options.max_packets;
    const bool packet_count_known = result.contains("packet_count") || result.contains("observed_packet_count");
    const std::uint64_t packet_count = result.value("packet_count", result.value("observed_packet_count", 0u));
    const bool replay_output_known = result.contains("sent_packet_count");
    const bool invocation_count_known = result.contains("attempted_packet_count") || result.contains("attempted_or_sent");
    const bool replay_attempted = replay_output_known || invocation_count_known;
    const bool replay_sent_packets = replay_output_known && result.value("sent_packet_count", 0u) > 0;
    c["packet_count"] = packet_count_known ? json(packet_count) : json(nullptr);
    c["observed_capture_count"] = packet_count_known ? json(packet_count) : json(nullptr);
    c["invocation_count_known"] = result.contains("attempted_packet_count") || result.contains("attempted_or_sent");
    c["invocation_count"] = result.contains("attempted_packet_count") ? result["attempted_packet_count"] : (result.contains("attempted_or_sent") ? result["attempted_or_sent"] : json(nullptr));
    c["replay_output_count_known"] = replay_output_known;
    c["replay_output_count"] = result.contains("sent_packet_count") ? result["sent_packet_count"] : json(nullptr);
    c["packets_sent"] = result.contains("sent_packet_count") ? result["sent_packet_count"] : json(nullptr);
    c["serializer_invocation_count_known"] = result.contains("serializer_invocation_count");
    c["serializer_invocation_count"] = result.contains("serializer_invocation_count") ? result["serializer_invocation_count"] : json(nullptr);
    c["serializer_output_count_known"] = result.contains("serializer_output_count");
    c["serializer_output_count"] = result.contains("serializer_output_count") ? result["serializer_output_count"] : json(nullptr);
    c["dropped_count_known"] = result.contains("dropped_count") || result.contains("dropped_packet_count");
    c["dropped_count"] = result.contains("dropped_count") ? result["dropped_count"] : (result.contains("dropped_packet_count") ? result["dropped_packet_count"] : json(nullptr));
    c["last_error"] = result.contains("last_error") ? result["last_error"] : (result.contains("error") ? result["error"] : json(nullptr));
    c["done"] = replay_attempted ? json(true) : json(nullptr);
    c["posted"] = replay_attempted ? json(replay_sent_packets) : json(nullptr);
    c["attempts"] = invocation_count_known ? c["invocation_count"] : json(nullptr);
    c["stimulus_observed"] = result.value("stimulus_observed", false) || packet_count > 0;
    c["stimulus_source"] = replay_attempted ? "gameproto_replay" : (packet_count > 0 ? "capture_observed" : "unproven");
    c["re_emit_attempted"] = replay_attempted;
    result["protocol_re_emit_stimulus"] = c;
    diag::log_tagged_fmt("gameproto",
        "protocol_re_emit_contract operation=%s pid=%u proto=%u packet_count=%llu packet_count_known=%d re_emit_attempted=%d invocation_known=%d output_known=%d dropped_known=%d last_error_present=%d",
        operation ? operation : "",
        options.pid,
        options.protocol,
        static_cast<unsigned long long>(packet_count),
        packet_count_known ? 1 : 0,
        replay_attempted ? 1 : 0,
        c.value("invocation_count_known", false) ? 1 : 0,
        c.value("replay_output_count_known", false) ? 1 : 0,
        c.value("dropped_count_known", false) ? 1 : 0,
        c["last_error"].is_null() ? 0 : 1);
}

json protocol_runtime_status(const json& params, const game_protocol::capture_options_t& options, const char* operation)
{
    const DWORD entry_gle = GetLastError();
    const int entry_wsa_error = current_wsa_last_error();
    json j;
    DWORD handle_count = 0;
    const bool handle_count_ok = GetProcessHandleCount(GetCurrentProcess(), &handle_count) != FALSE;
    const std::vector<std::uint32_t> attached = driver_bridge::attached_pids();
    j["operation"] = operation ? operation : "";
    j["target_pid"] = options.pid;
    j["target_pid_alive"] = process_alive_for_protocol_status(options.pid);
    j["driver_loaded"] = driver_bridge::is_loaded();
    j["driver_status"] = driver_bridge::status();
    j["driver_last_error"] = driver_bridge::last_error();
    j["driver_attached_pid"] = driver_bridge::attached_pid();
    j["driver_attached_pids"] = attached;
    j["driver_attached_pid_count"] = static_cast<std::uint64_t>(attached.size());
    j["gle"] = static_cast<std::uint32_t>(entry_gle);
    j["wsa_error"] = entry_wsa_error;
    j["handle_count_ok"] = handle_count_ok;
    j["process_handle_count"] = handle_count_ok ? static_cast<std::uint32_t>(handle_count) : 0u;
    aida::network::executor_status::attach_executor_snapshots(j);
    j["selected_protocol"] = options.protocol;
    j["selected_capture_ms"] = options.capture_ms;
    j["selected_max_packets"] = options.max_packets;
    j["selected_max_payload"] = options.max_payload;
    j["selected_local_port"] = params.value("local_port", params.value("source_port", 0u));
    j["selected_remote_port"] = params.value("remote_port", params.value("target_port", 0u));
    return j;
}

void attach_protocol_stimulus_status(json& result, const json& params, const game_protocol::capture_options_t& options, const char* operation)
{
    const std::uint64_t packet_count = result.value("packet_count", result.value("observed_packet_count", 0u));
    const bool stimulus_observed = result.value("stimulus_observed", false) || packet_count > 0;
    result["stimulus_start_required"] = true;
    result["stimulus_start_operation"] = params.value("stimulus_operation", std::string("external_udp_stimulus"));
    result["stimulus_start_observed"] = stimulus_observed;
    result["zero_capture_due_to_no_stimulus"] = packet_count == 0 && !stimulus_observed;
    result["no_stimulus"] = !stimulus_observed;
    json runtime_status = protocol_runtime_status(params, options, operation);
    const bool target_pid_alive = runtime_status.value("target_pid_alive", false);
    const std::uint32_t entry_gle = runtime_status.value("gle", 0u);
    const int entry_wsa_error = runtime_status.value("wsa_error", 0);
    result["protocol_runtime_status"] = std::move(runtime_status);
    attach_protocol_reemit_contract(result, params, options, operation);
    result["diagnostic_contract"] = "zero_capture_without_stimulus_is_not_functional_capture_evidence";
    diag::log_tagged_fmt("gameproto",
        "protocol_udp_stimulus_status operation=%s target_pid=%u target_pid_alive=%d driver_attached_pid=%u protocol=%u capture_ms=%u packets=%llu stimulus_observed=%d zero_due_to_no_stimulus=%d gle=%lu wsa=%d local_port=%u remote_port=%u work_pending=%llu work_active=%u critical_pending=%llu critical_active=%u",
        operation ? operation : "",
        options.pid,
        target_pid_alive ? 1 : 0,
        driver_bridge::attached_pid(),
        options.protocol,
        options.capture_ms,
        static_cast<unsigned long long>(packet_count),
        stimulus_observed ? 1 : 0,
        (packet_count == 0 && !stimulus_observed) ? 1 : 0,
        static_cast<unsigned long>(entry_gle),
        entry_wsa_error,
        params.value("local_port", params.value("source_port", 0u)),
        params.value("remote_port", params.value("target_port", 0u)),
        static_cast<unsigned long long>(aida::network::executor_status::work_pending()),
        aida::network::executor_status::work_active(),
        static_cast<unsigned long long>(aida::network::executor_status::critical_pending()),
        aida::network::executor_status::critical_active());
}

std::uint32_t protocol_from_param(const json& params)
{
    if (params.contains("protocol") && params["protocol"].is_number()) {
        const auto v = params["protocol"].get<std::int64_t>();
        if (v >= 0 && v <= 255)
            return static_cast<std::uint32_t>(v);
    }
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (p == "tcp")
            return 6;
        if (p == "udp")
            return 17;
    }
    return 0;
}

game_protocol::capture_options_t capture_options_from_params(const json& params,
                                                             std::uint32_t default_ms,
                                                             std::uint32_t default_packets)
{
    game_protocol::capture_options_t options;
    if (params.contains("pid") && params["pid"].is_number()) {
        const auto v = params["pid"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            options.pid = static_cast<std::uint32_t>(v);
    }
    if (params.contains("filter_pid") && params["filter_pid"].is_number()) {
        const auto v = params["filter_pid"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            options.pid = static_cast<std::uint32_t>(v);
    }
    options.protocol = protocol_from_param(params);
    const double capture_sec = params.value("capture_sec", static_cast<double>(default_ms) / 1000.0);
    options.capture_ms = static_cast<std::uint32_t>((std::max)(0.1, capture_sec) * 1000.0);
    if (options.capture_ms > 15000)
        options.capture_ms = 15000;
    options.max_packets = params.value("max_packets", default_packets);
    if (options.max_packets > 512)
        options.max_packets = 512;
    options.max_payload = params.value("max_payload", 1500u);
    if (options.max_payload > 8192)
        options.max_payload = 8192;
    return options;
}

tool_result_t handle_gameproto_detect(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    auto options = capture_options_from_params(params, 5000, 64);
    if ((params.contains("payload_hex") && params["payload_hex"].is_string()) ||
        (params.contains("packet_hex") && params["packet_hex"].is_string())) {
        const std::string hex = params.contains("payload_hex") && params["payload_hex"].is_string()
            ? params["payload_hex"].get<std::string>()
            : params["packet_hex"].get<std::string>();
        if (hex.empty()) {
            json result;
            result["backend"] = "provided_payload";
            result["capture_performed"] = false;
            result["deterministic_input"] = false;
            result["packet_count"] = 0;
            result["payload_bytes"] = 0;
            result["stimulus_observed"] = false;
            result["no_stimulus"] = true;
            result["diagnostic_contract"] = "empty_provided_payload_is_not_functional_protocol_evidence";
            return tool_result_t::error(std::string("payload_hex must contain at least one byte."), result);
        }
        std::string error;
        auto bytes = game_protocol::hex_to_bytes(hex, &error, options.max_payload);
        if (bytes.empty())
            return tool_result_t::error(error.empty() ? std::string("invalid payload_hex") : error);
        driver_bridge::captured_packet_t pkt{};
        pkt.pid = options.pid;
        pkt.protocol = options.protocol == 0 ? 17 : options.protocol;
        pkt.direction = 1;
        pkt.address_family = 2;
        pkt.local_addr[0] = 127;
        pkt.local_addr[3] = 1;
        pkt.remote_addr[0] = 127;
        pkt.remote_addr[3] = 1;
        pkt.local_port = params.value("local_port", 40000u);
        pkt.remote_port = params.value("remote_port", 40001u);
        pkt.payload = std::move(bytes);
        pkt.payload_size = static_cast<std::uint32_t>(pkt.payload.size());
        std::vector<driver_bridge::captured_packet_t> packets;
        packets.push_back(std::move(pkt));
        json result = game_protocol::detect_protocols(packets, 32);
        result["backend"] = "provided_payload";
        result["capture_performed"] = false;
        result["deterministic_input"] = true;
        result["stimulus_observed"] = true;
        result["no_stimulus"] = false;
        result["filter_pid"] = options.pid;
        result["filter_protocol"] = options.protocol == 0 ? "any" : (options.protocol == 17 ? "udp" : (options.protocol == 6 ? "tcp" : std::to_string(options.protocol)));
        result["payload_bytes"] = packets.front().payload.size();
        diag::log_tagged_fmt("gameproto", "detect provided_payload bytes=%zu protocol=%u pid=%u confidence=%.3f",
            packets.front().payload.size(), packets.front().protocol, packets.front().pid, result.value("confidence", 0.0));
        return tool_result_t::ok(std::string("Game protocol detection completed from provided payload."), result);
    }
    if (options.pid == 0)
        return tool_result_t::error(std::string("'pid' is required for live protocol detection."));

    std::vector<driver_bridge::captured_packet_t> packets;
    std::string error;
    if (!game_protocol::capture_packets_bounded(options, packets, error))
        return tool_result_t::error(error.empty() ? std::string("capture failed") : error);

    json result = game_protocol::detect_protocols(packets, 32);
    result["backend"] = "driver_capture";
    result["capture_performed"] = true;
    result["capture_ms"] = options.capture_ms;
    result["pid"] = options.pid;
    result["filter_pid"] = options.pid;
    result["filter_protocol"] = options.protocol == 0 ? "any" : (options.protocol == 17 ? "udp" : (options.protocol == 6 ? "tcp" : std::to_string(options.protocol)));
    result["max_packets"] = options.max_packets;
    result["max_payload"] = options.max_payload;
    attach_protocol_stimulus_status(result, params, options, "gameproto_detect");
    diag::log_tagged_fmt("gameproto", "detect live pid=%u protocol=%u packets=%zu confidence=%.3f",
        options.pid, options.protocol, packets.size(), result.value("confidence", 0.0));
    if (packets.empty())
        return tool_result_t::error(std::string("Game protocol detection completed with zero captured packets."), result);
    return tool_result_t::ok(std::string("Game protocol detection completed."), result);
}

tool_result_t handle_gameproto_enet_decode(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    if (!params.contains("packet_hex") || !params["packet_hex"].is_string())
        return tool_result_t::error(std::string("'packet_hex' is required."));
    if (params["packet_hex"].get_ref<const std::string&>().empty())
        return tool_result_t::error(std::string("packet_hex must contain at least one byte."));
    std::string error;
    auto bytes = game_protocol::hex_to_bytes(params["packet_hex"].get<std::string>(), &error, 65536);
    if (bytes.empty())
        return tool_result_t::error(error.empty() ? std::string("invalid packet_hex") : error);

    std::optional<std::uint32_t> channel;
    if (params.contains("channel_id") && params["channel_id"].is_number()) {
        const auto v = params["channel_id"].get<std::int64_t>();
        if (v >= 0 && v <= 255)
            channel = static_cast<std::uint32_t>(v);
    }

    json result = game_protocol::decode_enet_packet(bytes, channel);
    return tool_result_t::ok(std::string("ENet packet decoded with heuristic confidence."), result);
}

tool_result_t handle_gameproto_decode_heuristic(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    if (!params.contains("payload_hex") || !params["payload_hex"].is_string())
        return tool_result_t::error(std::string("'payload_hex' is required."));
    if (params["payload_hex"].get_ref<const std::string&>().empty())
        return tool_result_t::error(std::string("payload_hex must contain at least one byte."));

    std::string error;
    auto bytes = game_protocol::hex_to_bytes(params["payload_hex"].get<std::string>(), &error, 65536);
    if (bytes.empty())
        return tool_result_t::error(error.empty() ? std::string("invalid payload_hex") : error);

    const std::string hint = params.value("context_hint", std::string());
    json result = game_protocol::decode_payload_heuristic(bytes, hint);
    return tool_result_t::ok(std::string("Payload heuristic decode completed."), result);
}

tool_result_t handle_gameproto_replay(const json& raw_params)
{
    const std::string operation = compat_action_name(raw_params);
    const json params = compat_action_payload(raw_params);
    const std::string op = operation.empty() ? params.value("operation", std::string()) : operation;

    if (op == "record") {
        auto options = capture_options_from_params(params, 5000, 128);
        if (options.protocol == 0)
            options.protocol = 17;
        std::string error;
        diag::log_tagged_fmt("gameproto", "protocol_udp_stimulus_start operation=record target_pid=%u target_pid_alive=%d driver_attached_pid=%u protocol=%u capture_ms=%u gle=%lu wsa=%d local_port=%u remote_port=%u",
            options.pid,
            process_alive_for_protocol_status(options.pid) ? 1 : 0,
            driver_bridge::attached_pid(),
            options.protocol,
            options.capture_ms,
            static_cast<unsigned long>(GetLastError()),
            current_wsa_last_error(),
            params.value("local_port", params.value("source_port", 0u)),
            params.value("remote_port", params.value("target_port", 0u)));
        json result = game_protocol::record_replay_session(options, error);
        attach_protocol_stimulus_status(result, params, options, "gameproto_replay.record");
        if (!error.empty())
            return tool_result_t::error(error, result);
        if (result.value("packet_count", 0u) == 0)
            return tool_result_t::error(std::string("Game protocol replay record completed with zero captured packets."), result);
        return tool_result_t::ok(std::string("Game protocol replay session recorded."), result);
    }

    if (op == "stop") {
        std::string error;
        json result = game_protocol::stop_replay_recording(
            params.value("session_id", std::string()),
            params.value("max_packets", 128u),
            error);
        game_protocol::capture_options_t options;
        options.pid = params.value("filter_pid", params.value("pid", 0u));
        options.protocol = protocol_from_param(params);
        if (options.protocol == 0)
            options.protocol = 17;
        attach_protocol_stimulus_status(result, params, options, "gameproto_replay.stop");
        if (!error.empty())
            return tool_result_t::error(error, result);
        if (result.value("packet_count", 0u) == 0)
            return tool_result_t::error(std::string("Game protocol replay recording stopped with zero captured packets."), result);
        return tool_result_t::ok(std::string("Game protocol replay recording stopped."), result);
    }

    if (op == "list") {
        json result = game_protocol::list_replay_sessions();
        result["operation"] = "list";
        result["requires_recorded_session"] = true;
        result["record_operation"] = "gameproto_replay operation=record";
        result["replay_requires_existing_session"] = true;
        diag::log_tagged_fmt("gameproto", "replay list sessions=%u", result.value("count", 0u));
        return tool_result_t::ok(std::string("Game protocol replay sessions listed."), result);
    }

    if (op == "replay") {
        game_protocol::replay_options_t options;
        options.session_id = params.value("session_id", std::string());
        options.target_ip = params.value("target_ip", std::string());
        options.target_port = params.value("target_port", 0u);
        options.source_port = params.value("source_port", 0u);
        options.direction = params.value("direction", std::string("outbound"));
        options.max_packets = params.value("max_packets", 32u);
        options.payload_cap = params.value("payload_cap", params.value("max_payload", 1024u));
        options.replay_delay_ms = params.value("replay_delay_ms", 0u);
        options.allow_non_loopback = params.value("allow_non_loopback", false);
        options.allow_unsafe = params.value("allow_unsafe", false);
        options.confirm_unsafe = params.value("confirm_unsafe", false);

        json result;
        std::string error;
        game_protocol::capture_options_t contract_options;
        contract_options.pid = params.value("filter_pid", params.value("pid", 0u));
        contract_options.protocol = protocol_from_param(params);
        if (contract_options.protocol == 0)
            contract_options.protocol = 17;
        contract_options.max_packets = options.max_packets;
        if (!game_protocol::replay_session(options, result, error)) {
            attach_protocol_reemit_contract(result, params, contract_options, "gameproto_replay.replay");
            return tool_result_t::error(error.empty() ? std::string("replay failed") : error, result);
        }
        attach_protocol_reemit_contract(result, params, contract_options, "gameproto_replay.replay");
        if (result.value("sent_packet_count", 0u) == 0)
            return tool_result_t::error(std::string("Game protocol replay completed without sending a packet."), result);
        return tool_result_t::ok(std::string("Game protocol replay attempted with bounded packet caps."), result);
    }

    return compat_unknown_action("gameproto_replay", op);
}

}

void register_gameproto_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged("gameproto", "register_gameproto_tools entry");

    register_compat(srv, {
        std::string("gameproto_detect"), std::string("gameproto"),
        std::string("Capture a bounded live traffic sample for a PID and return protocol confidence and packet evidence for ENet, Photon, RakNet, protobuf, gzip, and custom binary formats."),
        {{std::string("pid"), std::string("number"), std::string("Target process ID."), true},
         {std::string("capture_sec"), std::string("number"), std::string("Capture duration in seconds, default 5, max 15."), false},
         {std::string("max_packets"), std::string("number"), std::string("Maximum packets to inspect, default 64, max 512."), false},
         {std::string("protocol"), std::string("string"), std::string("Optional tcp or udp capture filter."), false},
         {std::string("payload_hex"), std::string("string"), std::string("Optional payload for deterministic local protocol detection without live capture."), false},
         {std::string("packet_hex"), std::string("string"), std::string("Alias for payload_hex."), false}},
        handle_gameproto_detect, false});

    register_compat(srv, {
        std::string("gameproto_enet_decode"), std::string("gameproto"),
        std::string("Decode ENet packet bytes into header and command components with channel, sequence, length, payload preview, confidence, and parse-stop evidence."),
        {{std::string("packet_hex"), std::string("string"), std::string("Hex-encoded ENet packet bytes."), true},
         {std::string("channel_id"), std::string("number"), std::string("Optional channel filter."), false}},
        handle_gameproto_enet_decode, true});

    register_compat(srv, {
        std::string("gameproto_decode_heuristic"), std::string("gameproto"),
        std::string("Heuristically classify fields in an unknown binary protocol payload using entropy, strings, length prefixes, protobuf wire format, numeric values, and repeated records."),
        {{std::string("payload_hex"), std::string("string"), std::string("Hex-encoded payload bytes."), true},
         {std::string("context_hint"), std::string("string"), std::string("Optional hint such as entity_update, position, or damage."), false}},
        handle_gameproto_decode_heuristic, true});

    register_compat(srv, {
        std::string("gameproto_replay"), std::string("gameproto"),
        std::string("Record, stop, list, or replay bounded captured packets. Replay requires allow_unsafe and confirm_unsafe, payload caps, packet caps, and loopback-safe targeting by default."),
        {{std::string("operation"), std::string("string"), std::string("record|stop|replay|list"), true},
         {std::string("payload"), std::string("object"), std::string("Operation-specific parameters; top-level fields are also accepted."), false},
         {std::string("session_id"), std::string("string"), std::string("Replay session ID for stop or replay."), false},
         {std::string("filter_pid"), std::string("number"), std::string("PID filter for record."), false},
         {std::string("target_ip"), std::string("string"), std::string("IPv4 replay target. Non-loopback requires allow_non_loopback."), false},
         {std::string("target_port"), std::string("number"), std::string("Replay target port."), false},
         {std::string("max_packets"), std::string("number"), std::string("Replay or capture packet cap."), false},
         {std::string("payload_cap"), std::string("number"), std::string("Maximum replay payload bytes, hard-capped at 4096."), false},
         {std::string("allow_unsafe"), std::string("boolean"), std::string("Required true for replay."), false},
         {std::string("confirm_unsafe"), std::string("boolean"), std::string("Required true for replay."), false}},
        handle_gameproto_replay, false});
}

}
