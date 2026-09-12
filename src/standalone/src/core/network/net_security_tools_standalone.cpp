


#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <wincrypt.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "../runtime/standalone_driver.hpp"
#include "net_security.hpp"
#include "cert_generator.hpp"
#include "mitm_proxy.hpp"
#include "quic_proxy.hpp"
#include "intercept/cert_profile_manager.hpp"
#include "intercept/diagnostics.hpp"
#include "intercept/instrumentation_provider.hpp"
#include "executor_status.hpp"
#include "pro.h"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
namespace net_security_tools {

#ifdef __NT__

static std::string ns_bytes_to_hex(const std::uint8_t* data, std::size_t len) {
    std::string result;
    for (std::size_t i = 0; i < len; i++) {
        char hex[4]; qsnprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    return result;
}

static std::string ns_sha256_hex(const std::uint8_t* data, std::size_t len) {
    if ((!data && len != 0) || len > 0xFFFFFFFFull)
        return {};
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hash_obj_size = 0;
    DWORD hash_len = 0;
    DWORD cb_data = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hash_obj_size), sizeof(hash_obj_size), &cb_data, 0) != 0 ||
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb_data, 0) != 0 ||
        hash_len == 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    std::vector<std::uint8_t> hash_obj(hash_obj_size);
    std::vector<std::uint8_t> hash(hash_len);
    if (BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    const bool ok = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0) == 0 &&
                    BCryptFinishHash(hHash, hash.data(), hash_len, 0) == 0;
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok ? ns_bytes_to_hex(hash.data(), hash.size()) : std::string{};
}

static std::string ns_payload_hex_param(const json& params) {
    if (params.contains("payload_hex") && params["payload_hex"].is_string())
        return params["payload_hex"].get<std::string>();
    if (params.contains("packet_hex") && params["packet_hex"].is_string())
        return params["packet_hex"].get<std::string>();
    return {};
}

static bool ns_has_payload_hex_param(const json& params) {
    return (params.contains("payload_hex") && params["payload_hex"].is_string()) ||
        (params.contains("packet_hex") && params["packet_hex"].is_string());
}

static std::string ns_quic_rejection_reason(const std::uint8_t* data, std::size_t len) {
    if (!data || len == 0)
        return "empty_payload";
    const bool long_header = (data[0] & 0x80) != 0;
    if (!long_header)
        return len > 1 ? "short_header_without_long_initial" : "short_header_missing_connection_id";
    if (len < 7)
        return "long_header_too_short";
    std::size_t pos = 5;
    const std::uint8_t dcid_len = data[pos++];
    if (pos + dcid_len > len)
        return "dcid_exceeds_payload";
    pos += dcid_len;
    if (pos >= len)
        return "missing_scid_length";
    const std::uint8_t scid_len = data[pos++];
    if (pos + scid_len > len)
        return "scid_exceeds_payload";
    pos += scid_len;
    const std::uint8_t packet_type = (data[0] >> 4) & 0x03;
    if (packet_type != 0)
        return "not_initial_long_header";
    if (pos >= len)
        return "missing_token_length";
    std::uint8_t first_byte = data[pos++];
    std::uint8_t len_bytes = static_cast<std::uint8_t>(1u << (first_byte >> 6));
    std::uint32_t token_length = first_byte & 0x3F;
    for (std::uint8_t b = 1; b < len_bytes && pos < len; ++b)
        token_length = (token_length << 8) | data[pos++];
    if (pos + token_length > len)
        return "token_exceeds_payload";
    pos += token_length;
    if (pos >= len)
        return "missing_payload_length";
    first_byte = data[pos++];
    len_bytes = static_cast<std::uint8_t>(1u << (first_byte >> 6));
    for (std::uint8_t b = 1; b < len_bytes && pos < len; ++b)
        ++pos;
    if (pos > len)
        return "payload_length_exceeds_payload";
    return "parser_rejected_unknown";
}

static bool ns_parse_quic_payload_with_offset(const std::vector<std::uint8_t>& payload,
                                              net_security::QuicAnalyzer::quic_header_t& hdr,
                                              std::size_t& offset,
                                              std::string& rejection) {
    offset = 0;
    rejection = payload.empty() ? "empty_payload" : ns_quic_rejection_reason(payload.data(), payload.size());
    if (payload.empty())
        return false;
    if (net_security::QuicAnalyzer::instance().parse_quic_header(payload.data(), payload.size(), hdr) &&
        (hdr.is_long_header || !hdr.dcid.empty())) {
        rejection.clear();
        return true;
    }
    const std::size_t scan_limit = std::min<std::size_t>(payload.size(), 96);
    for (std::size_t off = 1; off + 5 < scan_limit; ++off) {
        if ((payload[off] & 0xC0) != 0xC0)
            continue;
        net_security::QuicAnalyzer::quic_header_t candidate;
        if (!net_security::QuicAnalyzer::instance().parse_quic_header(payload.data() + off, payload.size() - off, candidate)) {
            rejection = ns_quic_rejection_reason(payload.data() + off, payload.size() - off);
            continue;
        }
        if (!candidate.is_long_header || candidate.version == 0 || candidate.dcid.empty()) {
            rejection = !candidate.is_long_header ? "candidate_not_long_header" :
                (candidate.version == 0 ? "candidate_version_zero" : "candidate_dcid_empty");
            continue;
        }
        hdr = std::move(candidate);
        offset = off;
        rejection.clear();
        return true;
    }
    return false;
}

static std::string ns_dtls_rejection_reason(const std::uint8_t* data, std::size_t len) {
    if (!data || len == 0)
        return "empty_payload";
    if (len < 13)
        return "record_too_short";
    if (data[1] != 0xFE && data[1] != 0x01)
        return "unsupported_version_family";
    if (data[0] < 20 || data[0] > 25)
        return "unsupported_content_type";
    return "parser_rejected_unknown";
}

static bool ns_parse_dtls_payload_with_offset(const std::vector<std::uint8_t>& payload,
                                              net_security::DtlsAnalyzer::dtls_record_t& rec,
                                              std::size_t& offset,
                                              std::string& rejection) {
    offset = 0;
    rejection = payload.empty() ? "empty_payload" : ns_dtls_rejection_reason(payload.data(), payload.size());
    if (payload.empty())
        return false;
    if (net_security::DtlsAnalyzer::instance().parse_dtls_record(payload.data(), payload.size(), rec)) {
        rejection.clear();
        return true;
    }
    const std::size_t scan_limit = std::min<std::size_t>(payload.size(), 96);
    for (std::size_t off = 1; off + 13 <= scan_limit; ++off) {
        if (payload[off] < 20 || payload[off] > 25)
            continue;
        if (payload[off + 1] != 0xFE && payload[off + 1] != 0x01)
            continue;
        net_security::DtlsAnalyzer::dtls_record_t candidate;
        if (!net_security::DtlsAnalyzer::instance().parse_dtls_record(payload.data() + off, payload.size() - off, candidate)) {
            rejection = ns_dtls_rejection_reason(payload.data() + off, payload.size() - off);
            continue;
        }
        rec = candidate;
        offset = off;
        rejection.clear();
        return true;
    }
    return false;
}

static std::string ns_env_var(const char* name) {
    char env_buffer[32767] = {};
    DWORD len = GetEnvironmentVariableA(name, env_buffer, static_cast<DWORD>(sizeof(env_buffer)));
    if (len == 0 || len >= sizeof(env_buffer))
        return {};
    return std::string(env_buffer, len);
}

static void ns_add_unique_path(std::vector<std::string>& paths, const std::string& path) {
    if (path.empty())
        return;
    if (std::find(paths.begin(), paths.end(), path) == paths.end())
        paths.push_back(path);
}

static std::string ns_trim_path(std::string path) {
    while (!path.empty() && (path.front() == '"' || path.front() == '\'' || path.front() == ' ' || path.front() == '\t'))
        path.erase(path.begin());
    while (!path.empty() && (path.back() == '"' || path.back() == '\'' || path.back() == ' ' || path.back() == '\t'))
        path.pop_back();
    return path;
}

static void ns_add_tshark_candidate(std::vector<std::string>& paths, const std::string& raw_path) {
    const std::string path = ns_trim_path(raw_path);
    if (path.empty())
        return;
    ns_add_unique_path(paths, path);
    std::filesystem::path fs_path(path);
    if (!fs_path.has_extension() || _stricmp(fs_path.extension().string().c_str(), ".exe") != 0)
        ns_add_unique_path(paths, (fs_path / "tshark.exe").string());
}

static void ns_add_tshark_base_candidates(std::vector<std::string>& paths, const std::filesystem::path& base) {
    if (base.empty())
        return;
    ns_add_tshark_candidate(paths, (base / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "Wireshark" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "wireshark" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "deps" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "deps" / "Wireshark" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "deps" / "wireshark" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "tools" / "Wireshark" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "third_party" / "Wireshark" / "tshark.exe").string());
    ns_add_tshark_candidate(paths, (base / "vendor" / "Wireshark" / "tshark.exe").string());
}

static std::vector<std::string> ns_tshark_search_paths() {
    std::vector<std::string> paths;
    ns_add_tshark_candidate(paths, ns_env_var("AIDA_TSHARK"));
    ns_add_tshark_candidate(paths, ns_env_var("TSHARK_PATH"));
    const std::string program_files = ns_env_var("ProgramFiles");
    if (!program_files.empty())
        ns_add_tshark_candidate(paths, program_files + "\\Wireshark\\tshark.exe");
    const std::string program_files_x86 = ns_env_var("ProgramFiles(x86)");
    if (!program_files_x86.empty())
        ns_add_tshark_candidate(paths, program_files_x86 + "\\Wireshark\\tshark.exe");
    const std::string path_env = ns_env_var("PATH");
    size_t start = 0;
    while (start <= path_env.size()) {
        const size_t end = path_env.find(';', start);
        std::string dir = path_env.substr(start, end == std::string::npos ? std::string::npos : end - start);
        ns_add_tshark_candidate(paths, dir);
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    char module_path[MAX_PATH] = {};
    DWORD module_len = GetModuleFileNameA(nullptr, module_path, MAX_PATH);
    if (module_len > 0 && module_len < MAX_PATH) {
        std::filesystem::path base = std::filesystem::path(std::string(module_path, module_len)).parent_path();
        for (int i = 0; i < 4 && !base.empty(); ++i) {
            ns_add_tshark_base_candidates(paths, base);
            base = base.parent_path();
        }
    }
    std::error_code ec;
    std::filesystem::path current = std::filesystem::current_path(ec);
    if (!ec) {
        for (int i = 0; i < 4 && !current.empty(); ++i) {
            ns_add_tshark_base_candidates(paths, current);
            current = current.parent_path();
        }
    }
    return paths;
}

static json ns_paths_to_json(const std::vector<std::string>& paths) {
    json arr = json::array();
    for (const auto& path : paths) {
        json item;
        item["path"] = path;
        std::error_code ec;
        item["exists"] = std::filesystem::exists(path, ec);
        if (ec)
            item["exists_error"] = ec.message();
        arr.push_back(std::move(item));
    }
    return arr;
}

struct ns_pcap_probe_t {
    bool exists = false;
    bool readable = false;
    bool valid = false;
    bool truncated = false;
    bool pcapng = false;
    std::uint64_t file_size = 0;
    std::uint32_t packet_count = 0;
    std::uint32_t block_count = 0;
    std::string format;
    std::string reason;
};

struct ns_keylog_probe_t {
    bool exists = false;
    bool readable = false;
    bool valid = false;
    std::uint64_t file_size = 0;
    std::uint32_t entry_count = 0;
    std::string reason;
};

static std::uint32_t ns_read_u32_le(const std::vector<std::uint8_t>& data, std::size_t off) {
    return static_cast<std::uint32_t>(data[off]) |
        (static_cast<std::uint32_t>(data[off + 1]) << 8) |
        (static_cast<std::uint32_t>(data[off + 2]) << 16) |
        (static_cast<std::uint32_t>(data[off + 3]) << 24);
}

static std::uint32_t ns_read_u32_be(const std::vector<std::uint8_t>& data, std::size_t off) {
    return (static_cast<std::uint32_t>(data[off]) << 24) |
        (static_cast<std::uint32_t>(data[off + 1]) << 16) |
        (static_cast<std::uint32_t>(data[off + 2]) << 8) |
        static_cast<std::uint32_t>(data[off + 3]);
}

static std::uint32_t ns_read_u32_ordered(const std::vector<std::uint8_t>& data, std::size_t off, bool little) {
    return little ? ns_read_u32_le(data, off) : ns_read_u32_be(data, off);
}

static bool ns_is_hex_token(const std::string& token) {
    if (token.empty() || (token.size() % 2) != 0)
        return false;
    for (char ch : token) {
        if (!std::isxdigit(static_cast<unsigned char>(ch)))
            return false;
    }
    return true;
}

static ns_pcap_probe_t ns_probe_pcap_file(const std::string& path) {
    ns_pcap_probe_t out;
    std::error_code ec;
    out.exists = std::filesystem::exists(path, ec);
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (!out.exists) {
        out.reason = "pcap file does not exist";
        return out;
    }
    out.file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (out.file_size < 4) {
        out.reason = "pcap file is shorter than a capture header";
        return out;
    }
    if (out.file_size > 64ull * 1024ull * 1024ull) {
        out.reason = "pcap fixture probe refuses files larger than 64 MiB without tshark";
        return out;
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        out.reason = "pcap file could not be opened";
        return out;
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(out.file_size));
    if (!data.empty())
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file && static_cast<std::uint64_t>(file.gcount()) != out.file_size) {
        out.reason = "pcap file read was incomplete";
        return out;
    }
    out.readable = true;
    const std::uint32_t magic_le = ns_read_u32_le(data, 0);
    if (magic_le == 0xA1B2C3D4u || magic_le == 0xA1B23C4Du ||
        magic_le == 0xD4C3B2A1u || magic_le == 0x4D3CB2A1u) {
        if (data.size() < 24) {
            out.truncated = true;
            out.reason = "pcap global header is truncated";
            return out;
        }
        const bool little = magic_le == 0xA1B2C3D4u || magic_le == 0xA1B23C4Du;
        out.format = "pcap";
        std::size_t off = 24;
        while (off < data.size()) {
            if (data.size() - off < 16) {
                out.truncated = true;
                out.reason = "pcap packet header is truncated";
                return out;
            }
            const std::uint32_t incl_len = ns_read_u32_ordered(data, off + 8, little);
            if (incl_len > data.size() - off - 16) {
                out.truncated = true;
                out.reason = "pcap packet payload exceeds file size";
                return out;
            }
            ++out.packet_count;
            off += 16 + static_cast<std::size_t>(incl_len);
        }
        out.valid = off == data.size();
        out.reason = out.valid ? (out.packet_count == 0 ? "valid empty pcap" : "valid pcap") : "pcap parser ended off boundary";
        return out;
    }
    if (magic_le == 0x0A0D0D0Au) {
        if (data.size() < 28) {
            out.truncated = true;
            out.reason = "pcapng section header is truncated";
            return out;
        }
        out.format = "pcapng";
        out.pcapng = true;
        bool little = true;
        std::size_t off = 0;
        while (off < data.size()) {
            if (data.size() - off < 12) {
                out.truncated = true;
                out.reason = "pcapng block header is truncated";
                return out;
            }
            const std::uint32_t type_le = ns_read_u32_le(data, off);
            if (type_le == 0x0A0D0D0Au && data.size() - off >= 12) {
                const std::uint32_t bom_le = ns_read_u32_le(data, off + 8);
                if (bom_le == 0x1A2B3C4Du)
                    little = true;
                else if (bom_le == 0x4D3C2B1Au)
                    little = false;
                else {
                    out.reason = "pcapng byte-order magic is invalid";
                    return out;
                }
            }
            const std::uint32_t block_type = ns_read_u32_ordered(data, off, little);
            const std::uint32_t block_len = ns_read_u32_ordered(data, off + 4, little);
            if (block_len < 12 || block_len > data.size() - off) {
                out.truncated = true;
                out.reason = "pcapng block length is invalid";
                return out;
            }
            const std::uint32_t block_len_tail = ns_read_u32_ordered(data, off + block_len - 4, little);
            if (block_len_tail != block_len) {
                out.reason = "pcapng trailing block length mismatch";
                return out;
            }
            ++out.block_count;
            if (block_type == 0x00000006u || block_type == 0x00000003u)
                ++out.packet_count;
            off += block_len;
        }
        out.valid = off == data.size() && out.block_count != 0;
        out.reason = out.valid ? (out.packet_count == 0 ? "valid empty pcapng" : "valid pcapng") : "pcapng parser ended off boundary";
        return out;
    }
    out.reason = "capture magic is not pcap or pcapng";
    return out;
}

static ns_keylog_probe_t ns_probe_keylog_file(const std::string& path) {
    ns_keylog_probe_t out;
    std::error_code ec;
    out.exists = std::filesystem::exists(path, ec);
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (!out.exists) {
        out.reason = "keylog file does not exist";
        return out;
    }
    out.file_size = static_cast<std::uint64_t>(std::filesystem::file_size(path, ec));
    if (ec) {
        out.reason = ec.message();
        return out;
    }
    if (out.file_size > 16ull * 1024ull * 1024ull) {
        out.reason = "keylog fixture probe refuses files larger than 16 MiB without tshark";
        return out;
    }
    std::ifstream file(path);
    if (!file) {
        out.reason = "keylog file could not be opened";
        return out;
    }
    out.readable = true;
    std::string line;
    while (std::getline(file, line)) {
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back())))
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream is(line);
        std::string label;
        std::string first;
        std::string second;
        is >> label >> first >> second;
        if (!label.empty() && ns_is_hex_token(first) && ns_is_hex_token(second))
            ++out.entry_count;
    }
    out.valid = true;
    out.reason = out.entry_count == 0 ? "readable keylog with no parsed entries" : "readable keylog";
    return out;
}

static json ns_pcap_probe_to_json(const ns_pcap_probe_t& probe) {
    json j;
    j["exists"] = probe.exists;
    j["readable"] = probe.readable;
    j["valid"] = probe.valid;
    j["truncated"] = probe.truncated;
    j["format"] = probe.format;
    j["pcapng"] = probe.pcapng;
    j["file_size"] = probe.file_size;
    j["packet_count"] = probe.packet_count;
    j["block_count"] = probe.block_count;
    j["reason"] = probe.reason;
    return j;
}

static json ns_keylog_probe_to_json(const ns_keylog_probe_t& probe) {
    json j;
    j["exists"] = probe.exists;
    j["readable"] = probe.readable;
    j["valid"] = probe.valid;
    j["file_size"] = probe.file_size;
    j["entry_count"] = probe.entry_count;
    j["reason"] = probe.reason;
    return j;
}

struct ns_tls_keylog_session_state_t {
    std::mutex mutex;
    std::uint64_t next_session_id = 1;
    bool active = false;
    std::uint64_t session_id = 0;
    std::uint32_t pid = 0;
    std::uint32_t poll_interval_ms = 0;
    bool append = true;
    std::string output_file;
    std::uint64_t started_ms = 0;
    std::uint64_t stopped_ms = 0;
    std::uint64_t starts = 0;
    std::uint64_t stops = 0;
    std::size_t key_count_start = 0;
    std::string last_error;
};

static ns_tls_keylog_session_state_t& ns_tls_keylog_session_state() {
    static ns_tls_keylog_session_state_t s;
    return s;
}

static std::uint64_t ns_now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

static std::uint64_t ns_json_u64_param(const json& params, const char* key, std::uint64_t fallback = 0) {
    if (!params.is_object() || !params.contains(key))
        return fallback;
    const json& v = params[key];
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
        const auto signed_value = v.get<std::int64_t>();
        return signed_value > 0 ? static_cast<std::uint64_t>(signed_value) : fallback;
    }
    if (v.is_string()) {
        try {
            return std::stoull(v.get<std::string>(), nullptr, 0);
        } catch (...) {
            return fallback;
        }
    }
    return fallback;
}

static std::uint32_t ns_json_u32_bounded_param(const json& params, const char* key,
                                               std::uint32_t fallback,
                                               std::uint32_t min_value,
                                               std::uint32_t max_value) {
    const std::uint64_t raw = ns_json_u64_param(params, key, fallback);
    const std::uint64_t bounded = std::max<std::uint64_t>(min_value, std::min<std::uint64_t>(raw, max_value));
    return static_cast<std::uint32_t>(bounded);
}

static net_security::tls_key_scan_config_t ns_key_scan_config_from_params(const json& params,
                                                                          std::uint32_t default_timeout_ms,
                                                                          std::uint32_t default_max_results) {
    net_security::tls_key_scan_config_t config;
    config.pid = params.value("pid", 0u);
    config.scan_schannel = params.value("scan_schannel", true);
    config.scan_openssl = params.value("scan_openssl", true);
    config.scan_nss = params.value("scan_nss", true);
    config.scan_boringssl = params.value("scan_boringssl", true);
    config.scan_generic = params.value("scan_generic", true);
    config.scan_tls13_structures = params.value("scan_tls13_structures", true);
    config.max_results = ns_json_u32_bounded_param(params, "max_results", default_max_results, 1, 4096);
    if (params.contains("max_keys"))
        config.max_results = ns_json_u32_bounded_param(params, "max_keys", config.max_results, 1, 4096);
    config.timeout_ms = ns_json_u32_bounded_param(params, "timeout_ms", default_timeout_ms, 250, 60000);
    config.max_regions = ns_json_u32_bounded_param(params, "max_regions", 0, 0, 1000000);
    config.max_read_attempts = ns_json_u32_bounded_param(params, "max_read_attempts", 0, 0, 10000000);
    config.max_read_bytes = ns_json_u64_param(params, "max_read_bytes", 0);
    config.hint_address = ns_json_u64_param(params, "hint_address", 0);
    if (config.hint_address == 0)
        config.hint_address = ns_json_u64_param(params, "memory_hint_address", 0);
    config.hint_size = ns_json_u32_bounded_param(params, "hint_size", 0, 0, 0x10000000);
    if (config.hint_size == 0)
        config.hint_size = ns_json_u32_bounded_param(params, "memory_hint_size", 0, 0, 0x10000000);
    config.hint_only = params.value("hint_only", false) || params.value("memory_hint_only", false);
    return config;
}

static json ns_key_scan_diag_json(const net_security::key_scan_diagnostics_t& d) {
    json j;
    j["requested_pid"] = d.requested_pid;
    j["effective_pid"] = d.effective_pid;
    j["attached_pid"] = d.attached_pid;
    j["timeout_ms"] = d.timeout_ms;
    j["max_results"] = d.max_results;
    j["max_regions"] = d.max_regions;
    j["max_read_attempts"] = d.max_read_attempts;
    j["max_read_bytes"] = d.max_read_bytes;
    j["hint_address"] = d.hint_address;
    j["hint_size"] = d.hint_size;
    j["hint_only"] = d.hint_only;
    j["hint_used"] = d.hint_used;
    j["deadline_expired"] = d.deadline_expired;
    j["cancelled"] = d.cancelled;
    j["truncated"] = d.truncated;
    j["elapsed_ms"] = d.elapsed_ms;
    j["enumerate_elapsed_ms"] = d.enumerate_elapsed_ms;
    j["first_hit_elapsed_ms"] = d.first_hit_elapsed_ms;
    j["regions_seen"] = d.regions_seen;
    j["regions_committed"] = d.regions_committed;
    j["regions_skipped_state"] = d.regions_skipped_state;
    j["regions_skipped_size"] = d.regions_skipped_size;
    j["read_attempts"] = d.read_attempts;
    j["read_bytes"] = d.read_bytes;
    j["read_short"] = d.read_short;
    j["first_short_read_va"] = d.first_short_read_va;
    j["candidate_hits"] = d.candidate_hits;
    j["reject_count"] = d.reject_count;
    j["keys_found"] = d.keys_found;
    j["early_exit_reason"] = d.early_exit_reason;
    return j;
}

static json ns_tls_keylog_ledger_json(const ns_tls_keylog_session_state_t& s) {
    json j;
    j["active"] = s.active;
    j["session_id"] = s.session_id;
    j["pid"] = s.pid;
    j["output_file"] = s.output_file;
    j["poll_interval_ms"] = s.poll_interval_ms;
    j["append"] = s.append;
    j["started_ms"] = s.started_ms;
    j["stopped_ms"] = s.stopped_ms;
    j["starts"] = s.starts;
    j["stops"] = s.stops;
    j["key_count_start"] = static_cast<std::uint64_t>(s.key_count_start);
    j["last_error"] = s.last_error;
    return j;
}

static bool ns_hex_to_bytes_strict(const std::string& hex, std::vector<std::uint8_t>& out) {
    out.clear();
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != ':' && c != '-')
            clean += c;
    }
    if (clean.empty() || (clean.size() % 2) != 0)
        return false;
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        const int h = nib(clean[i]);
        const int l = nib(clean[i + 1]);
        if (h < 0 || l < 0) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return true;
}

static bool ns_decode_pem_certificate_der(const std::string& pem, std::vector<std::uint8_t>& out) {
    out.clear();
    if (pem.empty())
        return false;
    DWORD needed = 0;
    if (!CryptStringToBinaryA(pem.c_str(), static_cast<DWORD>(pem.size()), CRYPT_STRING_BASE64HEADER, nullptr, &needed, nullptr, nullptr) || needed == 0)
        return false;
    out.resize(needed);
    if (!CryptStringToBinaryA(pem.c_str(), static_cast<DWORD>(pem.size()), CRYPT_STRING_BASE64HEADER, out.data(), &needed, nullptr, nullptr)) {
        out.clear();
        return false;
    }
    out.resize(needed);
    return true;
}

static bool ns_is_valid_certificate_der(const std::vector<std::uint8_t>& der, std::string& subject) {
    subject.clear();
    if (der.empty() || der.size() > 0x100000)
        return false;
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der.data(), static_cast<DWORD>(der.size()));
    if (!ctx)
        return false;
    char name[512] = {};
    CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, static_cast<DWORD>(sizeof(name)));
    subject = name;
    CertFreeCertificateContext(ctx);
    return true;
}

static bool ns_valid_sha1_thumbprint_text(const std::string& thumbprint) {
    std::size_t n = 0;
    for (char c : thumbprint) {
        if (c == ' ' || c == ':' || c == '-')
            continue;
        const bool hex = (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
        ++n;
    }
    return n == 40;
}

static json ns_module_to_json(const cert_intercept::module_summary_t& module) {
    json out;
    out["name"] = module.name;
    out["path"] = module.path;
    out["base"] = module.base;
    out["size"] = module.size;
    out["browser_runtime"] = module.browser_runtime;
    out["system_tls"] = module.system_tls;
    out["app_tls_stack"] = module.app_tls_stack;
    out["managed_runtime"] = module.managed_runtime;
    out["quic_capable"] = module.quic_capable;
    out["proxy_aware"] = module.proxy_aware;
    out["stable_export_candidate"] = module.stable_export_candidate;
    out["evidence"] = module.evidence;
    return out;
}

static json ns_finding_to_json(const cert_intercept::diagnostic_finding_t& finding) {
    json out;
    out["classification"] = cert_intercept::to_string(finding.classification);
    out["severity"] = cert_intercept::to_string(finding.severity);
    out["title"] = finding.title;
    out["evidence"] = finding.evidence;
    out["next_action"] = finding.next_action;
    return out;
}

static json ns_diagnostics_to_json(const cert_intercept::process_diagnostics_t& diagnostics) {
    json out;
    out["pid"] = diagnostics.pid;
    out["process_name"] = diagnostics.process_name;
    out["primary"] = cert_intercept::to_string(diagnostics.primary);
    out["read_only"] = diagnostics.read_only;
    out["recommended_tier"] = diagnostics.recommended_tier;
    out["summary"] = diagnostics.summary;
    out["modules"] = json::array();
    for (const auto& module : diagnostics.modules) out["modules"].push_back(ns_module_to_json(module));
    out["findings"] = json::array();
    for (const auto& finding : diagnostics.findings) out["findings"].push_back(ns_finding_to_json(finding));
    return out;
}

static json ns_provider_to_json(const cert_intercept::provider_status_t& provider) {
    json out;
    out["provider_id"] = provider.descriptor.provider_id;
    out["display_name"] = provider.descriptor.display_name;
    out["state"] = cert_intercept::to_string(provider.state);
    out["active"] = provider.active;
    out["intent"] = provider.descriptor.intent;
    out["behavior"] = provider.descriptor.behavior;
    out["forces_certificate_success"] = provider.descriptor.forces_certificate_success;
    out["requires_explicit_target"] = provider.descriptor.requires_explicit_target;
    out["supports_attach"] = provider.descriptor.supports_attach;
    out["reason"] = provider.reason;
    out["evidence"] = provider.evidence;
    return out;
}

static std::string ns_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

static bool ns_has_any(const std::string& value, std::initializer_list<const char*> needles) {
    const std::string lowered = ns_lower_copy(value);
    for (const char* needle : needles) {
        if (lowered.find(needle) != std::string::npos) return true;
    }
    return false;
}

static std::wstring ns_utf8_to_wide(const std::string& value)
{
    if (value.empty())
        return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0)
        needed = MultiByteToWideChar(CP_ACP, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0)
        return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed) <= 0)
        MultiByteToWideChar(CP_ACP, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed);
    return out;
}

static std::string ns_wide_to_utf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

static bool ns_tls_valid_host(const std::string& host)
{
    if (host.empty() || host.size() > 253)
        return false;
    for (unsigned char c : host) {
        if (std::isspace(c) || c == '/' || c == '\\' || c == '@')
            return false;
    }
    return true;
}

static bool ns_json_u16_param(const json& params, const char* key, std::uint16_t& out, std::uint16_t fallback)
{
    out = fallback;
    if (!params.contains(key))
        return true;
    if (!params[key].is_number_unsigned() && !params[key].is_number_integer())
        return false;
    const auto raw = params[key].get<std::int64_t>();
    if (raw <= 0 || raw > 65535)
        return false;
    out = static_cast<std::uint16_t>(raw);
    return true;
}

static bool ns_tls_cancelled_or_deadline()
{
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return mcp_standalone::current_call_cancelled() || (deadline != 0 && GetTickCount64() >= deadline);
}

static DWORD ns_tls_timeout_ms(DWORD fallback)
{
    const DWORD bounded = std::max<DWORD>(100, std::min<DWORD>(fallback, 15000));
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline == 0)
        return bounded;
    const std::uint64_t now = GetTickCount64();
    if (deadline <= now)
        return 1;
    return std::max<DWORD>(1, static_cast<DWORD>(std::min<std::uint64_t>(bounded, deadline - now)));
}

static json ns_udp_live_stimulus_status_json(const char* protocol)
{
    const auto wq = aida::network::executor_status::work_stats();
    const auto sq = aida::network::executor_status::service_stats();
    const auto cq = aida::network::executor_status::critical_stats();
    const std::uint64_t now = GetTickCount64();
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    json j;
    j["protocol"] = protocol ? protocol : "";
    j["implementation_owns_udp_stimulus_executor"] = false;
    j["implementation_udp_stimulus_executor_available"] = false;
    j["implementation_udp_stimulus_executor_reason"] = "live UDP stimulus is owned by the Test Lab harness in this wave";
    j["parser_only_is_live_detection"] = false;
    j["live_detection_requires_external_stimulus"] = true;
    j["mcp_cancelled"] = mcp_standalone::current_call_cancelled();
    j["mcp_deadline_ms"] = deadline;
    j["deadline_remaining_ms"] = deadline > now ? deadline - now : 0;
    j["executor_work_pending"] = static_cast<std::uint64_t>(wq.pending);
    j["executor_work_active"] = static_cast<std::uint64_t>(wq.active);
    j["executor_service_pending"] = static_cast<std::uint64_t>(sq.pending);
    j["executor_service_active"] = static_cast<std::uint64_t>(sq.active);
    j["executor_critical_pending"] = static_cast<std::uint64_t>(cq.pending);
    j["executor_critical_active"] = static_cast<std::uint64_t>(cq.active);
    return j;
}

static std::once_flag& ns_tls_wsa_once()
{
    static std::once_flag flag;
    return flag;
}

static int& ns_tls_wsa_status()
{
    static int status = WSANOTINITIALISED;
    return status;
}

static bool ns_tls_ensure_winsock()
{
    std::call_once(ns_tls_wsa_once(), []() {
        WSADATA wsa{};
        ns_tls_wsa_status() = WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    return ns_tls_wsa_status() == 0;
}

static bool ns_tls_wait_socket(SOCKET s, bool write, DWORD timeout)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{static_cast<long>(timeout / 1000), static_cast<long>((timeout % 1000) * 1000)};
    const int rc = write ? select(0, nullptr, &fds, nullptr, &tv) : select(0, &fds, nullptr, nullptr, &tv);
    return rc > 0 && FD_ISSET(s, &fds);
}

static bool ns_tls_connect_socket(const std::string& host, std::uint16_t port, DWORD timeout, SOCKET& out_sock, std::string& error)
{
    out_sock = INVALID_SOCKET;
    if (!ns_tls_ensure_winsock()) {
        error = "WSAStartup failed " + std::to_string(ns_tls_wsa_status());
        return false;
    }
    const std::wstring host_w = ns_utf8_to_wide(host);
    const std::wstring port_w = ns_utf8_to_wide(std::to_string(port));
    ADDRINFOEXW hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    PADDRINFOEXW resolved = nullptr;
    timeval resolve_timeout{static_cast<long>(timeout / 1000), static_cast<long>((timeout % 1000) * 1000)};
    const int gai = GetAddrInfoExW(host_w.c_str(), port_w.c_str(), NS_ALL, nullptr, &hints, &resolved, &resolve_timeout, nullptr, nullptr, nullptr);
    if (gai != 0 || !resolved) {
        error = "GetAddrInfoExW failed " + std::to_string(gai != 0 ? gai : WSAGetLastError());
        if (resolved)
            FreeAddrInfoExW(resolved);
        return false;
    }
    for (PADDRINFOEXW ai = resolved; ai; ai = ai->ai_next) {
        if (ns_tls_cancelled_or_deadline()) {
            error = mcp_standalone::current_call_cancelled() ? "cancelled" : "deadline_expired";
            break;
        }
        if (!ai->ai_addr || ai->ai_addrlen == 0)
            continue;
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (rc == SOCKET_ERROR) {
            const int wsa = WSAGetLastError();
            if (wsa != WSAEWOULDBLOCK && wsa != WSAEINPROGRESS && wsa != WSAEINVAL) {
                closesocket(s);
                continue;
            }
        }
        if (ns_tls_wait_socket(s, true, ns_tls_timeout_ms(timeout))) {
            int soerr = 0;
            int soerr_len = sizeof(soerr);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &soerr_len);
            if (soerr == 0) {
                DWORD t = ns_tls_timeout_ms(timeout);
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
                out_sock = s;
                FreeAddrInfoExW(resolved);
                return true;
            }
        }
        closesocket(s);
    }
    FreeAddrInfoExW(resolved);
    if (error.empty())
        error = "connect timeout or refused";
    return false;
}

static bool ns_tls_send_all(SOCKET s, const std::uint8_t* data, std::size_t len, DWORD timeout, std::string& error)
{
    std::size_t sent = 0;
    while (sent < len) {
        if (ns_tls_cancelled_or_deadline()) {
            error = mcp_standalone::current_call_cancelled() ? "cancelled" : "deadline_expired";
            return false;
        }
        if (!ns_tls_wait_socket(s, true, ns_tls_timeout_ms(timeout))) {
            error = "send_timeout";
            return false;
        }
        const int n = send(s, reinterpret_cast<const char*>(data + sent), static_cast<int>(std::min<std::size_t>(len - sent, 8192)), 0);
        if (n <= 0) {
            error = "send_failed_wsa_" + std::to_string(WSAGetLastError());
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

static bool ns_tls_recv_some(SOCKET s, std::vector<std::uint8_t>& out, DWORD timeout, std::size_t max_chunk, std::string& error)
{
    if (ns_tls_cancelled_or_deadline()) {
        error = mcp_standalone::current_call_cancelled() ? "cancelled" : "deadline_expired";
        return false;
    }
    if (!ns_tls_wait_socket(s, false, ns_tls_timeout_ms(timeout))) {
        error = "receive_timeout";
        return false;
    }
    std::vector<std::uint8_t> buf(std::min<std::size_t>(max_chunk, 8192));
    const int n = recv(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
    if (n <= 0) {
        error = n == 0 ? "connection_closed" : "recv_failed_wsa_" + std::to_string(WSAGetLastError());
        return false;
    }
    out.insert(out.end(), buf.begin(), buf.begin() + n);
    return true;
}

static void ns_tls_put_u16(std::vector<std::uint8_t>& out, std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

static void ns_tls_put_u24(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

static void ns_tls_random_bytes(std::vector<std::uint8_t>& out, std::size_t count, std::uint8_t seed)
{
    const std::size_t start = out.size();
    out.resize(start + count);
    if (BCryptGenRandom(nullptr, out.data() + start, static_cast<ULONG>(count), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        for (std::size_t i = 0; i < count; ++i)
            out[start + i] = static_cast<std::uint8_t>((i * 37u + seed) & 0xffu);
    }
}

static std::string ns_tls_hex_u16(std::uint16_t value)
{
    std::ostringstream os;
    os << std::hex << std::nouppercase << std::setw(4) << std::setfill('0') << value;
    return os.str();
}

static std::string ns_tls_sha256_hex(const std::string& value)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_len = 0;
    DWORD hash_len = 0;
    DWORD cb = 0;
    std::vector<std::uint8_t> object;
    std::vector<std::uint8_t> digest;
    std::string out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &cb, 0) >= 0 &&
            BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0) >= 0) {
            object.resize(object_len);
            digest.resize(hash_len);
            if (BCryptCreateHash(alg, &hash, object.data(), object_len, nullptr, 0, 0) >= 0 &&
                BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(value.data())), static_cast<ULONG>(value.size()), 0) >= 0 &&
                BCryptFinishHash(hash, digest.data(), hash_len, 0) >= 0) {
                out = ns_bytes_to_hex(digest.data(), digest.size());
                std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            }
        }
    }
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    if (out.empty()) {
        std::uint64_t h = 1469598103934665603ull;
        for (unsigned char c : value) {
            h ^= c;
            h *= 1099511628211ull;
        }
        std::ostringstream os;
        os << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << h;
        out = os.str();
        while (out.size() < 64)
            out += out;
        out.resize(64);
    }
    return out;
}

struct ns_tls_probe_profile_t {
    std::string label;
    std::uint16_t record_version = 0x0301;
    std::uint16_t client_version = 0x0303;
    std::vector<std::uint16_t> ciphers;
    std::vector<std::uint16_t> supported_versions;
    std::vector<std::uint8_t> compressions{0};
    bool sni = true;
    bool alpn = false;
    bool rare_alpn = false;
    bool heartbeat = false;
    bool grease = false;
    bool psk_modes = true;
    bool key_share = true;
    std::string alpn_order = "FORWARD";
    std::string version_order = "FORWARD";
};

struct ns_tls_probe_result_t {
    std::string label;
    bool connected = false;
    bool sent = false;
    bool got_server_hello = false;
    bool server_hello_done = false;
    bool got_alert = false;
    std::uint8_t alert_level = 0;
    std::uint8_t alert_description = 0;
    std::uint16_t record_version = 0;
    std::uint16_t server_version = 0;
    std::uint16_t selected_version = 0;
    std::uint16_t cipher_suite = 0;
    std::uint8_t compression = 0xff;
    bool heartbeat_extension = false;
    std::string alpn;
    std::vector<std::uint16_t> extensions;
    std::size_t bytes_received = 0;
    std::uint64_t elapsed_ms = 0;
    std::string error;
};

template <typename T>
static std::vector<T> ns_tls_reorder(std::vector<T> in, const std::string& order)
{
    if (order == "REVERSE") {
        std::reverse(in.begin(), in.end());
        return in;
    }
    if (order == "BOTTOM_HALF") {
        const std::size_t mid = in.size() / 2;
        return std::vector<T>(in.begin() + static_cast<std::ptrdiff_t>(mid + (in.size() % 2)), in.end());
    }
    if (order == "TOP_HALF") {
        std::vector<T> reversed = in;
        std::reverse(reversed.begin(), reversed.end());
        const std::size_t mid = reversed.size() / 2;
        std::vector<T> bottom(reversed.begin() + static_cast<std::ptrdiff_t>(mid + (reversed.size() % 2)), reversed.end());
        if (in.size() % 2)
            bottom.insert(bottom.begin(), in[in.size() / 2]);
        return bottom;
    }
    if (order == "MIDDLE_OUT") {
        std::vector<T> out;
        const std::size_t mid = in.size() / 2;
        if (in.size() % 2)
            out.push_back(in[mid]);
        for (std::size_t i = 1; i <= mid; ++i) {
            if (mid - 1 + i < in.size())
                out.push_back(in[mid - 1 + i]);
            if (mid >= i)
                out.push_back(in[mid - i]);
        }
        return out;
    }
    return in;
}

static void ns_tls_add_extension(std::vector<std::uint8_t>& ext, std::uint16_t type, const std::vector<std::uint8_t>& data)
{
    ns_tls_put_u16(ext, type);
    ns_tls_put_u16(ext, static_cast<std::uint16_t>(data.size()));
    ext.insert(ext.end(), data.begin(), data.end());
}

static std::vector<std::uint8_t> ns_tls_alpn_payload(bool rare, const std::string& order)
{
    std::vector<std::string> labels = rare
        ? std::vector<std::string>{"http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"}
        : std::vector<std::string>{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq"};
    labels = ns_tls_reorder(labels, order);
    std::vector<std::uint8_t> list;
    for (const auto& label : labels) {
        list.push_back(static_cast<std::uint8_t>(label.size()));
        list.insert(list.end(), label.begin(), label.end());
    }
    std::vector<std::uint8_t> out;
    ns_tls_put_u16(out, static_cast<std::uint16_t>(list.size()));
    out.insert(out.end(), list.begin(), list.end());
    return out;
}

static std::vector<std::uint8_t> ns_tls_supported_versions_payload(std::vector<std::uint16_t> versions, const std::string& order, bool grease)
{
    versions = ns_tls_reorder(versions, order);
    std::vector<std::uint8_t> out;
    if (grease)
        ns_tls_put_u16(out, 0x0a0a);
    for (std::uint16_t version : versions)
        ns_tls_put_u16(out, version);
    std::vector<std::uint8_t> wrapped;
    wrapped.push_back(static_cast<std::uint8_t>(out.size()));
    wrapped.insert(wrapped.end(), out.begin(), out.end());
    return wrapped;
}

static std::vector<std::uint8_t> ns_tls_key_share_payload(bool grease)
{
    std::vector<std::uint8_t> entries;
    if (grease) {
        ns_tls_put_u16(entries, 0x0a0a);
        ns_tls_put_u16(entries, 1);
        entries.push_back(0);
    }
    ns_tls_put_u16(entries, 0x001d);
    ns_tls_put_u16(entries, 32);
    ns_tls_random_bytes(entries, 32, 0x5a);
    std::vector<std::uint8_t> out;
    ns_tls_put_u16(out, static_cast<std::uint16_t>(entries.size()));
    out.insert(out.end(), entries.begin(), entries.end());
    return out;
}

static std::vector<std::uint8_t> ns_tls_build_client_hello(const std::string& host, const ns_tls_probe_profile_t& profile)
{
    std::vector<std::uint8_t> body;
    ns_tls_put_u16(body, profile.client_version);
    ns_tls_random_bytes(body, 32, static_cast<std::uint8_t>(profile.label.size()));
    std::vector<std::uint8_t> session;
    ns_tls_random_bytes(session, 32, 0x31);
    body.push_back(static_cast<std::uint8_t>(session.size()));
    body.insert(body.end(), session.begin(), session.end());
    std::vector<std::uint16_t> ciphers = profile.ciphers.empty()
        ? std::vector<std::uint16_t>{0x1302, 0x1301, 0x1303, 0xc02f, 0xc030, 0xcca8, 0xcca9, 0x009e, 0x009f, 0x003c, 0x003d, 0x002f, 0x0035}
        : profile.ciphers;
    if (profile.grease)
        ciphers.insert(ciphers.begin(), 0x0a0a);
    ns_tls_put_u16(body, static_cast<std::uint16_t>(ciphers.size() * 2));
    for (std::uint16_t cipher : ciphers)
        ns_tls_put_u16(body, cipher);
    const auto compressions = profile.compressions.empty() ? std::vector<std::uint8_t>{0} : profile.compressions;
    body.push_back(static_cast<std::uint8_t>(compressions.size()));
    body.insert(body.end(), compressions.begin(), compressions.end());
    std::vector<std::uint8_t> extensions;
    if (profile.grease)
        ns_tls_add_extension(extensions, 0x0a0a, {});
    if (profile.sni && !host.empty()) {
        std::vector<std::uint8_t> sni;
        std::vector<std::uint8_t> hn(host.begin(), host.end());
        ns_tls_put_u16(sni, static_cast<std::uint16_t>(hn.size() + 3));
        sni.push_back(0);
        ns_tls_put_u16(sni, static_cast<std::uint16_t>(hn.size()));
        sni.insert(sni.end(), hn.begin(), hn.end());
        ns_tls_add_extension(extensions, 0, sni);
    }
    ns_tls_add_extension(extensions, 23, {});
    ns_tls_add_extension(extensions, 1, {1});
    ns_tls_add_extension(extensions, 0xff01, {0});
    ns_tls_add_extension(extensions, 10, {0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19});
    ns_tls_add_extension(extensions, 11, {0x01, 0x00});
    ns_tls_add_extension(extensions, 35, {});
    if (profile.alpn)
        ns_tls_add_extension(extensions, 16, ns_tls_alpn_payload(profile.rare_alpn, profile.alpn_order));
    ns_tls_add_extension(extensions, 13, {0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01});
    if (profile.heartbeat)
        ns_tls_add_extension(extensions, 15, {1});
    if (profile.key_share)
        ns_tls_add_extension(extensions, 51, ns_tls_key_share_payload(profile.grease));
    if (profile.psk_modes)
        ns_tls_add_extension(extensions, 45, {0x01, 0x01});
    if (!profile.supported_versions.empty())
        ns_tls_add_extension(extensions, 43, ns_tls_supported_versions_payload(profile.supported_versions, profile.version_order, profile.grease));
    ns_tls_put_u16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    std::vector<std::uint8_t> handshake;
    handshake.push_back(1);
    ns_tls_put_u24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    std::vector<std::uint8_t> record;
    record.push_back(0x16);
    ns_tls_put_u16(record, profile.record_version);
    ns_tls_put_u16(record, static_cast<std::uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

static bool ns_tls_parse_server_hello(const std::vector<std::uint8_t>& data, std::size_t offset, std::size_t length, ns_tls_probe_result_t& result)
{
    if (offset + length > data.size() || length < 38)
        return false;
    std::size_t p = offset;
    result.server_version = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
    p += 2 + 32;
    if (p >= offset + length)
        return false;
    const std::uint8_t sid_len = data[p++];
    if (p + sid_len + 3 > offset + length)
        return false;
    p += sid_len;
    result.cipher_suite = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
    p += 2;
    result.compression = data[p++];
    if (p + 2 <= offset + length) {
        const std::size_t ext_len = (static_cast<std::size_t>(data[p]) << 8) | data[p + 1];
        p += 2;
        const std::size_t ext_end = std::min<std::size_t>(offset + length, p + ext_len);
        while (p + 4 <= ext_end) {
            const std::uint16_t type = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
            const std::size_t elen = (static_cast<std::size_t>(data[p + 2]) << 8) | data[p + 3];
            p += 4;
            result.extensions.push_back(type);
            if (type == 43 && elen >= 2 && p + 2 <= ext_end)
                result.selected_version = static_cast<std::uint16_t>((data[p] << 8) | data[p + 1]);
            if (type == 15)
                result.heartbeat_extension = true;
            if (type == 16 && elen >= 3 && p + elen <= ext_end) {
                std::size_t ap = p;
                const std::size_t list_len = (static_cast<std::size_t>(data[ap]) << 8) | data[ap + 1];
                ap += 2;
                if (ap < p + elen && list_len + 2 <= elen) {
                    const std::size_t one_len = data[ap++];
                    if (ap + one_len <= p + elen)
                        result.alpn.assign(reinterpret_cast<const char*>(data.data() + ap), reinterpret_cast<const char*>(data.data() + ap + one_len));
                }
            }
            if (p + elen > ext_end)
                break;
            p += elen;
        }
    }
    result.got_server_hello = true;
    return true;
}

static void ns_tls_parse_records(const std::vector<std::uint8_t>& data, ns_tls_probe_result_t& result)
{
    std::size_t offset = 0;
    while (offset + 5 <= data.size()) {
        const std::uint8_t type = data[offset];
        const std::uint16_t version = static_cast<std::uint16_t>((data[offset + 1] << 8) | data[offset + 2]);
        const std::size_t length = (static_cast<std::size_t>(data[offset + 3]) << 8) | data[offset + 4];
        offset += 5;
        if (offset + length > data.size())
            break;
        result.record_version = version;
        if (type == 21 && length >= 2) {
            result.got_alert = true;
            result.alert_level = data[offset];
            result.alert_description = data[offset + 1];
        } else if (type == 22) {
            std::size_t hp = offset;
            const std::size_t end = offset + length;
            while (hp + 4 <= end) {
                const std::uint8_t htype = data[hp++];
                const std::size_t hlen = (static_cast<std::size_t>(data[hp]) << 16) | (static_cast<std::size_t>(data[hp + 1]) << 8) | data[hp + 2];
                hp += 3;
                if (hp + hlen > end)
                    break;
                if (htype == 2)
                    ns_tls_parse_server_hello(data, hp, hlen, result);
                if (htype == 14)
                    result.server_hello_done = true;
                hp += hlen;
            }
        }
        offset += length;
    }
}

static ns_tls_probe_result_t ns_tls_raw_probe(const std::string& host,
                                              std::uint16_t port,
                                              const ns_tls_probe_profile_t& profile,
                                              DWORD timeout,
                                              std::size_t max_bytes,
                                              bool read_until_server_hello_done = false)
{
    ns_tls_probe_result_t result;
    result.label = profile.label;
    const std::uint64_t started = GetTickCount64();
    SOCKET s = INVALID_SOCKET;
    std::string error;
    if (!ns_tls_connect_socket(host, port, timeout, s, error)) {
        result.error = error;
        result.elapsed_ms = GetTickCount64() - started;
        return result;
    }
    result.connected = true;
    const auto hello = ns_tls_build_client_hello(host, profile);
    if (!ns_tls_send_all(s, hello.data(), hello.size(), timeout, error)) {
        result.error = error;
        result.elapsed_ms = GetTickCount64() - started;
        closesocket(s);
        return result;
    }
    result.sent = true;
    std::vector<std::uint8_t> data;
    while (!ns_tls_cancelled_or_deadline() && data.size() < max_bytes) {
        std::string recv_error;
        if (!ns_tls_recv_some(s, data, ns_tls_timeout_ms(std::min<DWORD>(timeout, 2500)), std::min<std::size_t>(8192, max_bytes - data.size()), recv_error)) {
            if (data.empty())
                result.error = recv_error;
            break;
        }
        ns_tls_parse_records(data, result);
        if (result.got_alert || (result.got_server_hello && (!read_until_server_hello_done || result.server_hello_done)))
            break;
    }
    result.bytes_received = data.size();
    result.elapsed_ms = GetTickCount64() - started;
    closesocket(s);
    return result;
}

static std::string ns_tls_version_name(std::uint16_t version)
{
    switch (version) {
    case 0x0300: return "SSL 3.0";
    case 0x0301: return "TLS 1.0";
    case 0x0302: return "TLS 1.1";
    case 0x0303: return "TLS 1.2";
    case 0x0304: return "TLS 1.3";
    default: return ns_tls_hex_u16(version);
    }
}

static std::string ns_tls_cipher_name(std::uint16_t cipher)
{
    switch (cipher) {
    case 0x1301: return "TLS_AES_128_GCM_SHA256";
    case 0x1302: return "TLS_AES_256_GCM_SHA384";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
    case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    case 0x009e: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0x009f: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0x003c: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
    case 0x003d: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
    case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0x000a: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
    default: return ns_tls_hex_u16(cipher);
    }
}

static std::string ns_tls_cipher_strength(std::uint16_t cipher)
{
    const std::string name = ns_lower_copy(ns_tls_cipher_name(cipher));
    if (name.find("null") != std::string::npos || name.find("anon") != std::string::npos ||
        name.find("export") != std::string::npos || name.find("rc4") != std::string::npos ||
        name.find("3des") != std::string::npos)
        return "weak";
    if (name.find("cbc") != std::string::npos)
        return "legacy";
    if (name.find("gcm") != std::string::npos || name.find("chacha20") != std::string::npos)
        return "strong";
    return "unknown";
}

static json ns_tls_probe_json(const ns_tls_probe_result_t& result)
{
    json out;
    out["label"] = result.label;
    out["connected"] = result.connected;
    out["sent"] = result.sent;
    out["got_server_hello"] = result.got_server_hello;
    out["server_hello_done"] = result.server_hello_done;
    out["got_alert"] = result.got_alert;
    out["bytes_received"] = static_cast<std::uint64_t>(result.bytes_received);
    out["elapsed_ms"] = result.elapsed_ms;
    if (!result.error.empty())
        out["error"] = result.error;
    if (result.got_alert) {
        out["alert_level"] = result.alert_level;
        out["alert_description"] = result.alert_description;
    }
    if (result.got_server_hello) {
        const std::uint16_t version = result.selected_version ? result.selected_version : result.server_version;
        out["server_version"] = ns_tls_version_name(result.server_version);
        out["selected_version"] = ns_tls_version_name(version);
        out["cipher_suite"] = ns_tls_cipher_name(result.cipher_suite);
        out["cipher_suite_code"] = ns_tls_hex_u16(result.cipher_suite);
        out["cipher_strength"] = ns_tls_cipher_strength(result.cipher_suite);
        out["compression"] = result.compression;
        out["heartbeat_extension"] = result.heartbeat_extension;
        if (!result.alpn.empty())
            out["alpn"] = result.alpn;
        out["extensions"] = json::array();
        for (std::uint16_t ext : result.extensions)
            out["extensions"].push_back(ns_tls_hex_u16(ext));
    }
    return out;
}

static ns_tls_probe_profile_t ns_tls_assess_profile(std::string label, std::uint16_t version, std::vector<std::uint16_t> supported = {})
{
    ns_tls_probe_profile_t p;
    p.label = std::move(label);
    p.record_version = version <= 0x0301 ? 0x0301 : 0x0303;
    p.client_version = version;
    p.supported_versions = std::move(supported);
    p.alpn = true;
    p.ciphers = {0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0xc02b, 0xc02c, 0xcca8, 0xcca9, 0x009e, 0x009f, 0x003c, 0x003d, 0x002f, 0x0035, 0x000a};
    return p;
}

static long long ns_filetime_days_remaining(const FILETIME& ft)
{
    FILETIME now_ft{};
    GetSystemTimeAsFileTime(&now_ft);
    ULARGE_INTEGER due{};
    ULARGE_INTEGER now{};
    due.LowPart = ft.dwLowDateTime;
    due.HighPart = ft.dwHighDateTime;
    now.LowPart = now_ft.dwLowDateTime;
    now.HighPart = now_ft.dwHighDateTime;
    if (due.QuadPart >= now.QuadPart)
        return static_cast<long long>((due.QuadPart - now.QuadPart) / 10000000ull) / 86400;
    return -static_cast<long long>((now.QuadPart - due.QuadPart) / 10000000ull) / 86400;
}

static json ns_cert_context_json(PCCERT_CONTEXT cert, const std::string& host, bool check_chain)
{
    json out;
    char subject[512] = {};
    char issuer[512] = {};
    CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject, static_cast<DWORD>(sizeof(subject)));
    CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issuer, static_cast<DWORD>(sizeof(issuer)));
    out["subject"] = subject;
    out["issuer"] = issuer;
    out["der_bytes"] = cert->cbCertEncoded;
    out["sha256"] = ns_tls_sha256_hex(std::string(reinterpret_cast<const char*>(cert->pbCertEncoded), reinterpret_cast<const char*>(cert->pbCertEncoded + cert->cbCertEncoded)));
    out["days_remaining"] = ns_filetime_days_remaining(cert->pCertInfo->NotAfter);
    if (check_chain) {
        CERT_CHAIN_PARA chain_para{};
        chain_para.cbSize = sizeof(chain_para);
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        DWORD chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
        bool chain_ok = CertGetCertificateChain(nullptr, cert, nullptr, cert->hCertStore, &chain_para, chain_flags, nullptr, &chain) && chain;
        DWORD policy_error = 0;
        if (chain_ok) {
            const std::wstring whost = ns_utf8_to_wide(host);
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para{};
            ssl_para.cbSize = sizeof(ssl_para);
            ssl_para.dwAuthType = AUTHTYPE_SERVER;
            ssl_para.pwszServerName = const_cast<LPWSTR>(whost.c_str());
            CERT_CHAIN_POLICY_PARA policy_para{};
            policy_para.cbSize = sizeof(policy_para);
            policy_para.pvExtraPolicyPara = &ssl_para;
            CERT_CHAIN_POLICY_STATUS policy_status{};
            policy_status.cbSize = sizeof(policy_status);
            if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy_para, &policy_status))
                policy_error = GetLastError();
            else
                policy_error = policy_status.dwError;
            CertFreeCertificateChain(chain);
        } else {
            policy_error = GetLastError();
        }
        out["chain_checked"] = true;
        out["chain_valid"] = chain_ok && policy_error == 0;
        out["chain_policy_error"] = policy_error;
    } else {
        out["chain_checked"] = false;
    }
    return out;
}

static long long ns_hsts_max_age(const std::string& value)
{
    const std::string lower = ns_lower_copy(value);
    const std::string marker = "max-age=";
    const std::size_t pos = lower.find(marker);
    if (pos == std::string::npos)
        return -1;
    std::size_t p = pos + marker.size();
    long long out = 0;
    bool any = false;
    while (p < lower.size() && std::isdigit(static_cast<unsigned char>(lower[p]))) {
        any = true;
        out = out * 10 + (lower[p] - '0');
        ++p;
    }
    return any ? out : -1;
}

static json ns_hsts_json(const std::string& value)
{
    const std::string lower = ns_lower_copy(value);
    json out;
    out["present"] = !value.empty();
    if (!value.empty())
        out["value"] = value;
    out["max_age"] = value.empty() ? 0 : ns_hsts_max_age(value);
    out["include_subdomains"] = lower.find("includesubdomains") != std::string::npos;
    out["preload"] = lower.find("preload") != std::string::npos;
    out["status"] = value.empty() ? "warn" : (out["max_age"].get<long long>() >= 31536000 && out["include_subdomains"].get<bool>() ? "pass" : "warn");
    return out;
}

static json ns_winhttp_tls_assess(const std::string& host, std::uint16_t port, bool check_chain)
{
    json out;
    out["source"] = "winhttp_certificate_context";
    const std::wstring whost = ns_utf8_to_wide(host);
    HINTERNET session = WinHttpOpen(L"AiDA-TLSAssess/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        out["error"] = "WinHttpOpen failed";
        out["gle"] = GetLastError();
        return out;
    }
    DWORD timeout = ns_tls_timeout_ms(6000);
    WinHttpSetTimeouts(session, timeout, timeout, timeout, timeout);
    HINTERNET connect = WinHttpConnect(session, whost.c_str(), static_cast<INTERNET_PORT>(port), 0);
    if (!connect) {
        out["error"] = "WinHttpConnect failed";
        out["gle"] = GetLastError();
        WinHttpCloseHandle(session);
        return out;
    }
    HINTERNET request = WinHttpOpenRequest(connect, L"HEAD", L"/", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        out["error"] = "WinHttpOpenRequest failed";
        out["gle"] = GetLastError();
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return out;
    }
    WinHttpSetTimeouts(request, timeout, timeout, timeout, timeout);
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        out["error"] = "WinHttpSendRequest/ReceiveResponse failed";
        out["gle"] = GetLastError();
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return out;
    }
    DWORD status = 0;
    DWORD status_len = sizeof(status);
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &status_len, nullptr))
        out["http_status"] = status;
    DWORD header_len = 0;
    WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &header_len, WINHTTP_NO_HEADER_INDEX);
    std::string hsts;
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && header_len > 0 && header_len < 65536) {
        std::wstring raw(header_len / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &header_len, WINHTTP_NO_HEADER_INDEX)) {
            std::string headers = ns_lower_copy(ns_wide_to_utf8(raw));
            const std::string marker = "strict-transport-security:";
            const std::size_t pos = headers.find(marker);
            if (pos != std::string::npos) {
                std::size_t start = pos + marker.size();
                while (start < headers.size() && (headers[start] == ' ' || headers[start] == '\t'))
                    ++start;
                const std::size_t end = headers.find_first_of("\r\n", start);
                hsts = headers.substr(start, end == std::string::npos ? std::string::npos : end - start);
            }
        }
    }
    out["hsts"] = ns_hsts_json(hsts);
    PCCERT_CONTEXT cert = nullptr;
    DWORD cert_len = sizeof(cert);
    if (WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &cert_len) && cert) {
        out["certificate"] = ns_cert_context_json(cert, host, check_chain);
        CertFreeCertificateContext(cert);
    } else {
        out["certificate_error"] = GetLastError();
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return out;
}

static void ns_apply_proxy_observations(cert_intercept::diagnostic_context_t& context) {
    auto observations = mitm_proxy::get_tls_observations(64);
    for (const auto& obs : observations) {
        std::string evidence = std::string(mitm_proxy::to_string(obs.kind)) + " host=" + obs.target_host;
        if (!obs.sni.empty()) evidence += " sni=" + obs.sni;
        if (!obs.alpn.empty()) evidence += " alpn=" + obs.alpn;
        if (!obs.detail.empty()) evidence += " detail=" + obs.detail;
        switch (obs.kind) {
        case mitm_proxy::tls_observation_kind_t::http_tls:
            context.interception_observed = true;
            break;
        case mitm_proxy::tls_observation_kind_t::sni_authority_mismatch:
            context.hostname_san_mismatch_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        case mitm_proxy::tls_observation_kind_t::client_handshake_failed:
            if (ns_has_any(obs.detail, {"certificate", "unknown ca", "bad certificate", "required", "alert"})) {
                context.browser_trust_policy_or_ct_block = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::upstream_handshake_failed:
            if (ns_has_any(obs.detail, {"certificate required", "bad certificate", "handshake failure", "alert certificate"})) {
                context.mutual_tls_requested = true;
                context.interception_still_failing = true;
                context.observation_evidence.push_back(std::move(evidence));
            }
            break;
        case mitm_proxy::tls_observation_kind_t::non_http_tls:
            context.non_http_tls_observed = true;
            context.interception_still_failing = true;
            context.observation_evidence.push_back(std::move(evidence));
            break;
        default:
            break;
        }
    }
}

static cert_intercept::diagnostic_context_t ns_make_diagnostic_context(const json& params) {
    cert_intercept::diagnostic_context_t context;
    context.proxy_running = params.value("proxy_running", mitm_proxy::is_running());
    context.controlled_browser = params.value("controlled_browser", false);
    if (params.value("use_proxy_observations", true)) ns_apply_proxy_observations(context);
    if (params.value("quic_observed", false)) context.quic_observed = true;
    if (params.value("interception_observed", false)) context.interception_observed = true;
    if (params.value("interception_still_failing", false)) context.interception_still_failing = true;
    if (params.value("hostname_san_mismatch_observed", false)) context.hostname_san_mismatch_observed = true;
    if (params.value("browser_trust_policy_or_ct_block", false)) context.browser_trust_policy_or_ct_block = true;
    if (params.value("mutual_tls_requested", false)) context.mutual_tls_requested = true;
    if (params.value("non_http_tls_observed", false)) context.non_http_tls_observed = true;
    context.process_name = params.value("process_name", std::string());
    if (params.contains("proxy_endpoint") && params["proxy_endpoint"].is_string()) {
        context.proxy_endpoint = params["proxy_endpoint"].get<std::string>();
    } else {
        const auto& cfg = mitm_proxy::g_state.config;
        context.proxy_endpoint = cfg.bind_addr + ":" + std::to_string(static_cast<unsigned>(cfg.bind_port));
    }
    if (cert_generator::is_ready()) {
        const auto& ca = cert_generator::get_root_ca();
        context.ca_trusted = cert_generator::is_root_ca_installed(ca);
        context.ca_certificate_path = cert_generator::get_ca_storage_dir() + "\\aida_root_ca.pem";
    } else {
        context.ca_trusted = false;
    }
    if (params.contains("ca_trusted") && params["ca_trusted"].is_boolean())
        context.ca_trusted = params["ca_trusted"].get<bool>();
    if (params.contains("ca_certificate_path") && params["ca_certificate_path"].is_string())
        context.ca_certificate_path = params["ca_certificate_path"].get<std::string>();
    return context;
}

static bool ns_pin_method_from_string(const std::string& method, net_security::pin_bypass_method& out) {
    if (method.empty() || method == "all") {
        out = net_security::pin_bypass_method::all;
        return true;
    }
    if (method == "wintrust" || method == "windows_trust") {
        out = net_security::pin_bypass_method::windows_trust;
        return true;
    }
    if (method == "crypt32" || method == "chain_policy") {
        out = net_security::pin_bypass_method::windows_chain_policy;
        return true;
    }
    if (method == "schannel" || method == "windows_tls") {
        out = net_security::pin_bypass_method::windows_tls;
        return true;
    }
    if (method == "dotnet" || method == "managed") {
        out = net_security::pin_bypass_method::managed_dotnet;
        return true;
    }
    return false;
}

static std::string ns_get_downloads_folder() {
    char buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableA("USERPROFILE", buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH)
        return std::string(buf, len) + "\\Downloads";
    return ".";
}

static tool_result_t aida_tls_assess(const json& params)
{
    if (!params.is_object() || !params.contains("host") || !params["host"].is_string())
        return tool_result_t::error("host is required");
    const std::string host = params["host"].get<std::string>();
    if (!ns_tls_valid_host(host))
        return tool_result_t::error("host is invalid");
    std::uint16_t port = 443;
    if (!ns_json_u16_param(params, "port", port, 443))
        return tool_result_t::error("port must be 1..65535");
    const DWORD timeout = static_cast<DWORD>(std::max(500, std::min(params.value("timeout_ms", 7000), 15000)));
    json out;
    out["host"] = host;
    out["port"] = port;
    out["bounded"] = true;
    out["global_tls_policy_modified"] = false;
    out["persisted_findings"] = false;
    out["protocol_probes"] = json::array();
    std::vector<ns_tls_probe_profile_t> profiles;
    profiles.push_back(ns_tls_assess_profile("tls10", 0x0301));
    profiles.push_back(ns_tls_assess_profile("tls11", 0x0302));
    profiles.push_back(ns_tls_assess_profile("tls12", 0x0303));
    profiles.push_back(ns_tls_assess_profile("tls13", 0x0303, {0x0304, 0x0303}));
    bool weak_protocol = false;
    bool modern_protocol = false;
    bool weak_cipher = false;
    bool legacy_cipher = false;
    json protocols = json::array();
    json ciphers = json::array();
    std::set<std::uint16_t> seen_ciphers;
    for (const auto& profile : profiles) {
        if (ns_tls_cancelled_or_deadline()) {
            out["cancelled"] = mcp_standalone::current_call_cancelled();
            out["deadline_expired"] = !mcp_standalone::current_call_cancelled();
            return tool_result_t::error("TLS assessment cancelled or deadline reached", "cancelled", out);
        }
        auto probe = ns_tls_raw_probe(host, port, profile, timeout, 32768);
        out["protocol_probes"].push_back(ns_tls_probe_json(probe));
        const std::uint16_t selected = probe.selected_version ? probe.selected_version : probe.server_version;
        json protocol;
        protocol["probe"] = profile.label;
        protocol["name"] = selected ? ns_tls_version_name(selected) : ns_tls_version_name(profile.client_version);
        protocol["enabled"] = probe.got_server_hello;
        protocol["evidence"] = probe.got_server_hello ? "server_hello" : (probe.got_alert ? "alert" : "no_server_hello");
        if (probe.got_server_hello) {
            if (selected == 0x0301 || selected == 0x0302)
                weak_protocol = true;
            if (selected == 0x0303 || selected == 0x0304)
                modern_protocol = true;
            if (seen_ciphers.insert(probe.cipher_suite).second) {
                json cipher;
                cipher["name"] = ns_tls_cipher_name(probe.cipher_suite);
                cipher["code"] = ns_tls_hex_u16(probe.cipher_suite);
                cipher["strength"] = ns_tls_cipher_strength(probe.cipher_suite);
                cipher["pfs"] = cipher["name"].get<std::string>().find("ECDHE") != std::string::npos ||
                                cipher["name"].get<std::string>().find("DHE") != std::string::npos ||
                                cipher["name"].get<std::string>().rfind("TLS_AES_", 0) == 0 ||
                                cipher["name"].get<std::string>().rfind("TLS_CHACHA20_", 0) == 0;
                ciphers.push_back(std::move(cipher));
            }
            const std::string strength = ns_tls_cipher_strength(probe.cipher_suite);
            weak_cipher = weak_cipher || strength == "weak";
            legacy_cipher = legacy_cipher || strength == "legacy";
        }
        protocols.push_back(std::move(protocol));
    }
    out["protocols"] = protocols;
    out["cipher_suites"] = ciphers;
    out["certificate_assessment"] = ns_winhttp_tls_assess(host, port, params.value("check_chain", true));
    out["certificate"] = out["certificate_assessment"].value("certificate", json::object());
    out["hsts"] = out["certificate_assessment"].value("hsts", ns_hsts_json({}));
    json issues = json::array();
    int score = 100;
    if (weak_protocol) {
        score -= 25;
        issues.push_back({{"severity", "high"}, {"description", "TLS 1.0 or TLS 1.1 was negotiated by a bounded probe"}, {"cwe", "CWE-327"}});
    }
    if (!modern_protocol) {
        score -= 20;
        issues.push_back({{"severity", "high"}, {"description", "No TLS 1.2 or TLS 1.3 ServerHello evidence was observed"}, {"cwe", "CWE-326"}});
    }
    if (weak_cipher) {
        score -= 20;
        issues.push_back({{"severity", "high"}, {"description", "A weak cipher suite was negotiated"}, {"cwe", "CWE-327"}});
    } else if (legacy_cipher) {
        score -= 10;
        issues.push_back({{"severity", "medium"}, {"description", "A legacy CBC cipher suite was negotiated"}, {"cwe", "CWE-327"}});
    }
    const json certificate = out["certificate"];
    if (certificate.is_object() && !certificate.empty()) {
        if (certificate.value("chain_valid", true) == false) {
            score -= 20;
            issues.push_back({{"severity", "high"}, {"description", "Certificate chain or hostname validation failed"}, {"cwe", "CWE-295"}});
        }
        if (certificate.value("days_remaining", 1ll) < 0) {
            score -= 20;
            issues.push_back({{"severity", "critical"}, {"description", "TLS certificate is expired"}, {"cwe", "CWE-298"}});
        }
    } else {
        score -= 15;
        issues.push_back({{"severity", "medium"}, {"description", "Certificate context could not be collected with WinHTTP"}, {"cwe", "CWE-295"}});
    }
    if (!out["hsts"].value("present", false)) {
        score -= 5;
        issues.push_back({{"severity", "medium"}, {"description", "HSTS header was not observed on HTTPS root"}, {"cwe", "CWE-319"}});
    }
    score = std::max(0, std::min(score, 100));
    out["score"] = score;
    out["grade"] = score >= 90 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F";
    out["issues"] = issues;
    out["assessment_limitations"] = "Protocol and cipher evidence comes from bounded raw ClientHello probes. Certificate and HSTS evidence comes from WinHTTP without disabling certificate validation.";
    return tool_result_t::ok("TLS assessment complete", out);
}

static std::vector<std::uint16_t> ns_jarm_cipher_list(bool include_tls13)
{
    std::vector<std::uint16_t> ciphers = {
        0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3,
        0x009f, 0x0045, 0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac,
        0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9
    };
    if (include_tls13) {
        ciphers.push_back(0x1302);
        ciphers.push_back(0x1301);
    }
    ciphers.insert(ciphers.end(), {
        0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060,
        0xc061, 0xc076, 0xc077, 0xcca8
    });
    if (include_tls13) {
        ciphers.push_back(0x1305);
        ciphers.push_back(0x1304);
        ciphers.push_back(0x1303);
    }
    ciphers.insert(ciphers.end(), {
        0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d,
        0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005
    });
    return ciphers;
}

static ns_tls_probe_profile_t ns_jarm_profile(std::string label,
                                              std::uint16_t version,
                                              bool include_tls13,
                                              const std::string& cipher_order,
                                              bool grease,
                                              bool rare_alpn,
                                              const std::string& support_mode,
                                              const std::string& extension_order)
{
    ns_tls_probe_profile_t p;
    p.label = std::move(label);
    p.record_version = version == 0x0304 ? 0x0301 : version;
    p.client_version = version == 0x0304 ? 0x0303 : version;
    p.ciphers = ns_tls_reorder(ns_jarm_cipher_list(include_tls13), cipher_order);
    p.grease = grease;
    p.alpn = true;
    p.rare_alpn = rare_alpn;
    p.alpn_order = extension_order;
    p.version_order = extension_order;
    p.key_share = true;
    p.psk_modes = true;
    if (version == 0x0304)
        p.supported_versions = {0x0301, 0x0302, 0x0303, 0x0304};
    else if (support_mode == "1.2_SUPPORT")
        p.supported_versions = {0x0301, 0x0302, 0x0303};
    else
        p.supported_versions.clear();
    return p;
}

static std::string ns_jarm_cipher_byte(const std::string& cipher_hex)
{
    if (cipher_hex.empty())
        return "00";
    static const std::vector<std::uint16_t> order = {
        0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c,
        0x003d, 0x0041, 0x0045, 0x0067, 0x006b, 0x0084, 0x0088, 0x009a, 0x009c, 0x009d,
        0x009e, 0x009f, 0x00ba, 0x00be, 0x00c0, 0x00c4, 0xc007, 0xc008, 0xc009, 0xc00a,
        0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028, 0xc02b, 0xc02c,
        0xc02f, 0xc030, 0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077, 0xc09c, 0xc09d,
        0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af,
        0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305
    };
    std::uint16_t cipher = 0;
    try {
        cipher = static_cast<std::uint16_t>(std::stoul(cipher_hex, nullptr, 16));
    } catch (...) {
        return "00";
    }
    auto it = std::find(order.begin(), order.end(), cipher);
    if (it == order.end())
        return "00";
    const unsigned value = static_cast<unsigned>(std::distance(order.begin(), it)) + 1u;
    std::ostringstream os;
    os << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << value;
    return os.str();
}

static std::string ns_jarm_version_byte(const std::string& version_hex)
{
    if (version_hex.size() < 4)
        return "0";
    const char c = version_hex[3];
    if (c < '0' || c > '5')
        return "0";
    static constexpr char kOptions[] = "abcdef";
    return std::string(1, kOptions[c - '0']);
}

static std::string ns_jarm_segment(const ns_tls_probe_result_t& result)
{
    if (!result.got_server_hello)
        return "|||";
    std::string extensions;
    for (std::size_t i = 0; i < result.extensions.size(); ++i) {
        if (i != 0)
            extensions.push_back('-');
        extensions += ns_tls_hex_u16(result.extensions[i]);
    }
    return ns_tls_hex_u16(result.cipher_suite) + "|" + ns_tls_hex_u16(result.server_version) + "|" + result.alpn + "|" + extensions;
}

static std::string ns_jarm_hash(const std::string& raw)
{
    if (raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||")
        return std::string(62, '0');
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= raw.size()) {
        const std::size_t comma = raw.find(',', start);
        parts.push_back(raw.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (comma == std::string::npos)
            break;
        start = comma + 1;
    }
    std::string fuzzy;
    std::string ext_material;
    for (const auto& part : parts) {
        std::vector<std::string> fields;
        std::size_t p = 0;
        while (p <= part.size()) {
            const std::size_t pipe = part.find('|', p);
            fields.push_back(part.substr(p, pipe == std::string::npos ? std::string::npos : pipe - p));
            if (pipe == std::string::npos)
                break;
            p = pipe + 1;
        }
        while (fields.size() < 4)
            fields.push_back({});
        fuzzy += ns_jarm_cipher_byte(fields[0]);
        fuzzy += ns_jarm_version_byte(fields[1]);
        ext_material += fields[2];
        ext_material += fields[3];
    }
    const std::string digest = ns_tls_sha256_hex(ext_material);
    fuzzy += digest.substr(0, 32);
    return fuzzy;
}

static tool_result_t aida_tls_jarm(const json& params)
{
    if (!params.is_object() || !params.contains("host") || !params["host"].is_string())
        return tool_result_t::error("host is required");
    const std::string host = params["host"].get<std::string>();
    if (!ns_tls_valid_host(host))
        return tool_result_t::error("host is invalid");
    std::uint16_t port = 443;
    if (!ns_json_u16_param(params, "port", port, 443))
        return tool_result_t::error("port must be 1..65535");
    const DWORD timeout = static_cast<DWORD>(std::max(500, std::min(params.value("timeout_ms", 6000), 15000)));
    std::vector<ns_tls_probe_profile_t> queue;
    queue.push_back(ns_jarm_profile("tls1_2_forward", 0x0303, true, "FORWARD", false, false, "1.2_SUPPORT", "REVERSE"));
    queue.push_back(ns_jarm_profile("tls1_2_reverse", 0x0303, true, "REVERSE", false, false, "1.2_SUPPORT", "FORWARD"));
    queue.push_back(ns_jarm_profile("tls1_2_top_half", 0x0303, true, "TOP_HALF", false, false, "NO_SUPPORT", "FORWARD"));
    queue.push_back(ns_jarm_profile("tls1_2_bottom_half", 0x0303, true, "BOTTOM_HALF", false, true, "NO_SUPPORT", "FORWARD"));
    queue.push_back(ns_jarm_profile("tls1_2_middle_out", 0x0303, true, "MIDDLE_OUT", true, true, "NO_SUPPORT", "REVERSE"));
    queue.push_back(ns_jarm_profile("tls1_1_middle_out", 0x0302, true, "FORWARD", false, false, "NO_SUPPORT", "FORWARD"));
    queue.push_back(ns_jarm_profile("tls1_3_forward", 0x0304, true, "FORWARD", false, false, "1.3_SUPPORT", "REVERSE"));
    queue.push_back(ns_jarm_profile("tls1_3_reverse", 0x0304, true, "REVERSE", false, false, "1.3_SUPPORT", "FORWARD"));
    queue.push_back(ns_jarm_profile("tls1_3_invalid", 0x0304, false, "FORWARD", false, false, "1.3_SUPPORT", "FORWARD"));
    queue.push_back(ns_jarm_profile("tls1_3_middle_out", 0x0304, true, "MIDDLE_OUT", true, false, "1.3_SUPPORT", "REVERSE"));
    json probes = json::array();
    std::string raw;
    for (std::size_t i = 0; i < queue.size(); ++i) {
        if (ns_tls_cancelled_or_deadline()) {
            json d{{"host", host}, {"port", port}, {"raw", raw}, {"probes", probes}};
            d["cancelled"] = mcp_standalone::current_call_cancelled();
            d["deadline_expired"] = !mcp_standalone::current_call_cancelled();
            return tool_result_t::error("JARM scan cancelled or deadline reached", "cancelled", d);
        }
        auto probe = ns_tls_raw_probe(host, port, queue[i], timeout, 8192);
        const std::string segment = ns_jarm_segment(probe);
        if (i != 0)
            raw.push_back(',');
        raw += segment;
        json row = ns_tls_probe_json(probe);
        row["jarm_segment"] = segment;
        probes.push_back(std::move(row));
    }
    json out;
    out["host"] = host;
    out["port"] = port;
    out["jarm"] = ns_jarm_hash(raw);
    out["raw"] = raw;
    out["probes"] = probes;
    out["probe_count"] = probes.size();
    out["implementation"] = "salesforce_jarm_v1_compatible_probe_set";
    out["bounded"] = true;
    return tool_result_t::ok("JARM fingerprint complete", out);
}

static bool ns_tls_read_heartbeat_response(SOCKET s, DWORD timeout, json& evidence)
{
    std::vector<std::uint8_t> data;
    std::string error;
    while (!ns_tls_cancelled_or_deadline() && data.size() < 32768) {
        if (!ns_tls_recv_some(s, data, ns_tls_timeout_ms(std::min<DWORD>(timeout, 2500)), 8192, error))
            break;
        std::size_t offset = 0;
        while (offset + 5 <= data.size()) {
            const std::uint8_t record_type = data[offset];
            const std::uint16_t version = static_cast<std::uint16_t>((data[offset + 1] << 8) | data[offset + 2]);
            const std::size_t len = (static_cast<std::size_t>(data[offset + 3]) << 8) | data[offset + 4];
            offset += 5;
            if (offset + len > data.size())
                break;
            if (record_type == 24 && len >= 3) {
                const std::uint8_t hb_type = data[offset];
                const std::uint16_t claimed = static_cast<std::uint16_t>((data[offset + 1] << 8) | data[offset + 2]);
                evidence["record_type"] = record_type;
                evidence["record_version"] = ns_tls_hex_u16(version);
                evidence["heartbeat_type"] = hb_type;
                evidence["claimed_payload_length"] = claimed;
                evidence["record_payload_bytes"] = len;
                evidence["bytes_received"] = data.size();
                return hb_type == 2 && claimed > 1 && len > 20;
            }
            if (record_type == 21 && len >= 2) {
                evidence["alert_level"] = data[offset];
                evidence["alert_description"] = data[offset + 1];
                evidence["bytes_received"] = data.size();
                return false;
            }
            offset += len;
        }
    }
    if (!error.empty())
        evidence["error"] = error;
    evidence["bytes_received"] = data.size();
    return false;
}

static tool_result_t aida_tls_test_heartbleed(const json& params)
{
    if (!params.is_object() || !params.contains("host") || !params["host"].is_string())
        return tool_result_t::error("host is required");
    const std::string host = params["host"].get<std::string>();
    if (!ns_tls_valid_host(host))
        return tool_result_t::error("host is invalid");
    std::uint16_t port = 443;
    if (!ns_json_u16_param(params, "port", port, 443))
        return tool_result_t::error("port must be 1..65535");
    const DWORD timeout = static_cast<DWORD>(std::max(500, std::min(params.value("timeout_ms", 7000), 15000)));
    ns_tls_probe_profile_t profile = ns_tls_assess_profile("heartbleed_negotiation", 0x0302);
    profile.heartbeat = true;
    profile.supported_versions.clear();
    profile.ciphers = {0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009e, 0x009f, 0x003c, 0x003d, 0x002f, 0x0035};
    json out;
    out["host"] = host;
    out["port"] = port;
    out["bounded"] = true;
    out["probe_type"] = "tls_heartbeat_overread";
    SOCKET s = INVALID_SOCKET;
    std::string error;
    const std::uint64_t started = GetTickCount64();
    if (!ns_tls_connect_socket(host, port, timeout, s, error)) {
        out["error"] = error;
        out["elapsed_ms"] = GetTickCount64() - started;
        return tool_result_t::error("Heartbleed probe could not connect", "tls_connect_failed", out);
    }
    const auto hello = ns_tls_build_client_hello(host, profile);
    if (!ns_tls_send_all(s, hello.data(), hello.size(), timeout, error)) {
        out["error"] = error;
        out["elapsed_ms"] = GetTickCount64() - started;
        closesocket(s);
        return tool_result_t::error("Heartbleed probe failed to send ClientHello", "tls_send_failed", out);
    }
    std::vector<std::uint8_t> handshake;
    ns_tls_probe_result_t negotiation;
    negotiation.label = profile.label;
    negotiation.connected = true;
    negotiation.sent = true;
    while (!ns_tls_cancelled_or_deadline() && handshake.size() < 32768) {
        std::string recv_error;
        if (!ns_tls_recv_some(s, handshake, ns_tls_timeout_ms(std::min<DWORD>(timeout, 2500)), 8192, recv_error)) {
            if (negotiation.error.empty())
                negotiation.error = recv_error;
            break;
        }
        ns_tls_parse_records(handshake, negotiation);
        if (negotiation.got_alert || negotiation.server_hello_done || negotiation.heartbeat_extension)
            break;
    }
    negotiation.bytes_received = handshake.size();
    negotiation.elapsed_ms = GetTickCount64() - started;
    out["negotiation"] = ns_tls_probe_json(negotiation);
    if (!negotiation.heartbeat_extension && !params.value("force_probe", false)) {
        out["vulnerable"] = false;
        out["status"] = "heartbeat_extension_not_negotiated";
        out["elapsed_ms"] = GetTickCount64() - started;
        closesocket(s);
        return tool_result_t::ok("Heartbleed probe completed; server did not negotiate heartbeat.", out);
    }
    std::vector<std::uint8_t> hb;
    hb.push_back(24);
    ns_tls_put_u16(hb, negotiation.record_version ? negotiation.record_version : 0x0302);
    std::vector<std::uint8_t> msg;
    msg.push_back(1);
    ns_tls_put_u16(msg, 0x4000);
    msg.push_back('A');
    for (int i = 0; i < 16; ++i)
        msg.push_back(static_cast<std::uint8_t>(i));
    ns_tls_put_u16(hb, static_cast<std::uint16_t>(msg.size()));
    hb.insert(hb.end(), msg.begin(), msg.end());
    if (!ns_tls_send_all(s, hb.data(), hb.size(), timeout, error)) {
        out["error"] = error;
        out["elapsed_ms"] = GetTickCount64() - started;
        closesocket(s);
        return tool_result_t::error("Heartbleed heartbeat request send failed", "tls_send_failed", out);
    }
    json hb_evidence;
    const bool vulnerable = ns_tls_read_heartbeat_response(s, timeout, hb_evidence);
    closesocket(s);
    out["heartbeat_request"] = {{"declared_payload_length", 0x4000}, {"actual_payload_bytes", 1}, {"padding_bytes", 16}};
    out["heartbeat_response"] = hb_evidence;
    out["vulnerable"] = vulnerable;
    out["status"] = vulnerable ? "heartbeat_overread_response_observed" : "no_overread_response_observed";
    out["elapsed_ms"] = GetTickCount64() - started;
    return tool_result_t::ok("Heartbleed probe complete", out);
}

static tool_result_t aida_tls_test_crime(const json& params)
{
    if (!params.is_object() || !params.contains("host") || !params["host"].is_string())
        return tool_result_t::error("host is required");
    const std::string host = params["host"].get<std::string>();
    if (!ns_tls_valid_host(host))
        return tool_result_t::error("host is invalid");
    std::uint16_t port = 443;
    if (!ns_json_u16_param(params, "port", port, 443))
        return tool_result_t::error("port must be 1..65535");
    const DWORD timeout = static_cast<DWORD>(std::max(500, std::min(params.value("timeout_ms", 6000), 15000)));
    ns_tls_probe_profile_t profile = ns_tls_assess_profile("crime_tls_compression", 0x0303);
    profile.supported_versions.clear();
    profile.compressions = {0, 1};
    auto probe = ns_tls_raw_probe(host, port, profile, timeout, 32768);
    json out;
    out["host"] = host;
    out["port"] = port;
    out["bounded"] = true;
    out["probe"] = ns_tls_probe_json(probe);
    out["offered_compression_methods"] = json::array({0, 1});
    out["selected_compression"] = probe.got_server_hello ? json(probe.compression) : json(nullptr);
    out["vulnerable"] = probe.got_server_hello && probe.compression != 0xff && probe.compression != 0;
    out["status"] = !probe.got_server_hello ? "no_server_hello" : (out["vulnerable"].get<bool>() ? "tls_compression_negotiated" : "tls_compression_not_negotiated");
    if (!probe.got_server_hello)
        return tool_result_t::error("CRIME probe did not receive a ServerHello", "tls_no_server_hello", out);
    return tool_result_t::ok("CRIME TLS compression probe complete", out);
}

tool_result_t tls_extract_keys(const json& params) {
    auto config = ns_key_scan_config_from_params(params, 9000, 64);
    diag::log_tagged_fmt("net_sec", "tls_extract_keys entry pid=%u scan_schannel=%d scan_openssl=%d scan_nss=%d scan_boringssl=%d scan_generic=%d scan_tls13=%d timeout_ms=%u max_results=%u hint=0x%llX hint_size=%u hint_only=%d",
        config.pid,
        (int)params.value("scan_schannel", true),
        (int)params.value("scan_openssl", true),
        (int)params.value("scan_nss", true),
        (int)params.value("scan_boringssl", true),
        config.scan_generic ? 1 : 0,
        config.scan_tls13_structures ? 1 : 0,
        config.timeout_ms,
        config.max_results,
        static_cast<unsigned long long>(config.hint_address),
        config.hint_size,
        config.hint_only ? 1 : 0);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "tls_extract_keys driver not connected");
        return tool_result_t::error(std::string("Driver not connected"));
    }
    if (driver_bridge::attached_pid() == 0) {
        json r;
        r["driver_connected"] = true;
        r["driver_attached_pid"] = 0;
        r["driver_status"] = driver_bridge::status();
        r["driver_last_error"] = driver_bridge::last_error();
        diag::log_tagged("net_sec", "tls_extract_keys no process attached");
        return tool_result_t::error(std::string("No process attached to driver. DTB resolution may have failed."), r);
    }

    auto keys = net_security::TlsKeyExtractor::instance().extract_keys(config);
    auto scan_diag = net_security::TlsKeyExtractor::instance().last_tls_scan_diagnostics();
    diag::log_tagged_fmt("net_sec", "tls_extract_keys keys_found=%zu requested_pid=%u effective_pid=%u elapsed_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d",
        keys.size(),
        config.pid,
        scan_diag.effective_pid,
        static_cast<unsigned long long>(scan_diag.elapsed_ms),
        scan_diag.early_exit_reason.c_str(),
        scan_diag.deadline_expired ? 1 : 0,
        scan_diag.cancelled ? 1 : 0,
        scan_diag.truncated ? 1 : 0);
    json result;
    result["keys_found"] = keys.size();
    result["requested_pid"] = config.pid;
    result["effective_pid"] = scan_diag.effective_pid;
    result["driver_attached_pid"] = driver_bridge::attached_pid();
    result["scan"] = ns_key_scan_diag_json(scan_diag);
    result["deadline_expired"] = scan_diag.deadline_expired;
    result["cancelled"] = scan_diag.cancelled;
    result["truncated"] = scan_diag.truncated;
    result["bounded"] = true;
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["label"] = k.label;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["secret"] = ns_bytes_to_hex(k.secret.data(), k.secret.size());
        kj["tls_version"] = k.tls_version;
        kj["pid"] = k.pid;
        kj["library"] = k.library;
        kj["timestamp"] = k.timestamp;
        diag::log_tagged_fmt("net_sec", "tls_extract_keys key label=%s library=%s pid=%u", k.label.c_str(), k.library.c_str(), k.pid);
        arr.push_back(kj);
    }
    result["keys"] = arr;
    if (config.hint_only && (!scan_diag.hint_used || scan_diag.early_exit_reason == "hint_missing"))
        return tool_result_t::error(std::string("TLS key extraction hint range was not available"), result);
    if (keys.empty() && (scan_diag.deadline_expired || scan_diag.cancelled))
        return tool_result_t::error(scan_diag.deadline_expired ? std::string("TLS key extraction exceeded scan deadline") : std::string("TLS key extraction cancelled"), result);
    return tool_result_t::ok(std::string("Extracted ") + std::to_string(keys.size()) + std::string(" TLS session keys"), result);
}

tool_result_t tls_start_keylog(const json& params) {
    diag::log_tagged_fmt("net_sec", "tls_start_keylog entry pid=%u output_file=%s poll_interval_ms=%u",
        params.value("pid", 0u),
        params.value("output_file", "").c_str(),
        params.value("poll_interval_ms", 2000u));
    net_security::keylog_config_t config;
    config.pid = params.value("pid", 0u);
    config.output_file = params.value("output_file", "");
    config.poll_interval_ms = params.value("poll_interval_ms", 2000u);
    config.scan_timeout_ms = ns_json_u32_bounded_param(params, "scan_timeout_ms", 1500, 100, 60000);
    config.stop_wait_ms = ns_json_u32_bounded_param(params, "stop_wait_ms", 350, 50, 5000);
    config.max_results = ns_json_u32_bounded_param(params, "max_results", 16, 1, 4096);
    if (params.contains("max_keys"))
        config.max_results = ns_json_u32_bounded_param(params, "max_keys", config.max_results, 1, 4096);
    config.scan_schannel = params.value("scan_schannel", true);
    config.scan_openssl = params.value("scan_openssl", true);
    config.scan_nss = params.value("scan_nss", true);
    config.scan_boringssl = params.value("scan_boringssl", true);
    config.scan_generic = params.value("scan_generic", true);
    config.scan_tls13_structures = params.value("scan_tls13_structures", true);
    config.hint_address = ns_json_u64_param(params, "hint_address", 0);
    if (config.hint_address == 0)
        config.hint_address = ns_json_u64_param(params, "memory_hint_address", 0);
    config.hint_size = ns_json_u32_bounded_param(params, "hint_size", 0, 0, 0x10000000);
    if (config.hint_size == 0)
        config.hint_size = ns_json_u32_bounded_param(params, "memory_hint_size", 0, 0, 0x10000000);
    config.hint_only = params.value("hint_only", false) || params.value("memory_hint_only", false);
    config.append = params.value("append", true);

    if (config.output_file.empty()) {
        config.output_file = ns_get_downloads_folder() + "\\sslkeylog.txt";
        diag::log_tagged_fmt("net_sec", "tls_start_keylog using default output_file=%s", config.output_file.c_str());
    }

    auto& extractor = net_security::TlsKeyExtractor::instance();
    auto& ledger_state = ns_tls_keylog_session_state();
    const std::uint64_t call_start_ms = ns_now_ms();
    const bool extractor_active_before = extractor.is_keylogging();
    const auto seen_before = extractor.get_seen_keys();
    const auto file_before = ns_probe_keylog_file(config.output_file);
    json ledger_before;
    bool ledger_active_before = false;
    std::uint64_t ledger_session_before = 0;
    {
        std::lock_guard<std::mutex> lock(ledger_state.mutex);
        ledger_before = ns_tls_keylog_ledger_json(ledger_state);
        ledger_active_before = ledger_state.active;
        ledger_session_before = ledger_state.session_id;
    }

    bool started = extractor.start_keylog(config);
    const DWORD gle = GetLastError();
    const std::uint64_t elapsed_ms = ns_now_ms() - call_start_ms;
    const bool extractor_active_after = extractor.is_keylogging();
    const auto seen_after = extractor.get_seen_keys();
    const auto file_after = ns_probe_keylog_file(config.output_file);

    json r;
    r["status"] = started ? "started" : "not_started";
    r["session_id"] = 0;
    r["session_owner"] = "mcp_tls_manage";
    r["pid"] = config.pid;
    r["output_file"] = config.output_file;
    r["poll_interval_ms"] = config.poll_interval_ms;
    r["scan_timeout_ms"] = config.scan_timeout_ms;
    r["stop_wait_ms"] = config.stop_wait_ms;
    r["max_results"] = config.max_results;
    r["hint_address"] = config.hint_address;
    r["hint_size"] = config.hint_size;
    r["hint_only"] = config.hint_only;
    r["append"] = config.append;
    r["active_before"] = extractor_active_before || ledger_active_before;
    r["active_after"] = extractor_active_after;
    r["extractor_active_before"] = extractor_active_before;
    r["extractor_active_after"] = extractor_active_after;
    r["ledger_active_before"] = ledger_active_before;
    r["ledger_session_before"] = ledger_session_before;
    r["key_count_start"] = static_cast<std::uint64_t>(seen_before.size());
    r["key_count_after"] = static_cast<std::uint64_t>(seen_after.size());
    r["file_before"] = ns_keylog_probe_to_json(file_before);
    r["file_after"] = ns_keylog_probe_to_json(file_after);
    r["worker_enter_reason"] = started ? "executor_service_posted" : "not_posted";
    r["worker_exit_reason"] = started ? "worker_running" : "start_rejected";
    r["win32_last_error"] = static_cast<unsigned long>(gle);
    r["elapsed_ms"] = elapsed_ms;

    std::uint64_t session_id = 0;
    if (started) {
        {
            std::lock_guard<std::mutex> lock(ledger_state.mutex);
            session_id = ledger_state.next_session_id++;
            ledger_state.active = true;
            ledger_state.session_id = session_id;
            ledger_state.pid = config.pid;
            ledger_state.poll_interval_ms = config.poll_interval_ms;
            ledger_state.append = config.append;
            ledger_state.output_file = config.output_file;
            ledger_state.started_ms = call_start_ms;
            ledger_state.stopped_ms = 0;
            ledger_state.key_count_start = seen_before.size();
            ledger_state.last_error.clear();
            ++ledger_state.starts;
            r["ledger_after"] = ns_tls_keylog_ledger_json(ledger_state);
        }
        r["session_id"] = session_id;
        r["ledger_active_after"] = true;
        diag::log_tagged_fmt("net_sec", "tls_start_keylog started=1 session_id=%llu active_before=%d active_after=%d pid=%u output_file=%s elapsed_ms=%llu keys_before=%zu keys_after=%zu",
            static_cast<unsigned long long>(session_id),
            (extractor_active_before || ledger_active_before) ? 1 : 0,
            extractor_active_after ? 1 : 0,
            config.pid,
            config.output_file.c_str(),
            static_cast<unsigned long long>(elapsed_ms),
            seen_before.size(),
            seen_after.size());
        return tool_result_t::ok(std::string("TLS keylogging started -> ") + config.output_file, r);
    }

    const std::string early_reason = ledger_active_before ? "mcp_session_already_active" :
        (extractor_active_before ? "extractor_already_active" : "extractor_start_failed");
    r["early_exit_reason"] = early_reason;
    {
        std::lock_guard<std::mutex> lock(ledger_state.mutex);
        ledger_state.last_error = early_reason;
        r["ledger_after"] = ns_tls_keylog_ledger_json(ledger_state);
        r["ledger_active_after"] = ledger_state.active;
        r["session_id"] = ledger_state.active ? ledger_state.session_id : 0;
    }
    diag::log_tagged_fmt("net_sec", "tls_start_keylog started=0 reason=%s ledger_active_before=%d extractor_active_before=%d active_after=%d gle=%lu output_file=%s elapsed_ms=%llu",
        early_reason.c_str(),
        ledger_active_before ? 1 : 0,
        extractor_active_before ? 1 : 0,
        extractor_active_after ? 1 : 0,
        static_cast<unsigned long>(gle),
        config.output_file.c_str(),
        static_cast<unsigned long long>(elapsed_ms));
    return tool_result_t::error(std::string("Keylogging already active or failed to start"), r);
}

tool_result_t tls_stop_keylog(const json& params) {
    const std::uint64_t requested_session_id = ns_json_u64_param(params, "session_id", 0);
    diag::log_tagged_fmt("net_sec", "tls_stop_keylog entry requested_session_id=%llu",
        static_cast<unsigned long long>(requested_session_id));
    auto& extractor = net_security::TlsKeyExtractor::instance();
    auto& ledger_state = ns_tls_keylog_session_state();
    const std::uint64_t call_start_ms = ns_now_ms();
    const bool extractor_active_before = extractor.is_keylogging();
    const auto seen_before = extractor.get_seen_keys();

    json ledger_before;
    bool ledger_active_before = false;
    std::uint64_t ledger_session_before = 0;
    std::string ledger_output_file;
    std::uint64_t ledger_started_ms = 0;
    std::size_t ledger_key_count_start = 0;
    {
        std::lock_guard<std::mutex> lock(ledger_state.mutex);
        ledger_before = ns_tls_keylog_ledger_json(ledger_state);
        ledger_active_before = ledger_state.active;
        ledger_session_before = ledger_state.session_id;
        ledger_output_file = ledger_state.output_file;
        ledger_started_ms = ledger_state.started_ms;
        ledger_key_count_start = ledger_state.key_count_start;
    }

    json r;
    r["requested_session_id"] = requested_session_id;
    r["session_id"] = ledger_session_before;
    r["session_owner"] = ledger_active_before ? "mcp_tls_manage" : "unknown_or_external";
    r["active_before"] = extractor_active_before || ledger_active_before;
    r["extractor_active_before"] = extractor_active_before;
    r["ledger_active_before"] = ledger_active_before;
    r["ledger_before"] = ledger_before;
    r["output_file"] = ledger_output_file;
    r["key_count_start"] = static_cast<std::uint64_t>(ledger_key_count_start);
    r["key_count_before"] = static_cast<std::uint64_t>(seen_before.size());
    r["worker_enter_reason"] = "tls_stop_keylog_requested";

    auto finish_error = [&](const std::string& reason, const std::string& message) -> tool_result_t {
        const bool extractor_active_after = extractor.is_keylogging();
        const auto seen_after = extractor.get_seen_keys();
        const auto file_after = ns_probe_keylog_file(ledger_output_file);
        r["status"] = "not_stopped";
        r["early_exit_reason"] = reason;
        r["stop_attempted"] = false;
        r["stop_succeeded"] = false;
        r["active_after"] = extractor_active_after;
        r["extractor_active_after"] = extractor_active_after;
        r["key_count_after"] = static_cast<std::uint64_t>(seen_after.size());
        r["file_after"] = ns_keylog_probe_to_json(file_after);
        r["elapsed_ms"] = ns_now_ms() - call_start_ms;
        r["worker_exit_reason"] = reason;
        {
            std::lock_guard<std::mutex> lock(ledger_state.mutex);
            const bool same_session = ledger_state.session_id == ledger_session_before;
            if (same_session)
                ledger_state.last_error = reason;
            else
                r["ledger_update_skipped_newer_session"] = true;
            r["ledger_active_after"] = ledger_state.active;
            r["ledger_after"] = ns_tls_keylog_ledger_json(ledger_state);
        }
        diag::log_tagged_fmt("net_sec", "tls_stop_keylog early_exit reason=%s requested_session_id=%llu ledger_session=%llu ledger_active=%d extractor_active=%d elapsed_ms=%llu",
            reason.c_str(),
            static_cast<unsigned long long>(requested_session_id),
            static_cast<unsigned long long>(ledger_session_before),
            ledger_active_before ? 1 : 0,
            extractor_active_before ? 1 : 0,
            static_cast<unsigned long long>(r["elapsed_ms"].get<std::uint64_t>()));
        return tool_result_t::error(message, r);
    };

    if (requested_session_id != 0 && (!ledger_active_before || requested_session_id != ledger_session_before))
        return finish_error("session_id_mismatch", std::string("Requested TLS keylog session is not active"));

    if (!extractor_active_before && !ledger_active_before)
        return finish_error("no_active_keylog_session", std::string("No active keylogging session"));

    if (!extractor_active_before && ledger_active_before) {
        {
            std::lock_guard<std::mutex> lock(ledger_state.mutex);
            if (ledger_state.session_id == ledger_session_before) {
                ledger_state.active = false;
                ledger_state.stopped_ms = call_start_ms;
                ledger_state.last_error = "mcp_session_stale_inactive_extractor";
            } else {
                r["ledger_stale_clear_skipped_newer_session"] = true;
            }
        }
        return finish_error("mcp_session_stale_inactive_extractor", std::string("TLS keylog session was stale; extractor was inactive"));
    }

    const auto file_before = ns_probe_keylog_file(ledger_output_file);
    bool stopped = extractor.stop_keylog();
    const DWORD gle = GetLastError();
    const std::uint64_t elapsed_ms = ns_now_ms() - call_start_ms;
    const bool extractor_active_after = extractor.is_keylogging();
    const auto seen_after = extractor.get_seen_keys();
    const auto file_after = ns_probe_keylog_file(ledger_output_file);
    const bool stop_accepted = stopped || !extractor_active_after;
    r["status"] = stopped ? "stopped" : (stop_accepted ? "stopping" : "stop_failed");
    r["stop_attempted"] = true;
    r["stop_succeeded"] = stop_accepted;
    r["worker_done"] = stopped;
    r["bounded_stop"] = true;
    r["stop_wait_timeout"] = !stopped && stop_accepted;
    r["active_after"] = extractor_active_after;
    r["extractor_active_after"] = extractor_active_after;
    r["key_count_after"] = static_cast<std::uint64_t>(seen_after.size());
    r["keys_added_during_session"] = static_cast<std::uint64_t>(seen_after.size() >= ledger_key_count_start ? seen_after.size() - ledger_key_count_start : 0);
    r["file_before"] = ns_keylog_probe_to_json(file_before);
    r["file_after"] = ns_keylog_probe_to_json(file_after);
    r["win32_last_error"] = static_cast<unsigned long>(gle);
    r["elapsed_ms"] = elapsed_ms;
    r["lifetime_ms"] = ledger_started_ms != 0 && call_start_ms >= ledger_started_ms ? call_start_ms - ledger_started_ms : 0;
    r["worker_exit_reason"] = stopped ? "extractor_worker_done" : (stop_accepted ? "extractor_worker_unwinding_after_bounded_stop" : "extractor_stop_failed_or_timeout");

    {
        std::lock_guard<std::mutex> lock(ledger_state.mutex);
        const bool same_session = ledger_state.session_id == ledger_session_before;
        if (stop_accepted && same_session) {
            ledger_state.active = false;
            ledger_state.stopped_ms = call_start_ms;
            ledger_state.last_error = stopped ? "" : "extractor_worker_unwinding_after_bounded_stop";
            ++ledger_state.stops;
        } else if (same_session) {
            ledger_state.last_error = "extractor_stop_failed_or_timeout";
        } else {
            r["ledger_stop_update_skipped_newer_session"] = true;
        }
        r["ledger_active_after"] = ledger_state.active;
        r["ledger_after"] = ns_tls_keylog_ledger_json(ledger_state);
    }

    diag::log_tagged_fmt("net_sec", "tls_stop_keylog stopped=%d stop_accepted=%d worker_done=%d session_id=%llu requested_session_id=%llu active_before=%d active_after=%d elapsed_ms=%llu lifetime_ms=%llu keys_before=%zu keys_after=%zu output_file=%s gle=%lu",
        stopped ? 1 : 0,
        stop_accepted ? 1 : 0,
        stopped ? 1 : 0,
        static_cast<unsigned long long>(ledger_session_before),
        static_cast<unsigned long long>(requested_session_id),
        (extractor_active_before || ledger_active_before) ? 1 : 0,
        extractor_active_after ? 1 : 0,
        static_cast<unsigned long long>(elapsed_ms),
        static_cast<unsigned long long>(r["lifetime_ms"].get<std::uint64_t>()),
        seen_before.size(),
        seen_after.size(),
        ledger_output_file.c_str(),
        static_cast<unsigned long>(gle));
    if (stop_accepted)
        return tool_result_t::ok(stopped ? std::string("TLS keylogging stopped") : std::string("TLS keylogging stop accepted; worker is unwinding"), r);
    return tool_result_t::error(std::string("TLS keylogging stop failed"), r);
}

tool_result_t tls_get_extracted_keys(const json&) {
    diag::log_tagged("net_sec", "tls_get_extracted_keys entry");
    auto& ext = net_security::TlsKeyExtractor::instance();
    auto seen = ext.get_seen_keys();
    diag::log_tagged_fmt("net_sec", "tls_get_extracted_keys total_keys=%zu", seen.size());

    json result;
    result["total_keys"] = seen.size();
    json arr = json::array();
    for (const auto& [key, val] : seen) {
        json kj;
        kj["label"] = val.label;
        kj["client_random"] = ns_bytes_to_hex(val.client_random.data(), val.client_random.size());
        kj["secret"] = ns_bytes_to_hex(val.secret.data(), val.secret.size());
        kj["library"] = val.library;
        kj["pid"] = val.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    return tool_result_t::ok(std::string("Retrieved ") + std::to_string(seen.size()) + std::string(" cached TLS keys"), result);
}

tool_result_t cert_inject(const json& params) {
    const bool validate_only = params.contains("validate_only") &&
        params["validate_only"].is_boolean() &&
        params["validate_only"].get<bool>();
    diag::log_tagged_fmt("net_sec", "cert_inject entry store_name=%s system_wide=%d has_pem=%d has_der_hex=%d validate_only=%d",
        params.value("store_name", "ROOT").c_str(),
        (int)params.value("system_wide", false),
        (int)params.contains("cert_pem"),
        (int)params.contains("cert_der_hex"),
        validate_only ? 1 : 0);
    net_security::cert_injection_config_t config;
    config.cert_pem = params.value("cert_pem", "");
    config.store_name = params.value("store_name", "ROOT");
    config.system_wide = params.value("system_wide", false);

    if (params.contains("cert_der_hex") && params["cert_der_hex"].is_string()) {
        auto hex = params["cert_der_hex"].get<std::string>();
        if (!ns_hex_to_bytes_strict(hex, config.cert_der))
            return tool_result_t::error(std::string("cert_der_hex is not valid hex DER data"));
        diag::log_tagged_fmt("net_sec", "cert_inject der_hex len=%zu bytes=%zu", hex.size(), config.cert_der.size());
    }

    if (validate_only) {
        std::vector<std::uint8_t> der;
        std::string format;
        if (params.contains("cert_der_hex")) {
            if (!params["cert_der_hex"].is_string())
                return tool_result_t::error(std::string("cert_der_hex must be a string"));
            if (!ns_hex_to_bytes_strict(params["cert_der_hex"].get<std::string>(), der))
                return tool_result_t::error(std::string("cert_der_hex is not valid hex DER data"));
            format = std::string("der_hex");
        } else if (params.contains("cert_pem")) {
            if (!params["cert_pem"].is_string())
                return tool_result_t::error(std::string("cert_pem must be a string"));
            if (!ns_decode_pem_certificate_der(params["cert_pem"].get<std::string>(), der))
                return tool_result_t::error(std::string("cert_pem is not a valid PEM certificate"));
            format = std::string("pem");
        } else {
            return tool_result_t::error(std::string("cert_pem or cert_der_hex is required"));
        }
        std::string subject;
        if (!ns_is_valid_certificate_der(der, subject))
            return tool_result_t::error(std::string("certificate data is not a valid X.509 certificate"));
        json r;
        r["success"] = true;
        r["validate_only"] = true;
        r["format"] = format;
        r["cert_size"] = der.size();
        r["subject_cn"] = subject;
        r["store_name"] = config.store_name;
        r["system_wide"] = config.system_wide;
        return tool_result_t::ok(std::string("Validated certificate injection request without modifying the certificate store."), r);
    }

    auto result = net_security::CertificateInjector::instance().inject_certificate(config);
    diag::log_tagged_fmt("net_sec", "cert_inject result success=%d thumbprint=%s subject_cn=%s store=%s method=%s",
        (int)result.success, result.thumbprint.c_str(), result.subject_cn.c_str(), result.store_name.c_str(), result.method.c_str());
    json r;
    r["success"] = result.success;
    r["thumbprint"] = result.thumbprint;
    r["subject_cn"] = result.subject_cn;
    r["store_name"] = result.store_name;
    r["method"] = result.method;
    if (result.success)
        return tool_result_t::ok(std::string("Certificate injected: ") + result.subject_cn, r);
    return tool_result_t::error(std::string("Certificate injection failed"), r);
}

tool_result_t cert_remove(const json& params) {
    std::string thumbprint = params.value("thumbprint", "");
    std::string store_name = params.value("store_name", "ROOT");
    const bool validate_only = params.contains("validate_only") &&
        params["validate_only"].is_boolean() &&
        params["validate_only"].get<bool>();
    diag::log_tagged_fmt("net_sec", "cert_remove entry thumbprint=%s store_name=%s validate_only=%d", thumbprint.c_str(), store_name.c_str(), validate_only ? 1 : 0);
    if (thumbprint.empty()) {
        diag::log_tagged("net_sec", "cert_remove thumbprint empty -> error");
        return tool_result_t::error(std::string("thumbprint is required"));
    }

    if (validate_only) {
        if (!ns_valid_sha1_thumbprint_text(thumbprint))
            return tool_result_t::error(std::string("thumbprint must be a 40-hex-character SHA-1 certificate thumbprint"));
        json r;
        r["removed"] = false;
        r["validate_only"] = true;
        r["thumbprint"] = thumbprint;
        r["store_name"] = store_name;
        return tool_result_t::ok(std::string("Validated certificate removal request without modifying the certificate store."), r);
    }

    bool removed = net_security::CertificateInjector::instance().remove_certificate(thumbprint, store_name);
    diag::log_tagged_fmt("net_sec", "cert_remove removed=%d thumbprint=%s", (int)removed, thumbprint.c_str());
    if (removed) {
        json r;
        r["removed"] = true;
        r["thumbprint"] = thumbprint;
        return tool_result_t::ok(std::string("Certificate removed"), r);
    }
    return tool_result_t::error(std::string("Failed to remove certificate"));
}

tool_result_t cert_generate_ca(const json& params) {
    std::string cn = params.value("cn", "AiDA Proxy CA");
    std::uint32_t days = params.value("validity_days", 3650u);
    const bool validate_only = params.contains("validate_only") &&
        params["validate_only"].is_boolean() &&
        params["validate_only"].get<bool>();
    diag::log_tagged_fmt("net_sec", "cert_generate_ca entry cn=%s days=%u validate_only=%d", cn.c_str(), days, validate_only ? 1 : 0);

    if (validate_only) {
        if (!cert_generator::is_ready() && !cert_generator::initialize())
            return tool_result_t::error(std::string("AiDA CA is not ready"));
        std::vector<std::uint8_t> cert_der;
        if (!cert_generator::export_ca_certificate_der(cert_generator::get_root_ca(), cert_der) || cert_der.empty())
            return tool_result_t::error(std::string("Failed to export AiDA public CA certificate"));
        std::string subject;
        if (!ns_is_valid_certificate_der(cert_der, subject))
            return tool_result_t::error(std::string("Generated CA certificate did not validate as X.509"));
        json r;
        r["success"] = true;
        r["validate_only"] = true;
        r["private_key_exported"] = false;
        r["cert_size"] = cert_der.size();
        r["subject_cn"] = subject.empty() ? cn : subject;
        r["validity_days"] = days;
        return tool_result_t::ok(std::string("Validated public CA certificate generation path without exporting private key material"), r);
    }

    std::vector<std::uint8_t> cert_der;
    std::string subject_cn;
    bool ok = cert_generator::generate_public_ca_certificate_der(cn, days, cert_der, subject_cn);
    diag::log_tagged_fmt("net_sec", "cert_generate_ca ok=%d cert_size=%zu cn=%s subject=%s",
        (int)ok, cert_der.size(), cn.c_str(), subject_cn.c_str());
    json r;
    r["success"] = ok;
    r["backend"] = "openssl_public_der";
    r["private_key_exported"] = false;
    r["cert_size"] = cert_der.size();
    r["subject_cn"] = subject_cn.empty() ? cn : subject_cn;
    r["validity_days"] = days;
    if (ok) {
        r["cert_der_hex"] = ns_bytes_to_hex(cert_der.data(), cert_der.size());
        return tool_result_t::ok(std::string("Generated public CA certificate: ") + cn, r);
    }
    return tool_result_t::error(std::string("Failed to generate CA certificate"), r);
}

tool_result_t cert_list(const json& params) {
    std::string store_name = params.value("store_name", "ROOT");
    diag::log_tagged_fmt("net_sec", "cert_list entry store_name=%s", store_name.c_str());
    auto certs = net_security::CertificateInjector::instance().list_certificates(store_name);
    diag::log_tagged_fmt("net_sec", "cert_list count=%zu store_name=%s", certs.size(), store_name.c_str());

    json result;
    result["store_name"] = store_name;
    result["count"] = certs.size();
    json arr = json::array();
    for (const auto& c : certs) {
        json cj;
        cj["thumbprint"] = c.thumbprint;
        cj["subject"] = c.subject;
        cj["issuer"] = c.issuer;
        cj["not_before"] = c.not_before;
        cj["not_after"] = c.not_after;
        cj["is_ca"] = c.is_ca;
        arr.push_back(cj);
    }
    result["certificates"] = arr;
    return tool_result_t::ok(std::string("Listed ") + std::to_string(certs.size()) + std::string(" certificates"), result);
}

tool_result_t pin_bypass(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    std::string method = params.value("method", "all");
    diag::log_tagged_fmt("net_sec", "pin_bypass entry pid=%u method=%s", pid, method.c_str());
    const std::string method_lc = ns_lower_copy(method);
    net_security::pin_bypass_method parsed_method = net_security::pin_bypass_method::all;
    if (!ns_pin_method_from_string(method_lc, parsed_method)) {
        json r;
        r["success"] = false;
        r["camoufox_only"] = true;
        r["supported_browser"] = "camoufox";
        r["unsupported_method"] = method;
        return tool_result_t::error(std::string("Unsupported certificate diagnostic method; Camoufox is the only AiDA browser"), r);
    }
    if (pid == 0 && device && device->is_connected()) pid = device->get_process_id();

    net_security::pin_bypass_config_t config;
    config.pid = pid;
    config.method = parsed_method;

    auto legacy = net_security::CertPinBypasser::instance().bypass_pins(config);
    auto context = ns_make_diagnostic_context(params);
    auto diagnostics = cert_intercept::diagnose_process(pid, context);
    auto providers = cert_intercept::provider_registry_t::instance().evaluate(pid, diagnostics);
    diag::log_tagged_fmt("net_sec", "pin_bypass diagnostics primary=%s providers=%zu pid=%u",
        cert_intercept::to_string(diagnostics.primary).c_str(), providers.size(), pid);

    json r;
    r["success"] = false;
    r["pid"] = pid;
    r["read_only"] = true;
    r["target_process_modified"] = false;
    r["legacy_patching_disabled"] = legacy.legacy_patching_disabled;
    r["diagnostic_summary"] = legacy.diagnostic_summary;
    r["recommended_action"] = legacy.recommended_action;
    r["methods_requested"] = legacy.methods_requested;
    r["disabled_operations"] = legacy.disabled_operations;
    r["diagnostics"] = ns_diagnostics_to_json(diagnostics);
    r["providers"] = json::array();
    for (const auto& provider : providers) r["providers"].push_back(ns_provider_to_json(provider));
    return tool_result_t::ok(std::string("Certificate interception diagnostics completed without process modification"), r);
}

tool_result_t quic_detect_connections(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "quic_detect_connections entry pid=%u", pid);
    if (ns_has_payload_hex_param(params)) {
        const std::string hex = ns_payload_hex_param(params);
        std::vector<std::uint8_t> payload;
        if (!ns_hex_to_bytes_strict(hex, payload)) {
            json r;
            r["backend"] = "provided_payload";
            r["deterministic_input"] = true;
            r["parser_rejection_reason"] = hex.empty() ? "empty_payload_hex" : "invalid_payload_hex";
            return tool_result_t::error(std::string("Invalid QUIC payload_hex"), r);
        }
        net_security::QuicAnalyzer::quic_header_t hdr;
        std::size_t offset = 0;
        std::string rejection;
        const bool parsed = ns_parse_quic_payload_with_offset(payload, hdr, offset, rejection);
        json result;
        result["backend"] = "provided_payload";
        result["capture_performed"] = false;
        result["deterministic_input"] = true;
        result["pid"] = pid;
        result["payload_bytes"] = payload.size();
        result["payload_hex_preview"] = ns_bytes_to_hex(payload.data(), std::min<std::size_t>(payload.size(), 96));
        result["payload_sha256"] = ns_sha256_hex(payload.data(), payload.size());
        result["parser_offset"] = offset;
        result["parser_rejection_reason"] = rejection;
        result["header_classification"] = parsed ? (hdr.is_long_header ? "quic_long_header" : "quic_short_header") : "unclassified";
        result["is_long_header"] = parsed && hdr.is_long_header;
        result["quic_version"] = parsed ? hdr.version : 0u;
        result["dcid"] = parsed ? ns_bytes_to_hex(hdr.dcid.data(), hdr.dcid.size()) : "";
        result["scid"] = parsed ? ns_bytes_to_hex(hdr.scid.data(), hdr.scid.size()) : "";
        result["parser_only"] = true;
        result["state_contract_only"] = true;
        result["functional_evidence"] = false;
        result["capture_evidence"] = false;
        result["key_evidence"] = false;
        result["live_capture_required_for_functional"] = true;
        result["udp_live_stimulus_status"] = ns_udp_live_stimulus_status_json("quic");
        result["live_stimulus_owned_by"] = "testlab_harness";
        result["implementation_udp_stimulus_executor_available"] = false;
        result["live_capture_correlated"] = false;
        result["target_pid_correlated"] = false;
        result["tuple_correlated"] = false;
        result["payload_hash_correlated"] = false;
        result["nonce_correlated"] = false;
        result["capture_counter_delta"] = 0;
        result["functional_count"] = 0;
        result["parser_count"] = parsed ? 1 : 0;
        result["count"] = 0;
        json arr = json::array();
        if (parsed) {
            json cj;
            const std::uint32_t local_port = params.value("local_port", 40000u);
            const std::uint32_t remote_port = params.value("remote_port", 443u);
            cj["pid"] = pid;
            cj["src_port"] = local_port;
            cj["dst_port"] = remote_port;
            cj["dcid"] = ns_bytes_to_hex(hdr.dcid.data(), hdr.dcid.size());
            cj["scid"] = ns_bytes_to_hex(hdr.scid.data(), hdr.scid.size());
            cj["packets_sent"] = 1;
            cj["packets_recv"] = 0;
            cj["bytes_sent"] = payload.size();
            cj["bytes_recv"] = 0;
            cj["alpn"] = "h3";
            cj["quic_version"] = hdr.version;
            cj["parser_offset"] = offset;
            cj["payload_sha256"] = result["payload_sha256"];
            arr.push_back(std::move(cj));
        }
        result["connections"] = json::array();
        result["parser_connections"] = std::move(arr);
        result["zero_detection_reason"] = parsed ? "provided_payload_parser_only_no_driver_capture" : "provided_payload_parser_rejected";
        diag::log_tagged_fmt("net_sec", "quic_detect_connections provided_payload parsed=%d pid=%u bytes=%zu offset=%zu version=0x%08X dcid=%zu scid=%zu rejection=%s",
            parsed ? 1 : 0,
            pid,
            payload.size(),
            offset,
            parsed ? hdr.version : 0u,
            parsed ? hdr.dcid.size() : 0u,
            parsed ? hdr.scid.size() : 0u,
            rejection.empty() ? "<none>" : rejection.c_str());
        if (!parsed)
            return tool_result_t::error(std::string("QUIC payload did not parse as a connection"), result);
        return tool_result_t::ok(std::string("Parsed 1 QUIC payload as parser-only evidence"), result);
    }
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "quic_detect_connections driver not connected");
        json r;
        r["backend"] = "driver_capture";
        r["capture_performed"] = false;
        r["driver_connected"] = false;
        r["functional_evidence"] = false;
        r["live_capture_required_for_functional"] = true;
        r["udp_live_stimulus_status"] = ns_udp_live_stimulus_status_json("quic");
        r["live_stimulus_owned_by"] = "testlab_harness";
        r["implementation_udp_stimulus_executor_available"] = false;
        return tool_result_t::error(std::string("Driver not connected"), r);
    }

    bool cap_active_before = false;
    std::uint32_t cap_cnt_before = 0;
    std::uint32_t cap_drp_before = 0;
    device->get_capture_status(cap_active_before, cap_cnt_before, cap_drp_before);
    auto conns = net_security::QuicAnalyzer::instance().detect_quic_connections(pid);
    bool cap_active_after = false;
    std::uint32_t cap_cnt_after = 0;
    std::uint32_t cap_drp_after = 0;
    device->get_capture_status(cap_active_after, cap_cnt_after, cap_drp_after);
    std::uint32_t detection_attempts = 1;
    const DWORD wait_start = GetTickCount();
    DWORD capture_wait_elapsed_ms = 0;
    while ((conns.empty() || cap_cnt_after <= cap_cnt_before) && capture_wait_elapsed_ms < 750) {
        Sleep(25);
        ++detection_attempts;
        conns = net_security::QuicAnalyzer::instance().detect_quic_connections(pid);
        device->get_capture_status(cap_active_after, cap_cnt_after, cap_drp_after);
        capture_wait_elapsed_ms = GetTickCount() - wait_start;
    }
    diag::log_tagged_fmt("net_sec", "quic_detect_connections count=%zu pid=%u capture_before_active=%d capture_before_count=%u capture_before_dropped=%u capture_after_active=%d capture_after_count=%u capture_after_dropped=%u attempts=%u wait_ms=%lu",
        conns.size(),
        pid,
        cap_active_before ? 1 : 0,
        cap_cnt_before,
        cap_drp_before,
        cap_active_after ? 1 : 0,
        cap_cnt_after,
        cap_drp_after,
        detection_attempts,
        static_cast<unsigned long>(capture_wait_elapsed_ms));

    json result;
    result["backend"] = "driver_capture";
    result["capture_performed"] = true;
    result["deterministic_input"] = false;
    result["capture_active_before"] = cap_active_before;
    result["capture_count_before"] = cap_cnt_before;
    result["capture_dropped_before"] = cap_drp_before;
    result["capture_active_after"] = cap_active_after;
    result["capture_count_after"] = cap_cnt_after;
    result["capture_dropped_after"] = cap_drp_after;
    result["detection_attempts"] = detection_attempts;
    result["capture_wait_elapsed_ms"] = capture_wait_elapsed_ms;
    const std::uint32_t capture_delta = cap_cnt_after > cap_cnt_before ? (cap_cnt_after - cap_cnt_before) : 0;
    bool all_pid_correlated = !conns.empty();
    bool all_tuple_correlated = !conns.empty();
    bool all_hash_correlated = !conns.empty();
    bool all_nonce_correlated = !conns.empty();
    for (const auto& c : conns) {
        if (pid != 0 && c.pid != pid)
            all_pid_correlated = false;
        if (c.src_port == 0 || c.dst_port == 0)
            all_tuple_correlated = false;
        if (c.payload_sha256.empty() || c.capture_packet_count == 0)
            all_hash_correlated = false;
        if (c.dcid.empty() && c.scid.empty())
            all_nonce_correlated = false;
    }
    const bool functional = !conns.empty() && capture_delta > 0 && all_pid_correlated && all_tuple_correlated && all_hash_correlated && all_nonce_correlated;
    result["capture_counter_delta"] = capture_delta;
    result["parser_only"] = false;
    result["state_contract_only"] = !functional;
    result["functional_evidence"] = functional;
    result["capture_evidence"] = functional;
    result["key_evidence"] = false;
    result["live_capture_required_for_functional"] = true;
    result["udp_live_stimulus_status"] = ns_udp_live_stimulus_status_json("quic");
    result["live_stimulus_owned_by"] = "testlab_harness";
    result["implementation_udp_stimulus_executor_available"] = false;
    result["live_capture_correlated"] = functional;
    result["target_pid_correlated"] = all_pid_correlated;
    result["tuple_correlated"] = all_tuple_correlated;
    result["payload_hash_correlated"] = all_hash_correlated;
    result["nonce_correlated"] = all_nonce_correlated;
    result["detected_count"] = conns.size();
    result["functional_count"] = functional ? conns.size() : 0;
    result["parser_count"] = 0;
    result["count"] = functional ? conns.size() : 0;
    if (conns.empty())
        result["zero_detection_reason"] = cap_cnt_after == 0 ? "capture_queue_empty_or_not_drained_before_detector" : "no_quic_header_classified_from_captured_udp_payloads";
    else if (!functional)
        result["zero_detection_reason"] = capture_delta == 0 ? "captured_quic_packets_lacked_counter_delta_correlation" : "captured_quic_packets_lacked_pid_tuple_hash_or_nonce_correlation";
    json arr = json::array();
    for (const auto& c : conns) {
        json cj;
        cj["pid"] = c.pid;
        cj["src_port"] = c.src_port;
        cj["dst_port"] = c.dst_port;
        cj["dcid"] = ns_bytes_to_hex(c.dcid.data(), c.dcid.size());
        cj["scid"] = ns_bytes_to_hex(c.scid.data(), c.scid.size());
        cj["packets_sent"] = c.packets_sent;
        cj["packets_recv"] = c.packets_recv;
        cj["bytes_sent"] = c.bytes_sent;
        cj["bytes_recv"] = c.bytes_recv;
        cj["alpn"] = c.alpn;
        cj["capture_packet_count"] = c.capture_packet_count;
        cj["capture_byte_count"] = c.capture_byte_count;
        cj["parser_offset"] = c.parser_offset;
        cj["payload_sha256"] = c.payload_sha256;
        arr.push_back(cj);
    }
    result["captured_connections"] = arr;
    result["connections"] = functional ? arr : json::array();
    const std::string message = functional
        ? std::string("Detected ") + std::to_string(conns.size()) + std::string(" correlated QUIC connections")
        : std::string("Parsed QUIC capture candidates without functional correlation");
    return tool_result_t::ok(message, result);
}

tool_result_t quic_decrypt_initial(const json& params) {
    diag::log_tagged("net_sec", "quic_decrypt_initial entry");
    if (!params.contains("packet_hex")) {
        diag::log_tagged("net_sec", "quic_decrypt_initial missing packet_hex");
        return tool_result_t::error(std::string("packet_hex is required"));
    }

    std::vector<std::uint8_t> pkt_bytes;
    const bool packet_hex_valid = ns_hex_to_bytes_strict(params["packet_hex"].get<std::string>(), pkt_bytes);
    diag::log_tagged_fmt("net_sec", "quic_decrypt_initial packet_bytes=%zu", pkt_bytes.size());
    if (!packet_hex_valid) {
        diag::log_tagged("net_sec", "quic_decrypt_initial invalid packet hex data");
        return tool_result_t::error(std::string("Invalid packet hex data"));
    }

    auto result = net_security::QuicAnalyzer::instance().decrypt_initial_packet(pkt_bytes.data(), pkt_bytes.size());
    diag::log_tagged_fmt("net_sec", "quic_decrypt_initial result success=%d version=0x%x type=%s", (int)result.success, result.quic_version, result.packet_type.c_str());
    json r;
    r["success"] = result.success;
    r["quic_version"] = result.quic_version;
    r["packet_type"] = result.packet_type;
    r["dcid"] = ns_bytes_to_hex(result.dcid.data(), result.dcid.size());
    r["scid"] = ns_bytes_to_hex(result.scid.data(), result.scid.size());
    if (result.success)
        return tool_result_t::ok(std::string("QUIC Initial packet decoded"), r);
    return tool_result_t::error(std::string("Failed to decode QUIC Initial packet"));
}

tool_result_t quic_extract_keys(const json& params) {
    auto config = ns_key_scan_config_from_params(params, 9000, 64);
    diag::log_tagged_fmt("net_sec", "quic_extract_keys entry pid=%u timeout_ms=%u max_results=%u max_regions=%u max_reads=%u max_bytes=%llu hint=0x%llX hint_size=%u hint_only=%d",
        config.pid,
        config.timeout_ms,
        config.max_results,
        config.max_regions,
        config.max_read_attempts,
        static_cast<unsigned long long>(config.max_read_bytes),
        static_cast<unsigned long long>(config.hint_address),
        config.hint_size,
        config.hint_only ? 1 : 0);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "quic_extract_keys driver not connected");
        return tool_result_t::error(std::string("Driver not connected"));
    }

    auto keys = net_security::TlsKeyExtractor::instance().extract_quic_keys(config);
    auto scan_diag = net_security::TlsKeyExtractor::instance().last_quic_scan_diagnostics();
    diag::log_tagged_fmt("net_sec", "quic_extract_keys keys_found=%zu requested_pid=%u effective_pid=%u elapsed_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d",
        keys.size(),
        config.pid,
        scan_diag.effective_pid,
        static_cast<unsigned long long>(scan_diag.elapsed_ms),
        scan_diag.early_exit_reason.c_str(),
        scan_diag.deadline_expired ? 1 : 0,
        scan_diag.cancelled ? 1 : 0,
        scan_diag.truncated ? 1 : 0);

    json result;
    result["keys_found"] = keys.size();
    result["requested_pid"] = config.pid;
    result["effective_pid"] = scan_diag.effective_pid;
    result["driver_attached_pid"] = driver_bridge::attached_pid();
    result["scan"] = ns_key_scan_diag_json(scan_diag);
    result["deadline_expired"] = scan_diag.deadline_expired;
    result["cancelled"] = scan_diag.cancelled;
    result["truncated"] = scan_diag.truncated;
    result["bounded"] = true;
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["label"] = k.label;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["secret"] = ns_bytes_to_hex(k.secret.data(), k.secret.size());
        kj["library"] = k.library;
        kj["pid"] = k.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    if (config.hint_only && (!scan_diag.hint_used || scan_diag.early_exit_reason == "hint_missing"))
        return tool_result_t::error(std::string("QUIC key extraction hint range was not available"), result);
    if (keys.empty() && (scan_diag.deadline_expired || scan_diag.cancelled))
        return tool_result_t::error(scan_diag.deadline_expired ? std::string("QUIC key extraction exceeded scan deadline") : std::string("QUIC key extraction cancelled"), result);
    return tool_result_t::ok(std::string("Extracted ") + std::to_string(keys.size()) + std::string(" QUIC keys"), result);
}

json quic_observer_stats_json(const mitm_proxy::quic_proxy::quic_proxy_stats& stats) {
    json r;
    r["running"] = stats.running;
    r["listener_count"] = stats.listener_count;
    r["datagrams"] = stats.datagrams;
    r["bytes_in"] = stats.bytes_in;
    r["quic_packets"] = stats.quic_packets;
    r["non_quic_packets"] = stats.non_quic_packets;
    r["dropped_unsupported"] = stats.dropped_unsupported;
    r["parse_errors"] = stats.parse_errors;
    r["http3_frames"] = stats.http3_frames;
    r["observation_only"] = stats.observation_only;
    r["mitm_supported"] = stats.mitm_supported;
    r["last_error"] = stats.last_error;
    r["contract"] = stats.contract;
    r["last_packet_type"] = stats.last_packet_type;
    r["last_version"] = stats.last_version;
    r["last_sni"] = stats.last_sni;
    return r;
}

json quic_observation_json(const mitm_proxy::quic_proxy::quic_observation& obs) {
    json r;
    r["timestamp"] = obs.timestamp;
    r["listener_id"] = obs.listener_id;
    r["client_addr"] = obs.client_addr;
    r["client_port"] = obs.client_port;
    r["local_port"] = obs.local_port;
    r["datagram_size"] = obs.datagram_size;
    r["is_quic"] = obs.is_quic;
    r["decrypted"] = obs.decrypted;
    r["tls_client_hello_available"] = obs.tls_client_hello_available;
    r["http3_frames_available"] = obs.http3_frames_available;
    r["unsupported_reason"] = obs.unsupported_reason;
    r["header"] = {
        {"valid", obs.header.valid},
        {"is_long_header", obs.header.is_long_header},
        {"first_byte", obs.header.first_byte},
        {"version", obs.header.version},
        {"version_name", obs.header.version_name},
        {"packet_type", obs.header.packet_type},
        {"dcid", obs.header.dcid_hex()},
        {"scid", obs.header.scid_hex()},
        {"payload_offset", obs.header.payload_offset},
        {"is_version_negotiation", obs.header.is_version_negotiation}
    };
    json versions = json::array();
    for (const auto version : obs.header.supported_versions)
        versions.push_back(version);
    r["header"]["supported_versions"] = std::move(versions);
    r["sni"] = obs.client_hello.sni;
    r["alpn_protocols"] = obs.client_hello.alpn_protocols;
    json frames = json::array();
    for (const auto& frame : obs.http3_frames) {
        frames.push_back({
            {"type", frame.type},
            {"length", frame.length},
            {"payload_offset", frame.payload_offset},
            {"valid", frame.valid}
        });
    }
    r["http3_frames"] = std::move(frames);
    return r;
}

tool_result_t quic_observer_start(const json& params) {
    mitm_proxy::quic_proxy::quic_proxy_config cfg;
    if (params.contains("bind_addr") && !params["bind_addr"].is_string())
        return tool_result_t::error(std::string("bind_addr must be a string"));
    cfg.bind_addr = params.value("bind_addr", std::string("127.0.0.1"));
    std::string bind_lower = cfg.bind_addr;
    std::transform(bind_lower.begin(), bind_lower.end(), bind_lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (bind_lower.empty() || bind_lower == "localhost" || bind_lower == "::1" || bind_lower == "[::1]") {
        cfg.bind_addr = "127.0.0.1";
    } else if (bind_lower == "127.0.0.1") {
        cfg.bind_addr = "127.0.0.1";
    } else {
        return tool_result_t::error(std::string("QUIC observer bind address must be loopback"));
    }
    std::uint16_t bind_port = 8443;
    std::uint16_t origin_port = 443;
    if (!ns_json_u16_param(params, "bind_port", bind_port, 8443) ||
        !ns_json_u16_param(params, "expected_origin_port", origin_port, 443))
        return tool_result_t::error(std::string("Invalid QUIC observer port"));
    cfg.bind_port = bind_port;
    cfg.expected_origin_port = origin_port;
    int max_observations = 512;
    if (params.contains("max_observations")) {
        if (!params["max_observations"].is_number_integer() && !params["max_observations"].is_number_unsigned())
            return tool_result_t::error(std::string("max_observations must be numeric"));
        if (params["max_observations"].is_number_unsigned()) {
            const auto raw = params["max_observations"].get<uint64_t>();
            max_observations = raw > 8192 ? 8192 : static_cast<int>(raw);
        } else {
            const auto raw = params["max_observations"].get<int64_t>();
            if (raw <= 0)
                return tool_result_t::error(std::string("max_observations must be positive"));
            max_observations = raw > 8192 ? 8192 : static_cast<int>(raw);
        }
    }
    if (params.contains("fail_closed_without_tls_keys") && !params["fail_closed_without_tls_keys"].is_boolean())
        return tool_result_t::error(std::string("fail_closed_without_tls_keys must be boolean"));
    if (params.contains("observation_only") && !params["observation_only"].is_boolean())
        return tool_result_t::error(std::string("observation_only must be boolean"));
    cfg.max_observations = static_cast<size_t>(max_observations);
    cfg.fail_closed_without_tls_keys = params.value("fail_closed_without_tls_keys", true);
    cfg.observation_only = params.value("observation_only", true);
    uint64_t listener_id = 0;
    const bool ok = mitm_proxy::quic_proxy::start(cfg, &listener_id);
    json r = quic_observer_stats_json(mitm_proxy::quic_proxy::get_stats());
    r["listener_id"] = listener_id;
    r["requested_observation_only"] = cfg.observation_only;
    if (!ok)
        return tool_result_t::error(std::string("QUIC observer start failed"), r);
    return tool_result_t::ok(std::string("QUIC observer started"), r);
}

tool_result_t quic_observer_stop(const json& params) {
    if (params.contains("listener_id")) {
        if (!params["listener_id"].is_number_unsigned() && !params["listener_id"].is_number_integer())
            return tool_result_t::error(std::string("listener_id must be numeric"));
        uint64_t id = 0;
        if (params["listener_id"].is_number_unsigned()) {
            id = params["listener_id"].get<uint64_t>();
        } else {
            const int64_t signed_id = params["listener_id"].get<int64_t>();
            if (signed_id <= 0)
                return tool_result_t::error(std::string("listener_id must be non-zero"));
            id = static_cast<uint64_t>(signed_id);
        }
        if (id == 0)
            return tool_result_t::error(std::string("listener_id must be non-zero"));
        if (!mitm_proxy::quic_proxy::stop(id))
            return tool_result_t::error(std::string("QUIC observer listener not found"), quic_observer_stats_json(mitm_proxy::quic_proxy::get_stats()));
    } else {
        mitm_proxy::quic_proxy::stop_all();
    }
    return tool_result_t::ok(std::string("QUIC observer stopped"), quic_observer_stats_json(mitm_proxy::quic_proxy::get_stats()));
}

tool_result_t quic_observer_stats(const json&) {
    return tool_result_t::ok(std::string("QUIC observer stats"), quic_observer_stats_json(mitm_proxy::quic_proxy::get_stats()));
}

tool_result_t quic_observer_observations(const json& params) {
    size_t limit = 0;
    if (params.contains("limit")) {
        if (!params["limit"].is_number_integer() && !params["limit"].is_number_unsigned())
            return tool_result_t::error(std::string("limit must be numeric"));
        if (params["limit"].is_number_unsigned()) {
            limit = static_cast<size_t>(std::min<uint64_t>(params["limit"].get<uint64_t>(), 8192));
        } else {
            const int64_t v = params["limit"].get<int64_t>();
            if (v < 0)
                return tool_result_t::error(std::string("limit must be non-negative"));
            limit = static_cast<size_t>(std::min<int64_t>(v, 8192));
        }
    }
    auto observations = mitm_proxy::quic_proxy::get_observations(limit);
    json arr = json::array();
    for (const auto& obs : observations)
        arr.push_back(quic_observation_json(obs));
    json r = quic_observer_stats_json(mitm_proxy::quic_proxy::get_stats());
    r["observations"] = std::move(arr);
    r["count"] = observations.size();
    return tool_result_t::ok(std::string("QUIC observer observations"), r);
}

tool_result_t dtls_detect_sessions(const json& params) {
    std::uint32_t pid = params.value("pid", 0u);
    diag::log_tagged_fmt("net_sec", "dtls_detect_sessions entry pid=%u", pid);
    if (ns_has_payload_hex_param(params)) {
        const std::string hex = ns_payload_hex_param(params);
        std::vector<std::uint8_t> payload;
        if (!ns_hex_to_bytes_strict(hex, payload)) {
            json r;
            r["backend"] = "provided_payload";
            r["deterministic_input"] = true;
            r["parser_rejection_reason"] = hex.empty() ? "empty_payload_hex" : "invalid_payload_hex";
            return tool_result_t::error(std::string("Invalid DTLS payload_hex"), r);
        }
        net_security::DtlsAnalyzer::dtls_record_t rec;
        std::size_t offset = 0;
        std::string rejection;
        const bool parsed = ns_parse_dtls_payload_with_offset(payload, rec, offset, rejection);
        json result;
        result["backend"] = "provided_payload";
        result["capture_performed"] = false;
        result["deterministic_input"] = true;
        result["pid"] = pid;
        result["payload_bytes"] = payload.size();
        result["payload_hex_preview"] = ns_bytes_to_hex(payload.data(), std::min<std::size_t>(payload.size(), 96));
        result["payload_sha256"] = ns_sha256_hex(payload.data(), payload.size());
        result["parser_offset"] = offset;
        result["parser_rejection_reason"] = rejection;
        result["header_classification"] = parsed ? (rec.is_handshake ? "dtls_handshake_record" : "dtls_record") : "unclassified";
        result["dtls_version"] = parsed ? rec.version : 0u;
        result["content_type"] = parsed ? rec.content_type : 0u;
        result["epoch"] = parsed ? rec.epoch : 0u;
        result["sequence"] = parsed ? rec.sequence : 0u;
        result["parser_only"] = true;
        result["state_contract_only"] = true;
        result["functional_evidence"] = false;
        result["capture_evidence"] = false;
        result["key_evidence"] = false;
        result["live_capture_required_for_functional"] = true;
        result["udp_live_stimulus_status"] = ns_udp_live_stimulus_status_json("dtls");
        result["live_stimulus_owned_by"] = "testlab_harness";
        result["implementation_udp_stimulus_executor_available"] = false;
        result["live_capture_correlated"] = false;
        result["target_pid_correlated"] = false;
        result["tuple_correlated"] = false;
        result["payload_hash_correlated"] = false;
        result["nonce_correlated"] = false;
        result["capture_counter_delta"] = 0;
        result["functional_count"] = 0;
        result["parser_count"] = parsed ? 1 : 0;
        result["count"] = 0;
        json arr = json::array();
        if (parsed) {
            json sj;
            const std::uint32_t local_port = params.value("local_port", 40000u);
            const std::uint32_t remote_port = params.value("remote_port", 4443u);
            sj["pid"] = pid;
            sj["src_port"] = local_port;
            sj["dst_port"] = remote_port;
            sj["dtls_version"] = rec.version;
            sj["epoch"] = rec.epoch;
            sj["state"] = rec.is_handshake ? "handshake" : (rec.content_type == 23 ? "established" : (rec.content_type == 21 ? "closing" : "unknown"));
            sj["content_type"] = rec.content_type;
            sj["parser_offset"] = offset;
            sj["payload_sha256"] = result["payload_sha256"];
            arr.push_back(std::move(sj));
        }
        result["sessions"] = json::array();
        result["parser_sessions"] = std::move(arr);
        result["zero_detection_reason"] = parsed ? "provided_payload_parser_only_no_driver_capture" : "provided_payload_parser_rejected";
        diag::log_tagged_fmt("net_sec", "dtls_detect_sessions provided_payload parsed=%d pid=%u bytes=%zu offset=%zu version=0x%04X content_type=%u epoch=%u rejection=%s",
            parsed ? 1 : 0,
            pid,
            payload.size(),
            offset,
            parsed ? rec.version : 0u,
            parsed ? rec.content_type : 0u,
            parsed ? rec.epoch : 0u,
            rejection.empty() ? "<none>" : rejection.c_str());
        if (!parsed)
            return tool_result_t::error(std::string("DTLS payload did not parse as a session"), result);
        return tool_result_t::ok(std::string("Parsed 1 DTLS payload as parser-only evidence"), result);
    }
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "dtls_detect_sessions driver not connected");
        json r;
        r["backend"] = "driver_capture";
        r["capture_performed"] = false;
        r["driver_connected"] = false;
        r["functional_evidence"] = false;
        r["live_capture_required_for_functional"] = true;
        r["udp_live_stimulus_status"] = ns_udp_live_stimulus_status_json("dtls");
        r["live_stimulus_owned_by"] = "testlab_harness";
        r["implementation_udp_stimulus_executor_available"] = false;
        return tool_result_t::error(std::string("Driver not connected"), r);
    }

    bool cap_active_before = false;
    std::uint32_t cap_cnt_before = 0;
    std::uint32_t cap_drp_before = 0;
    device->get_capture_status(cap_active_before, cap_cnt_before, cap_drp_before);
    auto sessions = net_security::DtlsAnalyzer::instance().detect_dtls_sessions(pid);
    bool cap_active_after = false;
    std::uint32_t cap_cnt_after = 0;
    std::uint32_t cap_drp_after = 0;
    device->get_capture_status(cap_active_after, cap_cnt_after, cap_drp_after);
    std::uint32_t detection_attempts = 1;
    const DWORD wait_start = GetTickCount();
    DWORD capture_wait_elapsed_ms = 0;
    while ((sessions.empty() || cap_cnt_after <= cap_cnt_before) && capture_wait_elapsed_ms < 750) {
        Sleep(25);
        ++detection_attempts;
        sessions = net_security::DtlsAnalyzer::instance().detect_dtls_sessions(pid);
        device->get_capture_status(cap_active_after, cap_cnt_after, cap_drp_after);
        capture_wait_elapsed_ms = GetTickCount() - wait_start;
    }
    diag::log_tagged_fmt("net_sec", "dtls_detect_sessions count=%zu pid=%u capture_before_active=%d capture_before_count=%u capture_before_dropped=%u capture_after_active=%d capture_after_count=%u capture_after_dropped=%u attempts=%u wait_ms=%lu",
        sessions.size(),
        pid,
        cap_active_before ? 1 : 0,
        cap_cnt_before,
        cap_drp_before,
        cap_active_after ? 1 : 0,
        cap_cnt_after,
        cap_drp_after,
        detection_attempts,
        static_cast<unsigned long>(capture_wait_elapsed_ms));

    json result;
    result["backend"] = "driver_capture";
    result["capture_performed"] = true;
    result["deterministic_input"] = false;
    result["capture_active_before"] = cap_active_before;
    result["capture_count_before"] = cap_cnt_before;
    result["capture_dropped_before"] = cap_drp_before;
    result["capture_active_after"] = cap_active_after;
    result["capture_count_after"] = cap_cnt_after;
    result["capture_dropped_after"] = cap_drp_after;
    result["detection_attempts"] = detection_attempts;
    result["capture_wait_elapsed_ms"] = capture_wait_elapsed_ms;
    const std::uint32_t capture_delta = cap_cnt_after > cap_cnt_before ? (cap_cnt_after - cap_cnt_before) : 0;
    bool all_pid_correlated = !sessions.empty();
    bool all_tuple_correlated = !sessions.empty();
    bool all_hash_correlated = !sessions.empty();
    bool all_nonce_correlated = !sessions.empty();
    for (const auto& s : sessions) {
        if (pid != 0 && s.pid != pid)
            all_pid_correlated = false;
        if (s.src_port == 0 || s.dst_port == 0)
            all_tuple_correlated = false;
        if (s.payload_sha256.empty())
            all_hash_correlated = false;
        if (s.content_type == 0)
            all_nonce_correlated = false;
    }
    const bool functional = !sessions.empty() && capture_delta > 0 && all_pid_correlated && all_tuple_correlated && all_hash_correlated && all_nonce_correlated;
    result["capture_counter_delta"] = capture_delta;
    result["parser_only"] = false;
    result["state_contract_only"] = !functional;
    result["functional_evidence"] = functional;
    result["capture_evidence"] = functional;
    result["key_evidence"] = false;
    result["live_capture_required_for_functional"] = true;
    result["udp_live_stimulus_status"] = ns_udp_live_stimulus_status_json("dtls");
    result["live_stimulus_owned_by"] = "testlab_harness";
    result["implementation_udp_stimulus_executor_available"] = false;
    result["live_capture_correlated"] = functional;
    result["target_pid_correlated"] = all_pid_correlated;
    result["tuple_correlated"] = all_tuple_correlated;
    result["payload_hash_correlated"] = all_hash_correlated;
    result["nonce_correlated"] = all_nonce_correlated;
    result["detected_count"] = sessions.size();
    result["functional_count"] = functional ? sessions.size() : 0;
    result["parser_count"] = 0;
    result["count"] = functional ? sessions.size() : 0;
    if (sessions.empty())
        result["zero_detection_reason"] = cap_cnt_after == 0 ? "capture_queue_empty_or_not_drained_before_detector" : "no_dtls_record_classified_from_captured_udp_payloads";
    else if (!functional)
        result["zero_detection_reason"] = capture_delta == 0 ? "captured_dtls_packets_lacked_counter_delta_correlation" : "captured_dtls_packets_lacked_pid_tuple_hash_or_nonce_correlation";
    json arr = json::array();
    for (const auto& s : sessions) {
        json sj;
        sj["pid"] = s.pid;
        sj["src_port"] = s.src_port;
        sj["dst_port"] = s.dst_port;
        sj["dtls_version"] = s.dtls_version;
        sj["epoch"] = s.epoch;
        sj["state"] = s.state;
        sj["content_type"] = s.content_type;
        sj["parser_offset"] = s.parser_offset;
        sj["payload_sha256"] = s.payload_sha256;
        arr.push_back(sj);
    }
    result["captured_sessions"] = arr;
    result["sessions"] = functional ? arr : json::array();
    const std::string message = functional
        ? std::string("Detected ") + std::to_string(sessions.size()) + std::string(" correlated DTLS sessions")
        : std::string("Parsed DTLS capture candidates without functional correlation");
    return tool_result_t::ok(message, result);
}

tool_result_t dtls_extract_keys(const json& params) {
    auto config = ns_key_scan_config_from_params(params, 9000, 64);
    diag::log_tagged_fmt("net_sec", "dtls_extract_keys entry pid=%u timeout_ms=%u max_results=%u max_regions=%u max_reads=%u max_bytes=%llu hint=0x%llX hint_size=%u hint_only=%d",
        config.pid,
        config.timeout_ms,
        config.max_results,
        config.max_regions,
        config.max_read_attempts,
        static_cast<unsigned long long>(config.max_read_bytes),
        static_cast<unsigned long long>(config.hint_address),
        config.hint_size,
        config.hint_only ? 1 : 0);
    if (!device || !device->is_connected()) {
        diag::log_tagged("net_sec", "dtls_extract_keys driver not connected");
        return tool_result_t::error(std::string("Driver not connected"));
    }
    if (driver_bridge::attached_pid() == 0) {
        json r;
        r["driver_connected"] = true;
        r["driver_attached_pid"] = 0;
        r["driver_status"] = driver_bridge::status();
        r["driver_last_error"] = driver_bridge::last_error();
        diag::log_tagged("net_sec", "dtls_extract_keys no process attached");
        return tool_result_t::error(std::string("No process attached to driver. DTB resolution may have failed."), r);
    }

    auto keys = net_security::TlsKeyExtractor::instance().extract_dtls_keys(config);
    auto scan_diag = net_security::TlsKeyExtractor::instance().last_dtls_scan_diagnostics();
    diag::log_tagged_fmt("net_sec", "dtls_extract_keys keys_found=%zu requested_pid=%u effective_pid=%u elapsed_ms=%llu reason=%s deadline=%d cancelled=%d truncated=%d",
        keys.size(),
        config.pid,
        scan_diag.effective_pid,
        static_cast<unsigned long long>(scan_diag.elapsed_ms),
        scan_diag.early_exit_reason.c_str(),
        scan_diag.deadline_expired ? 1 : 0,
        scan_diag.cancelled ? 1 : 0,
        scan_diag.truncated ? 1 : 0);

    json result;
    result["keys_found"] = keys.size();
    result["requested_pid"] = config.pid;
    result["effective_pid"] = scan_diag.effective_pid;
    result["driver_attached_pid"] = driver_bridge::attached_pid();
    result["scan"] = ns_key_scan_diag_json(scan_diag);
    result["deadline_expired"] = scan_diag.deadline_expired;
    result["cancelled"] = scan_diag.cancelled;
    result["truncated"] = scan_diag.truncated;
    result["bounded"] = true;
    json arr = json::array();
    for (const auto& k : keys) {
        json kj;
        kj["dtls_version"] = k.dtls_version;
        kj["client_random"] = ns_bytes_to_hex(k.client_random.data(), k.client_random.size());
        kj["master_secret"] = ns_bytes_to_hex(k.master_secret.data(), k.master_secret.size());
        kj["library"] = k.library;
        kj["pid"] = k.pid;
        arr.push_back(kj);
    }
    result["keys"] = arr;
    if (config.hint_only && (!scan_diag.hint_used || scan_diag.early_exit_reason == "hint_missing"))
        return tool_result_t::error(std::string("DTLS key extraction hint range was not available"), result);
    if (keys.empty() && (scan_diag.deadline_expired || scan_diag.cancelled))
        return tool_result_t::error(scan_diag.deadline_expired ? std::string("DTLS key extraction exceeded scan deadline") : std::string("DTLS key extraction cancelled"), result);
    return tool_result_t::ok(std::string("Extracted ") + std::to_string(keys.size()) + std::string(" DTLS keys"), result);
}

tool_result_t network_decrypt_capture(const json& params) {
    if ((params.contains("pcap_path") && !params["pcap_path"].is_string()) ||
        (params.contains("keylog_path") && !params["keylog_path"].is_string()) ||
        (params.contains("display_filter") && !params["display_filter"].is_string())) {
        json r;
        r["success"] = false;
        r["input_valid"] = false;
        r["error"] = "pcap_path, keylog_path, and display_filter must be strings";
        return tool_result_t::error(std::string("pcap_path, keylog_path, and display_filter must be strings"), r);
    }
    std::string pcap_path = params.value("pcap_path", "");
    std::string keylog_path = params.value("keylog_path", "");
    std::string display_filter = params.value("display_filter", "http2");
    const std::uint32_t timeout_ms = ns_json_u32_bounded_param(params, "timeout_ms", 9500, 1000, 60000);
    diag::log_tagged_fmt("net_sec", "network_decrypt_capture entry pcap_path=%s keylog_path=%s display_filter=%s timeout_ms=%u",
        pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str(), timeout_ms);

    if (pcap_path.empty()) {
        diag::log_tagged("net_sec", "network_decrypt_capture pcap_path empty -> error");
        return tool_result_t::error(std::string("pcap_path is required"));
    }
    if (pcap_path.find('\0') != std::string::npos || keylog_path.find('\0') != std::string::npos || display_filter.find('\0') != std::string::npos) {
        json r;
        r["success"] = false;
        r["input_valid"] = false;
        r["error"] = "network_decrypt_capture inputs must not contain embedded NUL characters";
        return tool_result_t::error(std::string("network_decrypt_capture inputs must not contain embedded NUL characters"), r);
    }
    std::string display_filter_reason;
    if (!net_security::validate_tshark_display_filter(display_filter, &display_filter_reason)) {
        json r;
        r["success"] = false;
        r["input_valid"] = false;
        r["display_filter"] = display_filter;
        r["display_filter_valid"] = false;
        r["display_filter_rejection_reason"] = display_filter_reason;
        r["requires_http2_frames"] = true;
        diag::log_tagged_fmt("net_sec", "network_decrypt_capture display_filter_invalid filter=%s reason=%s",
            display_filter.c_str(), display_filter_reason.c_str());
        return tool_result_t::error(std::string("Invalid tshark display_filter"), r);
    }


    if (keylog_path.empty()) {
        char buf[MAX_PATH] = {};
        DWORD len = GetEnvironmentVariableA("SSLKEYLOGFILE", buf, MAX_PATH);
        if (len > 0 && len < MAX_PATH) keylog_path = std::string(buf, len);
        diag::log_tagged_fmt("net_sec", "network_decrypt_capture SSLKEYLOGFILE env keylog_path=%s", keylog_path.c_str());
    }
    if (keylog_path.empty()) {
        diag::log_tagged("net_sec", "network_decrypt_capture keylog_path empty -> error");
        return tool_result_t::error(std::string("keylog_path is required (or set SSLKEYLOGFILE environment variable)"));
    }

    auto searched_paths = ns_tshark_search_paths();
    const ns_pcap_probe_t pcap_probe = ns_probe_pcap_file(pcap_path);
    const ns_keylog_probe_t keylog_probe = ns_probe_keylog_file(keylog_path);
    std::string tshark_path = net_security::TlsKeyExtractor::instance().find_tshark_path();
    if (tshark_path.empty()) {
        json r;
        const bool empty_fixture_ok = pcap_probe.valid && pcap_probe.packet_count == 0 && keylog_probe.valid;
        r["success"] = false;
        r["backend"] = empty_fixture_ok ? "builtin_empty_pcap_fixture" : "tshark";
        r["state_contract"] = empty_fixture_ok ? "valid_empty_pcap_builtin_parse_no_external_decryptor_required" : "non_empty_tls_capture_requires_tshark";
        r["state_contract_only"] = empty_fixture_ok;
        r["functional_evidence"] = false;
        r["dependency"] = empty_fixture_ok ? "builtin_empty_pcap_parser" : "tshark";
        r["external_dependency_required"] = !empty_fixture_ok;
        r["host_execution_attempted"] = false;
        r["safe_parser_backend"] = "builtin_empty_pcap_fixture";
        r["dependency_available"] = empty_fixture_ok;
        r["dependency_unavailable"] = !empty_fixture_ok;
        r["dependency_blocked"] = !empty_fixture_ok;
        r["tshark_available"] = false;
        r["tshark_dependency_available"] = false;
        r["selected"] = nullptr;
        r["searched_paths"] = ns_paths_to_json(searched_paths);
        r["pcap_file"] = pcap_path;
        r["keylog_file"] = keylog_path;
        r["display_filter"] = display_filter;
        r["display_filter_valid"] = true;
        r["pcap"] = ns_pcap_probe_to_json(pcap_probe);
        r["keylog"] = ns_keylog_probe_to_json(keylog_probe);
        r["pcap_valid"] = pcap_probe.valid;
        r["pcap_packet_count"] = pcap_probe.packet_count;
        r["keylog_entry_count"] = keylog_probe.entry_count;
        r["total_packets"] = pcap_probe.packet_count;
        r["decrypted_packets"] = 0;
        r["http2_frames"] = json::array();
        r["http2_frame_count"] = 0;
        r["requires_http2_frames"] = true;
        if (empty_fixture_ok) {
            r["expected_empty"] = true;
            r["reason"] = "valid empty capture fixture parsed without tshark";
            diag::log_tagged_fmt("net_sec", "network_decrypt_capture empty_fixture backend=builtin pcap=%s keylog=%s filter=%s packets=%u keylog_entries=%u searched_paths=%zu",
                pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str(),
                pcap_probe.packet_count, keylog_probe.entry_count, searched_paths.size());
            return tool_result_t::ok(std::string("Validated empty TLS capture fixture without tshark"), r);
        }
        r["reason"] = pcap_probe.valid && pcap_probe.packet_count != 0
            ? "non-empty capture requires tshark for decryption"
            : (!pcap_probe.valid ? pcap_probe.reason : (!keylog_probe.valid ? keylog_probe.reason : "tshark backend unavailable"));
        r["dependency_unavailable_reason"] = r["reason"];
        r["error"] = "tshark not found. Install Wireshark to enable PCAP decryption.";
        diag::log_tagged_fmt("net_sec", "network_decrypt_capture dependency_unavailable backend=tshark pcap=%s keylog=%s filter=%s pcap_valid=%d packets=%u keylog_valid=%d keylog_entries=%u reason=%s searched_paths=%zu",
            pcap_path.c_str(), keylog_path.c_str(), display_filter.c_str(),
            pcap_probe.valid ? 1 : 0, pcap_probe.packet_count,
            keylog_probe.valid ? 1 : 0, keylog_probe.entry_count,
            r["reason"].get<std::string>().c_str(), searched_paths.size());
        return tool_result_t::error(std::string("tshark not found. Install Wireshark to enable PCAP decryption."), r);
    }
    ns_add_unique_path(searched_paths, tshark_path);

    diag::log_tagged_fmt("net_sec", "network_decrypt_capture calling tshark pcap=%s keylog=%s filter=%s tshark=%s timeout_ms=%u pcap_packets=%u keylog_entries=%u",
        pcap_path.c_str(),
        keylog_path.c_str(),
        display_filter.c_str(),
        tshark_path.c_str(),
        timeout_ms,
        pcap_probe.packet_count,
        keylog_probe.entry_count);
    net_security::pcap_decrypt_result_t decrypt_result;
    const ULONGLONG decrypt_call_start = GetTickCount64();
    const std::string tshark_command_shape = "\"" + tshark_path + "\" -n -r <pcap> -o tls.keylog_file:<keylog> -Y \"" + display_filter + "\" -T json -l";
    try {
        decrypt_result = net_security::TlsKeyExtractor::instance().decrypt_pcap_with_tshark(
            pcap_path, keylog_path, display_filter, timeout_ms);
    } catch (const std::bad_alloc& ex) {
        decrypt_result.pcap_file_used = pcap_path;
        decrypt_result.keylog_file_used = keylog_path;
        decrypt_result.tshark_path = tshark_path;
        decrypt_result.command_shape = tshark_command_shape;
        decrypt_result.timeout_ms = timeout_ms;
        decrypt_result.elapsed_ms = GetTickCount64() - decrypt_call_start;
        decrypt_result.local_resource_failure = true;
        decrypt_result.local_exception_stage = "network_decrypt_capture_handler";
        decrypt_result.local_exception_message = ex.what();
        decrypt_result.local_exception_code = ERROR_NOT_ENOUGH_MEMORY;
        decrypt_result.win32_error = ERROR_NOT_ENOUGH_MEMORY;
        decrypt_result.error_message = std::string("Local resource failure during network_decrypt_capture handler: ") + ex.what();
    } catch (const std::system_error& ex) {
        decrypt_result.pcap_file_used = pcap_path;
        decrypt_result.keylog_file_used = keylog_path;
        decrypt_result.tshark_path = tshark_path;
        decrypt_result.command_shape = tshark_command_shape;
        decrypt_result.timeout_ms = timeout_ms;
        decrypt_result.elapsed_ms = GetTickCount64() - decrypt_call_start;
        decrypt_result.local_resource_failure = true;
        decrypt_result.local_exception_stage = "network_decrypt_capture_handler";
        decrypt_result.local_exception_message = ex.what();
        decrypt_result.local_exception_code = static_cast<std::uint32_t>(ex.code().value());
        decrypt_result.win32_error = decrypt_result.local_exception_code;
        decrypt_result.error_message = std::string("Local resource failure during network_decrypt_capture handler: ") + ex.what();
    } catch (const std::exception& ex) {
        decrypt_result.pcap_file_used = pcap_path;
        decrypt_result.keylog_file_used = keylog_path;
        decrypt_result.tshark_path = tshark_path;
        decrypt_result.command_shape = tshark_command_shape;
        decrypt_result.timeout_ms = timeout_ms;
        decrypt_result.elapsed_ms = GetTickCount64() - decrypt_call_start;
        decrypt_result.local_exception_stage = "network_decrypt_capture_handler";
        decrypt_result.local_exception_message = ex.what();
        decrypt_result.error_message = std::string("network_decrypt_capture handler exception: ") + ex.what();
    }
    diag::log_tagged_fmt("net_sec", "network_decrypt_capture result success=%d dependency_slow=%d killed=%d total_packets=%u decrypted=%u http2_frames=%zu elapsed_ms=%llu exit_code=%u stdout_bytes=%llu stderr_bytes=%llu local_resource=%d prelaunch_resource=%d attempts=%u create_process=%d pipes=%d/%d readers=%d/%d stage=%s",
        (int)decrypt_result.success,
        decrypt_result.dependency_slow ? 1 : 0,
        decrypt_result.killed_on_deadline ? 1 : 0,
        decrypt_result.total_packets,
        decrypt_result.decrypted_packets,
        decrypt_result.http2_frames.size(),
        static_cast<unsigned long long>(decrypt_result.elapsed_ms),
        decrypt_result.exit_code,
        static_cast<unsigned long long>(decrypt_result.stdout_bytes),
        static_cast<unsigned long long>(decrypt_result.stderr_bytes),
        decrypt_result.local_resource_failure ? 1 : 0,
        decrypt_result.prelaunch_resource_failure ? 1 : 0,
        decrypt_result.launch_attempts,
        decrypt_result.create_process_ok ? 1 : 0,
        decrypt_result.pipe_stdout_created ? 1 : 0,
        decrypt_result.pipe_stderr_created ? 1 : 0,
        decrypt_result.stdout_reader_started ? 1 : 0,
        decrypt_result.stderr_reader_started ? 1 : 0,
        decrypt_result.local_exception_stage.c_str());

    json r;
    r["success"] = decrypt_result.success;
    r["backend"] = "tshark";
    r["state_contract"] = "tls_capture_decryption_attempted_with_tshark";
    r["dependency"] = "tshark";
    r["external_dependency_required"] = true;
    r["dependency_available"] = true;
    r["dependency_unavailable"] = false;
    r["dependency_blocked"] = false;
    r["dependency_slow"] = decrypt_result.dependency_slow;
    r["killed_on_deadline"] = decrypt_result.killed_on_deadline;
    r["tshark_available"] = true;
    r["tshark_dependency_available"] = true;
    r["host_execution_attempted"] = true;
    r["selected"] = tshark_path;
    r["searched_paths"] = ns_paths_to_json(searched_paths);
    r["tshark_path"] = tshark_path;
    r["tshark_command_shape"] = decrypt_result.command_shape;
    r["pcap_file"] = decrypt_result.pcap_file_used;
    r["keylog_file"] = decrypt_result.keylog_file_used;
    r["display_filter"] = display_filter;
    r["display_filter_valid"] = true;
    r["pcap"] = ns_pcap_probe_to_json(pcap_probe);
    r["keylog"] = ns_keylog_probe_to_json(keylog_probe);
    r["pcap_valid"] = pcap_probe.valid;
    r["pcap_packet_count"] = pcap_probe.packet_count;
    r["keylog_entry_count"] = keylog_probe.entry_count;
    r["total_packets"] = decrypt_result.total_packets;
    r["decrypted_packets"] = decrypt_result.decrypted_packets;
    r["requires_http2_frames"] = true;
    r["timeout_ms"] = decrypt_result.timeout_ms;
    r["elapsed_ms"] = decrypt_result.elapsed_ms;
    r["tshark_process_id"] = decrypt_result.process_id;
    r["tshark_exit_code"] = decrypt_result.exit_code;
    r["tshark_wait_status"] = decrypt_result.wait_status;
    r["tshark_win32_error"] = decrypt_result.win32_error;
    r["tshark_launched"] = decrypt_result.launched;
    r["tshark_launch_attempts"] = decrypt_result.launch_attempts;
    r["tshark_create_process_attempted"] = decrypt_result.create_process_attempted;
    r["tshark_create_process_ok"] = decrypt_result.create_process_ok;
    r["tshark_pipe_stdout_created"] = decrypt_result.pipe_stdout_created;
    r["tshark_pipe_stdout_error"] = decrypt_result.pipe_stdout_error;
    r["tshark_pipe_stderr_created"] = decrypt_result.pipe_stderr_created;
    r["tshark_pipe_stderr_error"] = decrypt_result.pipe_stderr_error;
    r["tshark_stdout_reader_started"] = decrypt_result.stdout_reader_started;
    r["tshark_stdout_reader_error"] = decrypt_result.stdout_reader_error;
    r["tshark_stderr_reader_started"] = decrypt_result.stderr_reader_started;
    r["tshark_stderr_reader_error"] = decrypt_result.stderr_reader_error;
    r["tshark_local_resource_failure"] = decrypt_result.local_resource_failure;
    r["tshark_prelaunch_resource_failure"] = decrypt_result.prelaunch_resource_failure;
    r["tshark_retry_exhausted"] = decrypt_result.retry_exhausted;
    r["tshark_prelaunch_retry_sleep_ms"] = decrypt_result.prelaunch_retry_sleep_ms;
    r["tshark_killed_after_reader_failure"] = decrypt_result.killed_after_reader_failure;
    r["tshark_local_exception_stage"] = decrypt_result.local_exception_stage;
    r["tshark_local_exception_message"] = decrypt_result.local_exception_message;
    r["tshark_local_exception_code"] = decrypt_result.local_exception_code;
    r["tshark_launch_elapsed_ms"] = decrypt_result.launch_elapsed_ms;
    r["tshark_first_stdout_elapsed_ms"] = decrypt_result.first_stdout_elapsed_ms;
    r["tshark_first_stderr_elapsed_ms"] = decrypt_result.first_stderr_elapsed_ms;
    r["tshark_stdout_bytes"] = decrypt_result.stdout_bytes;
    r["tshark_stderr_bytes"] = decrypt_result.stderr_bytes;
    r["tshark_stderr_tail"] = decrypt_result.stderr_tail;
    r["tshark_json_parse_elapsed_ms"] = decrypt_result.json_parse_elapsed_ms;
    r["reason"] = decrypt_result.success
        ? "tshark decrypted capture"
        : (decrypt_result.dependency_slow ? "tshark dependency exceeded decrypt deadline" : (decrypt_result.error_message.empty() ? "tshark completed without matching decrypted packets" : decrypt_result.error_message));

    if (!decrypt_result.error_message.empty())
        r["error"] = decrypt_result.error_message;

    json frames = json::array();
    for (const auto& f : decrypt_result.http2_frames) {
        json fj;
        if (!f.stream_id.empty()) fj["stream_id"] = f.stream_id;
        if (!f.method.empty()) fj["method"] = f.method;
        if (!f.url.empty()) fj["url"] = f.url;
        if (!f.authority.empty()) fj["authority"] = f.authority;
        if (!f.content_type.empty()) fj["content_type"] = f.content_type;
        if (f.status_code != 0) fj["status_code"] = f.status_code;
        if (!f.frame_type.empty()) fj["frame_type"] = f.frame_type;
        if (!f.headers.empty()) {
            json hdrs = json::object();
            for (const auto& [k, v] : f.headers) hdrs[k] = v;
            fj["headers"] = hdrs;
        }
        if (!f.body.empty()) fj["body"] = f.body;
        frames.push_back(fj);
    }
    r["http2_frames"] = frames;
    r["http2_frame_count"] = frames.size();
    r["functional_evidence"] = decrypt_result.success;
    r["state_contract_only"] = !decrypt_result.success;

    if (decrypt_result.success)
        return tool_result_t::ok(
            std::string("Decrypted ") + std::to_string(decrypt_result.decrypted_packets) +
            std::string(" packets, found ") + std::to_string(decrypt_result.http2_frames.size()) +
            std::string(" HTTP/2 frames"), r);

    if (decrypt_result.dependency_slow)
        return tool_result_t::error(std::string("tshark dependency exceeded decrypt deadline"), r);

    return tool_result_t::error(decrypt_result.error_message.empty() ?
        std::string("Decryption failed - no matching packets found") : decrypt_result.error_message, r);
}

tool_result_t autoresponder_add_rule(const json& params) {
    std::string mt = params.value("match_type", "prefix_url");
    std::string match_pattern = params.value("match_pattern", "");
    diag::log_tagged_fmt("net_sec", "autoresponder_add_rule entry match_type=%s match_pattern=%s status_code=%u",
        mt.c_str(), match_pattern.c_str(), params.value("status_code", 200u));
    net_security::autoresponder_rule_t rule;
    rule.enabled = params.value("enabled", true);
    rule.priority = params.value("priority", 0);
    if (mt == "exact_url") rule.match_type = net_security::autoresponder_match_type::exact_url;
    else if (mt == "prefix_url") rule.match_type = net_security::autoresponder_match_type::prefix_url;
    else if (mt == "regex_url") rule.match_type = net_security::autoresponder_match_type::regex_url;
    else if (mt == "method_and_url") rule.match_type = net_security::autoresponder_match_type::method_and_url;
    else if (mt == "header_contains") rule.match_type = net_security::autoresponder_match_type::header_contains;
    else if (mt == "body_contains") rule.match_type = net_security::autoresponder_match_type::body_contains;
    else if (mt == "sni_contains") rule.match_type = net_security::autoresponder_match_type::sni_contains;
    else rule.match_type = net_security::autoresponder_match_type::prefix_url;

    rule.match_pattern = params.value("match_pattern", "");
    rule.match_method = params.value("match_method", "");
    rule.status_code = params.value("status_code", 200u);
    rule.status_reason = params.value("status_reason", "");
    rule.response_body = params.value("response_body", "");
    rule.response_file_path = params.value("response_file_path", "");
    rule.latency_ms = params.value("latency_ms", 0u);
    rule.drop_request = params.value("drop_request", false);
    rule.passthrough = params.value("passthrough", false);

    if (params.contains("response_headers") && params["response_headers"].is_object()) {
        for (auto it = params["response_headers"].begin(); it != params["response_headers"].end(); ++it)
            rule.response_headers[it.key()] = it.value().get<std::string>();
    }

    std::uint32_t id = net_security::AutoResponder::instance().add_rule(rule);
    diag::log_tagged_fmt("net_sec", "autoresponder_add_rule rule_id=%u match_type=%s match_pattern=%s", id, mt.c_str(), match_pattern.c_str());
    json r;
    r["rule_id"] = id;
    return tool_result_t::ok(std::string("AutoResponder rule added with ID ") + std::to_string(id), r);
}

tool_result_t autoresponder_remove_rule(const json& params) {
    std::uint32_t rule_id = params.value("rule_id", 0u);
    diag::log_tagged_fmt("net_sec", "autoresponder_remove_rule entry rule_id=%u", rule_id);
    bool removed = net_security::AutoResponder::instance().remove_rule(rule_id);
    diag::log_tagged_fmt("net_sec", "autoresponder_remove_rule removed=%d rule_id=%u", (int)removed, rule_id);
    if (removed) {
        json r;
        r["removed"] = true;
        r["rule_id"] = rule_id;
        return tool_result_t::ok(std::string("Rule removed"), r);
    }
    return tool_result_t::error(std::string("Rule not found"));
}

tool_result_t autoresponder_list_rules(const json&) {
    diag::log_tagged("net_sec", "autoresponder_list_rules entry");
    auto rules = net_security::AutoResponder::instance().list_rules();
    diag::log_tagged_fmt("net_sec", "autoresponder_list_rules count=%zu", rules.size());
    json result;
    result["count"] = rules.size();
    json arr = json::array();
    for (const auto& rule : rules) {
        json rj;
        rj["rule_id"] = rule.rule_id;
        rj["enabled"] = rule.enabled;
        rj["priority"] = rule.priority;
        rj["match_pattern"] = rule.match_pattern;
        rj["match_method"] = rule.match_method;
        rj["status_code"] = rule.status_code;
        rj["match_count"] = rule.match_count;
        rj["drop_request"] = rule.drop_request;
        rj["passthrough"] = rule.passthrough;
        arr.push_back(rj);
    }
    result["rules"] = arr;
    return tool_result_t::ok(std::string("Listed ") + std::to_string(rules.size()) + std::string(" autoresponder rules"), result);
}

tool_result_t autoresponder_match_request(const json& params) {
    const std::string method = params.value("method", "GET");
    const std::string url = params.value("url", "");
    const std::string body = params.value("body", "");
    std::map<std::string, std::string> headers;
    if (params.contains("headers") && params["headers"].is_object()) {
        for (auto it = params["headers"].begin(); it != params["headers"].end(); ++it) {
            if (it.value().is_string())
                headers[it.key()] = it.value().get<std::string>();
        }
    }
    diag::log_tagged_fmt("net_sec", "autoresponder_match_request entry method=%s url=%s headers=%zu body_len=%zu",
        method.c_str(), url.c_str(), headers.size(), body.size());
    if (url.empty())
        return tool_result_t::error(std::string("url is required"));

    auto match = net_security::AutoResponder::instance().match_request(method, url, headers, body);
    auto rules = net_security::AutoResponder::instance().list_rules();
    std::uint64_t match_count = 0;
    for (const auto& rule : rules) {
        if (rule.rule_id == match.rule_id) {
            match_count = rule.match_count;
            break;
        }
    }

    json r;
    r["matched"] = match.matched;
    r["rule_id"] = match.rule_id;
    r["match_count"] = match_count;
    r["response_status_line"] = match.response_status_line;
    r["response_headers"] = match.response_headers_str;
    r["response_body"] = match.response_body;
    diag::log_tagged_fmt("net_sec", "autoresponder_match_request result matched=%d rule_id=%u match_count=%llu status=%s body_len=%zu",
        match.matched ? 1 : 0,
        match.rule_id,
        static_cast<unsigned long long>(match_count),
        match.response_status_line.c_str(),
        match.response_body.size());
    if (match.matched)
        return tool_result_t::ok(std::string("AutoResponder matched request"), r);
    return tool_result_t::error(std::string("No AutoResponder rule matched request"), r);
}

tool_result_t autoresponder_start(const json&) {
    diag::log_tagged("net_sec", "autoresponder_start entry");
    bool started = net_security::AutoResponder::instance().start();
    diag::log_tagged_fmt("net_sec", "autoresponder_start started=%d", (int)started);
    if (started) {
        json r;
        r["status"] = "started";
        return tool_result_t::ok(std::string("AutoResponder started"), r);
    }
    return tool_result_t::error(std::string("AutoResponder already running or failed"));
}

tool_result_t autoresponder_stop(const json&) {
    diag::log_tagged("net_sec", "autoresponder_stop entry");
    bool stopped = net_security::AutoResponder::instance().stop();
    diag::log_tagged_fmt("net_sec", "autoresponder_stop stopped=%d", (int)stopped);
    if (stopped) {
        json r;
        r["status"] = "stopped";
        return tool_result_t::ok(std::string("AutoResponder stopped"), r);
    }
    return tool_result_t::error(std::string("AutoResponder is not running"));
}

tool_result_t autoresponder_import_rules(const json& params) {
    std::string rules_json = params.value("rules_json", "");
    diag::log_tagged_fmt("net_sec", "autoresponder_import_rules entry rules_json_len=%zu", rules_json.size());
    if (rules_json.empty()) {
        diag::log_tagged("net_sec", "autoresponder_import_rules rules_json empty -> error");
        return tool_result_t::error(std::string("rules_json is required"));
    }

    bool imported = net_security::AutoResponder::instance().import_rules(rules_json);
    diag::log_tagged_fmt("net_sec", "autoresponder_import_rules imported=%d", (int)imported);
    if (imported) {
        auto count = net_security::AutoResponder::instance().list_rules().size();
        diag::log_tagged_fmt("net_sec", "autoresponder_import_rules total_rules=%zu", count);
        json r;
        r["imported"] = true;
        r["total_rules"] = count;
        return tool_result_t::ok(std::string("Rules imported, total: ") + std::to_string(count), r);
    }
    return tool_result_t::error(std::string("Failed to import rules - invalid JSON"));
}

tool_result_t autoresponder_export_rules(const json& params) {
    diag::log_tagged("net_sec", "autoresponder_export_rules entry");
    std::string exported = net_security::AutoResponder::instance().export_rules();
    const auto count = net_security::AutoResponder::instance().list_rules().size();
    const std::string path = params.value("path", std::string());
    bool wrote_file = false;
    uint64_t file_size = 0;
    std::error_code fs_ec;
    if (!path.empty()) {
        std::filesystem::path out_path(path);
        if (!out_path.parent_path().empty())
            std::filesystem::create_directories(out_path.parent_path(), fs_ec);
        if (!fs_ec) {
            std::ofstream ofs(out_path, std::ios::binary | std::ios::trunc);
            if (ofs) {
                ofs.write(exported.data(), static_cast<std::streamsize>(exported.size()));
                ofs.flush();
                wrote_file = !ofs.fail();
            }
        }
        if (wrote_file) {
            std::error_code size_ec;
            file_size = static_cast<uint64_t>(std::filesystem::file_size(out_path, size_ec));
            if (size_ec)
                file_size = 0;
        }
    }
    diag::log_tagged_fmt("net_sec", "autoresponder_export_rules exported_len=%zu count=%zu path=%s wrote=%d file_size=%llu ec=%lu",
        exported.size(), count, path.c_str(), wrote_file ? 1 : 0,
        static_cast<unsigned long long>(file_size), static_cast<unsigned long>(fs_ec.value()));
    json r;
    r["rules_json"] = exported;
    r["rule_count"] = count;
    r["path"] = path;
    r["wrote_file"] = wrote_file;
    r["file_size"] = file_size;
    r["fs_error"] = fs_ec.value();
    if (!path.empty() && (!wrote_file || file_size == 0)) {
        diag::log_tagged_fmt("net_sec", "autoresponder_export_rules write_failed path=%s wrote=%d file_size=%llu ec=%lu",
            path.c_str(), wrote_file ? 1 : 0,
            static_cast<unsigned long long>(file_size), static_cast<unsigned long>(fs_ec.value()));
        return tool_result_t::error(std::string("AutoResponder rules export file write failed"), r);
    }
    return tool_result_t::ok(std::string("AutoResponder rules exported"), r);
}

#else

tool_result_t tls_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_start_keylog(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_stop_keylog(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t tls_get_extracted_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_inject(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_remove(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_generate_ca(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t cert_list(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t pin_bypass(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_detect_connections(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_decrypt_initial(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_observer_start(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_observer_stop(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_observer_stats(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t quic_observer_observations(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t dtls_detect_sessions(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t dtls_extract_keys(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_add_rule(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_remove_rule(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_list_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_match_request(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_start(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_stop(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_import_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t autoresponder_export_rules(const json&) { return tool_result_t::error("Not supported on this platform"); }
tool_result_t network_decrypt_capture(const json&) { return tool_result_t::error("Not supported on this platform"); }
static tool_result_t aida_tls_assess(const json&) { return tool_result_t::error("Not supported on this platform"); }
static tool_result_t aida_tls_jarm(const json&) { return tool_result_t::error("Not supported on this platform"); }
static tool_result_t aida_tls_test_heartbleed(const json&) { return tool_result_t::error("Not supported on this platform"); }
static tool_result_t aida_tls_test_crime(const json&) { return tool_result_t::error("Not supported on this platform"); }
#endif

void register_net_security_tools(mcp_standalone::server_t& srv) {
    diag::log_tagged("net_sec", "register_net_security_tools entry");

    register_compat(srv, {
        std::string("tls_manage"), std::string("network_security"),
        std::string("Manage TLS key extraction and keylog capture. Actions: extract_keys, start_keylog, stop_keylog, get_extracted_keys."),
        {{std::string("action"), std::string("string"), std::string("extract_keys|start_keylog|stop_keylog|get_extracted_keys"), true},
         {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false},
         {std::string("pid"), std::string("number"), std::string("Target process ID; 0 resolves to the attached driver target."), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Bounded memory scan deadline in milliseconds."), false},
         {std::string("scan_timeout_ms"), std::string("number"), std::string("Per-worker bounded key scan deadline for start_keylog."), false},
         {std::string("stop_wait_ms"), std::string("number"), std::string("Bounded wait for keylog worker shutdown."), false},
         {std::string("max_results"), std::string("number"), std::string("Maximum keys to return."), false},
         {std::string("max_keys"), std::string("number"), std::string("Alias for max_results."), false},
         {std::string("max_regions"), std::string("number"), std::string("Maximum memory regions to scan; 0 means unrestricted diagnostic scan."), false},
         {std::string("max_read_attempts"), std::string("number"), std::string("Maximum process memory reads; 0 means unrestricted diagnostic scan."), false},
         {std::string("max_read_bytes"), std::string("number"), std::string("Maximum bytes to read from target memory; 0 means unrestricted diagnostic scan."), false},
         {std::string("scan_schannel"), std::string("boolean"), std::string("Enable SChannel key scanner."), false},
         {std::string("scan_openssl"), std::string("boolean"), std::string("Enable OpenSSL key scanner."), false},
         {std::string("scan_nss"), std::string("boolean"), std::string("Enable NSS key scanner."), false},
         {std::string("scan_boringssl"), std::string("boolean"), std::string("Enable BoringSSL key scanner."), false},
         {std::string("scan_generic"), std::string("boolean"), std::string("Enable generic keylog-pattern scanner."), false},
         {std::string("scan_tls13_structures"), std::string("boolean"), std::string("Enable TLS 1.3 structure scanner."), false},
         {std::string("hint_address"), std::string("string"), std::string("Optional target memory address hint for bounded fixture/key scans."), false},
         {std::string("memory_hint_address"), std::string("string"), std::string("Alias for hint_address."), false},
         {std::string("hint_size"), std::string("number"), std::string("Size of the hinted target memory range."), false},
         {std::string("memory_hint_size"), std::string("number"), std::string("Alias for hint_size."), false},
         {std::string("hint_only"), std::string("boolean"), std::string("Restrict extraction to the hinted range instead of broad process scanning."), false},
         {std::string("memory_hint_only"), std::string("boolean"), std::string("Alias for hint_only."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "extract_keys") return tls_extract_keys(p);
            if (action == "start_keylog") return tls_start_keylog(p);
            if (action == "stop_keylog") return tls_stop_keylog(p);
            if (action == "get_extracted_keys") return tls_get_extracted_keys(p);
            return compat_unknown_action("tls_manage", action);
        },
        false});

    srv.register_tool({
        "aida.tls.assess",
        "Assess TLS protocol, cipher, certificate, chain, and HSTS evidence with bounded raw ClientHello probes and WinHTTP certificate collection.",
        {{"host", "string", "TLS server hostname or address.", true},
         {"port", "number", "TLS port, default 443.", false},
         {"timeout_ms", "number", "Per-probe timeout bounded by MCP deadline, capped at 15000.", false},
         {"check_chain", "boolean", "Validate certificate chain and hostname with Windows CryptoAPI cache-only revocation evidence.", false}},
        false,
        aida_tls_assess
    });

    srv.register_tool({
        "aida.tls.jarm",
        "Compute a Salesforce JARM v1-compatible active TLS server fingerprint with ten bounded ClientHello probes and per-probe evidence.",
        {{"host", "string", "TLS server hostname or address.", true},
         {"port", "number", "TLS port, default 443.", false},
         {"timeout_ms", "number", "Per-probe timeout bounded by MCP deadline, capped at 15000.", false}},
        false,
        aida_tls_jarm
    });

    srv.register_tool({
        "aida.tls.test_heartbleed",
        "Run a bounded TLS heartbeat over-read probe and report negotiated heartbeat, alert, timeout, and over-read evidence without returning leaked payload bytes.",
        {{"host", "string", "TLS server hostname or address.", true},
         {"port", "number", "TLS port, default 443.", false},
         {"timeout_ms", "number", "Probe timeout bounded by MCP deadline, capped at 15000.", false},
         {"force_probe", "boolean", "Send the malformed heartbeat even if the heartbeat extension is not observed.", false}},
        false,
        aida_tls_test_heartbleed
    });

    srv.register_tool({
        "aida.tls.test_crime",
        "Probe TLS-level compression negotiation as CRIME evidence by offering null and DEFLATE compression in a bounded ClientHello.",
        {{"host", "string", "TLS server hostname or address.", true},
         {"port", "number", "TLS port, default 443.", false},
         {"timeout_ms", "number", "Probe timeout bounded by MCP deadline, capped at 15000.", false}},
        false,
        aida_tls_test_crime
    });

    register_compat(srv, {
        std::string("cert_manage"), std::string("network_security"),
        std::string("Manage certificate generation and Windows certificate store operations. Actions: inject, remove, generate_ca, list."),
        {{std::string("action"), std::string("string"), std::string("inject|remove|generate_ca|list"), true},
         {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "inject") return cert_inject(p);
            if (action == "remove") return cert_remove(p);
            if (action == "generate_ca") return cert_generate_ca(p);
            if (action == "list") return cert_list(p);
            return compat_unknown_action("cert_manage", action);
        },
        false});

    register_compat(srv, {
        std::string("pin_bypass"), std::string("network_security"),
        std::string("Run read-only certificate interception diagnostics for a target process. Reports proxy, CA trust, "
               "Camoufox, provider, and handoff readiness; normal builds do not modify target process code."),
        {{std::string("pid"), std::string("number"), std::string("Target process ID (0 = current attached)"), false},
         {std::string("method"), std::string("string"), std::string("Diagnostic focus: 'all', 'wintrust', 'crypt32', 'schannel', 'dotnet' (default: all)"), false},
         {std::string("proxy_running"), std::string("boolean"), std::string("Override proxy route readiness"), false},
         {std::string("ca_trusted"), std::string("boolean"), std::string("Override AiDA CA trust readiness"), false},
         {std::string("interception_still_failing"), std::string("boolean"), std::string("Set when proxy and trust are present but interception still fails"), false}},
        pin_bypass, true});

    register_compat(srv, {
        std::string("quic_manage"), std::string("network_security"),
        std::string("Manage QUIC analysis and observation-only UDP listener state. Actions: detect_connections, decrypt_initial, extract_keys, start_observer, stop_observer, observer_stats, observer_observations."),
        {{std::string("action"), std::string("string"), std::string("detect_connections|decrypt_initial|extract_keys|start_observer|stop_observer|observer_stats|observer_observations"), true},
         {std::string("pid"), std::string("number"), std::string("Target process ID for live detection or deterministic payload attribution."), false},
         {std::string("payload_hex"), std::string("string"), std::string("Optional QUIC UDP payload bytes for deterministic detection without live capture."), false},
         {std::string("packet_hex"), std::string("string"), std::string("Optional QUIC packet bytes for decrypt_initial or deterministic detection."), false},
         {std::string("bind_addr"), std::string("string"), std::string("Loopback bind address for start_observer."), false},
         {std::string("bind_port"), std::string("number"), std::string("UDP bind port for start_observer."), false},
         {std::string("expected_origin_port"), std::string("number"), std::string("Expected original QUIC server port for observation."), false},
         {std::string("max_observations"), std::string("number"), std::string("Maximum retained observer observations, capped at 8192."), false},
         {std::string("fail_closed_without_tls_keys"), std::string("boolean"), std::string("Mark encrypted QUIC payloads unsupported when TLS keys are unavailable."), false},
         {std::string("observation_only"), std::string("boolean"), std::string("Must remain true; full QUIC MITM is not claimed by this observer."), false},
         {std::string("listener_id"), std::string("number"), std::string("Listener id for stop_observer."), false},
         {std::string("limit"), std::string("number"), std::string("Maximum observer observations to return."), false},
         {std::string("local_port"), std::string("number"), std::string("Synthetic source port for deterministic payload detection."), false},
         {std::string("remote_port"), std::string("number"), std::string("Synthetic destination port for deterministic payload detection."), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Bounded key extraction scan deadline in milliseconds."), false},
         {std::string("max_results"), std::string("number"), std::string("Maximum keys to return for extract_keys."), false},
         {std::string("max_regions"), std::string("number"), std::string("Maximum memory regions to scan for extract_keys."), false},
         {std::string("max_read_attempts"), std::string("number"), std::string("Maximum process memory reads for extract_keys."), false},
         {std::string("max_read_bytes"), std::string("number"), std::string("Maximum target memory bytes to read for extract_keys."), false},
         {std::string("hint_address"), std::string("string"), std::string("Optional target memory address hint for bounded key scans."), false},
         {std::string("hint_size"), std::string("number"), std::string("Size of the hinted target memory range."), false},
         {std::string("hint_only"), std::string("boolean"), std::string("Restrict extract_keys to the hinted range."), false},
         {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "detect_connections") return quic_detect_connections(p);
            if (action == "decrypt_initial") return quic_decrypt_initial(p);
            if (action == "extract_keys") return quic_extract_keys(p);
            if (action == "start_observer") return quic_observer_start(p);
            if (action == "stop_observer") return quic_observer_stop(p);
            if (action == "observer_stats") return quic_observer_stats(p);
            if (action == "observer_observations") return quic_observer_observations(p);
            return compat_unknown_action("quic_manage", action);
        },
        false});

    register_compat(srv, {
        std::string("dtls_manage"), std::string("network_security"),
        std::string("Manage DTLS analysis. Actions: detect_sessions, extract_keys."),
        {{std::string("action"), std::string("string"), std::string("detect_sessions|extract_keys"), true},
         {std::string("pid"), std::string("number"), std::string("Target process ID for live detection or deterministic payload attribution."), false},
         {std::string("payload_hex"), std::string("string"), std::string("Optional DTLS UDP payload bytes for deterministic detection without live capture."), false},
         {std::string("packet_hex"), std::string("string"), std::string("Optional DTLS packet bytes for deterministic detection."), false},
         {std::string("local_port"), std::string("number"), std::string("Synthetic source port for deterministic payload detection."), false},
         {std::string("remote_port"), std::string("number"), std::string("Synthetic destination port for deterministic payload detection."), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Bounded key extraction scan deadline in milliseconds."), false},
         {std::string("max_results"), std::string("number"), std::string("Maximum keys to return for extract_keys."), false},
         {std::string("max_regions"), std::string("number"), std::string("Maximum memory regions to scan for extract_keys."), false},
         {std::string("max_read_attempts"), std::string("number"), std::string("Maximum process memory reads for extract_keys."), false},
         {std::string("max_read_bytes"), std::string("number"), std::string("Maximum target memory bytes to read for extract_keys."), false},
         {std::string("hint_address"), std::string("string"), std::string("Optional target memory address hint for bounded key scans."), false},
         {std::string("hint_size"), std::string("number"), std::string("Size of the hinted target memory range."), false},
         {std::string("hint_only"), std::string("boolean"), std::string("Restrict extract_keys to the hinted range."), false},
         {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "detect_sessions") return dtls_detect_sessions(p);
            if (action == "extract_keys") return dtls_extract_keys(p);
            return compat_unknown_action("dtls_manage", action);
        },
        false});

    register_compat(srv, {
        std::string("autoresponder_manage"), std::string("network_security"),
        std::string("Manage AutoResponder rules and runtime state. Actions: add_rule, remove_rule, list_rules, match_request, start, stop, import_rules, export_rules."),
        {{std::string("action"), std::string("string"), std::string("add_rule|remove_rule|list_rules|match_request|start|stop|import_rules|export_rules"), true},
         {std::string("payload"), std::string("object"), std::string("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "add_rule") return autoresponder_add_rule(p);
            if (action == "remove_rule") return autoresponder_remove_rule(p);
            if (action == "list_rules") return autoresponder_list_rules(p);
            if (action == "match_request") return autoresponder_match_request(p);
            if (action == "start") return autoresponder_start(p);
            if (action == "stop") return autoresponder_stop(p);
            if (action == "import_rules") return autoresponder_import_rules(p);
            if (action == "export_rules") return autoresponder_export_rules(p);
            return compat_unknown_action("autoresponder_manage", action);
        },
        false});

    register_compat(srv, {
        std::string("network_decrypt_capture"), std::string("network_security"),
        std::string("Decrypt a captured PCAP file using TLS session keys and return the decrypted HTTP/2 frames. "
               "Uses tshark (Wireshark CLI) with an SSLKEYLOGFILE to decrypt TLS traffic. "
               "Automatically reads the SSLKEYLOGFILE path from the environment if keylog_path is not specified. "
               "Returns decrypted HTTP/2 request/response headers, methods, URLs, and bodies. "
               "The target process must have been started with SSLKEYLOGFILE set for key logging to work."),
        {{std::string("pcap_path"), std::string("string"), std::string("Path to the PCAP file to decrypt"), true},
         {std::string("keylog_path"), std::string("string"), std::string("Path to the SSLKEYLOGFILE (auto-detected from env if empty)"), false},
         {std::string("display_filter"), std::string("string"), std::string("Strict HTTP/2 Wireshark display filter (default: 'http2')"), false},
         {std::string("timeout_ms"), std::string("number"), std::string("Bounded TShark decrypt deadline in milliseconds."), false}},
        network_decrypt_capture, true});

    diag::log_tagged("net_sec", "register_net_security_tools complete");
}

}
