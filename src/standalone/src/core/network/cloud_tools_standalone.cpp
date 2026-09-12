
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#include "cloud_tools_standalone.hpp"
#include "standalone_compat.hpp"
#include "pro.h"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace aida {
namespace cloud_tools {
namespace {

struct winhttp_handle_t {
    HINTERNET h = nullptr;
    explicit winhttp_handle_t(HINTERNET v = nullptr) : h(v) {}
    ~winhttp_handle_t() { if (h) WinHttpCloseHandle(h); }
    winhttp_handle_t(const winhttp_handle_t&) = delete;
    winhttp_handle_t& operator=(const winhttp_handle_t&) = delete;
    winhttp_handle_t(winhttp_handle_t&& o) noexcept : h(o.h) { o.h = nullptr; }
    winhttp_handle_t& operator=(winhttp_handle_t&& o) noexcept {
        if (this != &o) {
            if (h) WinHttpCloseHandle(h);
            h = o.h;
            o.h = nullptr;
        }
        return *this;
    }
};

struct http_probe_t {
    bool attempted = false;
    bool ok = false;
    DWORD gle = 0;
    DWORD status = 0;
    std::string error;
    std::map<std::string, std::string> headers;
    std::uint64_t body_length = 0;
    std::uint64_t body_hash = 0;
    bool body_truncated = false;
};

static std::uint64_t fnv1a64(const void* data, std::size_t len) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::uint64_t h = 1469598103934665603ull;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static std::uint64_t fnv1a64(const std::string& s) {
    return fnv1a64(s.data(), s.size());
}

static std::string hex64(std::uint64_t v) {
    std::ostringstream os;
    os << std::hex << std::setw(16) << std::setfill('0') << v;
    return os.str();
}

static std::string lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty() || s.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return {};
    const int length = static_cast<int>(s.size());
    UINT code_page = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int needed = MultiByteToWideChar(code_page, flags, s.data(), length, nullptr, 0);
    if (needed <= 0) {
        code_page = CP_ACP;
        flags = 0;
        needed = MultiByteToWideChar(code_page, flags, s.data(), length, nullptr, 0);
    }
    if (needed <= 0)
        return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(code_page, flags, s.data(), length, out.data(), needed) != needed)
        return {};
    return out;
}

static std::string wide_to_utf8(const std::wstring& s) {
    if (s.empty() || s.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        return {};
    const int length = static_cast<int>(s.size());
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), length,
                                            nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(), length, out.data(), needed,
                            nullptr, nullptr) != needed)
        return {};
    return out;
}

static bool call_expired() {
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    return mcp_standalone::current_call_cancelled() || (deadline != 0 && GetTickCount64() >= deadline);
}

static DWORD timeout_ms(DWORD fallback) {
    const std::uint64_t deadline = mcp_standalone::current_call_deadline_ms();
    if (deadline == 0)
        return fallback;
    const std::uint64_t now = GetTickCount64();
    if (deadline <= now)
        return 1;
    return static_cast<DWORD>(std::max<std::uint64_t>(1, std::min<std::uint64_t>(fallback, deadline - now)));
}

static bool valid_dnsish(const std::string& s, std::size_t min_len, std::size_t max_len, bool allow_dot, bool allow_underscore) {
    if (s.size() < min_len || s.size() > max_len)
        return false;
    if (s.front() == '-' || s.back() == '-' || s.front() == '.' || s.back() == '.')
        return false;
    bool prev_dot = false;
    for (unsigned char c : s) {
        const bool ok = std::islower(c) || std::isdigit(c) || c == '-' || (allow_dot && c == '.') || (allow_underscore && c == '_');
        if (!ok)
            return false;
        if (c == '.') {
            if (prev_dot)
                return false;
            prev_dot = true;
        } else {
            prev_dot = false;
        }
    }
    return true;
}

static bool valid_azure_account(const std::string& s) {
    if (s.size() < 3 || s.size() > 24)
        return false;
    for (unsigned char c : s) {
        if (!(std::islower(c) || std::isdigit(c)))
            return false;
    }
    return true;
}

static std::string url_path_escape(const std::string& s) {
    std::ostringstream os;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/')
            os << static_cast<char>(c);
        else
            os << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c) << std::nouppercase << std::dec;
    }
    return os.str();
}

static bool secret_header_name(const std::string& name) {
    const std::string n = lower_ascii(name);
    return n.find("authorization") != std::string::npos ||
           n.find("cookie") != std::string::npos ||
           n.find("token") != std::string::npos ||
           n.find("credential") != std::string::npos ||
           n.find("signature") != std::string::npos ||
           n.find("secret") != std::string::npos ||
           n.find("key") != std::string::npos;
}

static json header_value_json(const std::string& name, const std::string& value) {
    if (secret_header_name(name) || value.size() > 192) {
        json out;
        out["redacted"] = true;
        out["length"] = static_cast<std::uint64_t>(value.size());
        out["hash64"] = hex64(fnv1a64(value));
        return out;
    }
    return value;
}

static std::map<std::string, std::string> parse_headers(const std::wstring& raw) {
    std::map<std::string, std::string> out;
    const std::string u = wide_to_utf8(raw);
    std::size_t pos = 0;
    while (pos < u.size()) {
        std::size_t end = u.find("\r\n", pos);
        if (end == std::string::npos)
            end = u.size();
        std::string line = u.substr(pos, end - pos);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = lower_ascii(line.substr(0, colon));
            std::string val = line.substr(colon + 1);
            while (!val.empty() && std::isspace(static_cast<unsigned char>(val.front())))
                val.erase(val.begin());
            while (!val.empty() && std::isspace(static_cast<unsigned char>(val.back())))
                val.pop_back();
            out[key] = val;
        }
        pos = end + 2;
    }
    return out;
}

static std::wstring header_lines(const std::map<std::string, std::string>& headers) {
    std::wstring out;
    for (const auto& kv : headers) {
        out += utf8_to_wide(kv.first + ": " + kv.second + "\r\n");
    }
    return out;
}

static http_probe_t http_probe(const std::string& method,
                               const std::string& host,
                               const std::string& path,
                               const std::map<std::string, std::string>& headers = {},
                               const std::string& body = {},
                               DWORD timeout = 5000,
                               std::size_t max_body = 4096) {
    http_probe_t out;
    out.attempted = true;
    if (call_expired()) {
        out.error = "cancelled_or_deadline";
        return out;
    }
    const std::wstring whost = utf8_to_wide(host);
    const std::wstring wpath = utf8_to_wide(path.empty() ? "/" : path);
    const std::wstring wmethod = utf8_to_wide(method);
    winhttp_handle_t session(WinHttpOpen(L"AiDA-CloudProbe/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.h) {
        out.gle = GetLastError();
        out.error = "WinHttpOpen failed";
        return out;
    }
    const DWORD t = timeout_ms(timeout);
    WinHttpSetTimeouts(session.h, t, t, t, t);
    winhttp_handle_t connect(WinHttpConnect(session.h, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!connect.h) {
        out.gle = GetLastError();
        out.error = "WinHttpConnect failed";
        return out;
    }
    winhttp_handle_t req(WinHttpOpenRequest(connect.h, wmethod.c_str(), wpath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!req.h) {
        out.gle = GetLastError();
        out.error = "WinHttpOpenRequest failed";
        return out;
    }
    WinHttpSetTimeouts(req.h, t, t, t, t);
    const std::wstring whdrs = header_lines(headers);
    void* body_ptr = body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data());
    const DWORD body_len = static_cast<DWORD>(body.size());
    if (!WinHttpSendRequest(req.h,
                            whdrs.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : whdrs.c_str(),
                            whdrs.empty() ? 0 : static_cast<DWORD>(-1L),
                            body_ptr,
                            body_len,
                            body_len,
                            0)) {
        out.gle = GetLastError();
        out.error = "WinHttpSendRequest failed";
        return out;
    }
    if (!WinHttpReceiveResponse(req.h, nullptr)) {
        out.gle = GetLastError();
        out.error = "WinHttpReceiveResponse failed";
        return out;
    }
    DWORD status = 0;
    DWORD status_len = sizeof(status);
    if (WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status, &status_len, nullptr))
        out.status = status;
    DWORD header_len = 0;
    WinHttpQueryHeaders(req.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &header_len, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && header_len > 0) {
        std::wstring raw(header_len / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(req.h, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, raw.data(), &header_len, WINHTTP_NO_HEADER_INDEX)) {
            raw.resize(header_len / sizeof(wchar_t));
            out.headers = parse_headers(raw);
        }
    }
    std::uint64_t hash = 1469598103934665603ull;
    while (!call_expired()) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(req.h, &available) || available == 0)
            break;
        std::vector<char> buf(std::min<DWORD>(available, 8192));
        DWORD read = 0;
        if (!WinHttpReadData(req.h, buf.data(), static_cast<DWORD>(buf.size()), &read) || read == 0)
            break;
        out.body_length += read;
        for (DWORD i = 0; i < read; ++i) {
            hash ^= static_cast<unsigned char>(buf[i]);
            hash *= 1099511628211ull;
        }
        if (out.body_length >= max_body) {
            out.body_truncated = true;
            break;
        }
    }
    out.body_hash = hash;
    out.ok = out.status != 0 && out.status < 600;
    return out;
}

static json probe_json(const std::string& label, const std::string& method, const std::string& host, const std::string& path, const http_probe_t& p) {
    json out;
    out["label"] = label;
    out["method"] = method;
    out["host"] = host;
    out["path"] = path;
    out["attempted"] = p.attempted;
    out["status"] = p.status;
    out["ok"] = p.ok;
    if (!p.error.empty()) {
        out["error"] = p.error;
        out["gle"] = p.gle;
    }
    json headers = json::object();
    for (const auto& kv : p.headers)
        headers[kv.first] = header_value_json(kv.first, kv.second);
    out["headers"] = headers;
    out["body"] = {
        {"length_observed", p.body_length},
        {"hash64", hex64(p.body_hash)},
        {"truncated", p.body_truncated}
    };
    return out;
}

static std::vector<std::string> string_array_param(const json& params, const char* name, std::size_t cap) {
    std::vector<std::string> out;
    if (!params.contains(name) || !params[name].is_array())
        return out;
    for (const auto& v : params[name]) {
        if (v.is_string()) {
            out.push_back(v.get<std::string>());
            if (out.size() >= cap)
                break;
        }
    }
    return out;
}

static bool status_bucket_exists(DWORD status) {
    return status == 200 || status == 301 || status == 302 || status == 307 || status == 308 || status == 401 || status == 403;
}

static bool status_public(DWORD status) {
    return status >= 200 && status < 300;
}

static json write_probe(const std::string& provider,
                        const std::string& host,
                        const std::string& path,
                        const std::map<std::string, std::string>& headers) {
    json out;
    out["provider"] = provider;
    out["explicitly_permitted"] = true;
    const std::string marker_body = "aida-cloud-marker\n";
    http_probe_t put = http_probe("PUT", host, path, headers, marker_body, 5000, 1024);
    out["put"] = probe_json("write_marker_put", "PUT", host, path, put);
    if (status_public(put.status)) {
        http_probe_t del = http_probe("DELETE", host, path, headers, {}, 5000, 1024);
        out["delete"] = probe_json("write_marker_delete", "DELETE", host, path, del);
    }
    out["write_allowed_evidence"] = status_public(put.status);
    return out;
}

tool_result_t discover_s3(const json& params) {
    diag::log_tagged("cloud_tools", "discover_s3 entry");
    const auto buckets = string_array_param(params, "bucket_names", 64);
    if (buckets.empty())
        return tool_result_t::error("bucket_names must be a non-empty array");
    const std::string region = params.value("region", std::string());
    const bool check_list = params.value("check_list", false);
    const bool check_read = params.value("check_read", false);
    const bool allow_write = params.value("allow_write_check", false);
    const std::string object_key = params.value("object_key", std::string());
    json out;
    out["provider"] = "aws_s3";
    out["write_checks_default"] = false;
    out["results"] = json::array();
    for (const std::string& bucket : buckets) {
        if (call_expired())
            return tool_result_t::error("Cloud discovery cancelled or deadline reached", out);
        json item;
        item["bucket"] = bucket;
        if (!valid_dnsish(bucket, 3, 63, true, false)) {
            item["valid_name"] = false;
            item["error"] = "invalid_bucket_name";
            out["results"].push_back(item);
            continue;
        }
        const std::string host = region.empty() ? bucket + ".s3.amazonaws.com" : bucket + ".s3." + region + ".amazonaws.com";
        http_probe_t head = http_probe("HEAD", host, "/", {}, {}, 5000, 1024);
        item["head_bucket"] = probe_json("head_bucket", "HEAD", host, "/", head);
        item["exists_evidence"] = status_bucket_exists(head.status);
        item["public_metadata_evidence"] = status_public(head.status);
        if (check_list) {
            const std::string path = "/?list-type=2&max-keys=0";
            http_probe_t list = http_probe("GET", host, path, {}, {}, 5000, 2048);
            item["list_check"] = probe_json("list_bucket_limited", "GET", host, path, list);
            item["list_allowed_evidence"] = status_public(list.status);
        }
        if (check_read && !object_key.empty()) {
            const std::string path = "/" + url_path_escape(object_key);
            http_probe_t read = http_probe("HEAD", host, path, {}, {}, 5000, 1024);
            item["read_check"] = probe_json("head_object", "HEAD", host, path, read);
            item["read_allowed_evidence"] = status_public(read.status);
        }
        if (allow_write) {
            const std::string marker = params.value("marker_name", std::string("aida-public-write-probe.txt"));
            item["write_check"] = write_probe("aws_s3", host, "/" + url_path_escape(marker), {});
        }
        out["results"].push_back(item);
    }
    return tool_result_t::ok("S3 discovery complete", out);
}

tool_result_t discover_gcs(const json& params) {
    diag::log_tagged("cloud_tools", "discover_gcs entry");
    const auto buckets = string_array_param(params, "bucket_names", 64);
    if (buckets.empty())
        return tool_result_t::error("bucket_names must be a non-empty array");
    const bool check_list = params.value("check_list", false);
    const bool check_read = params.value("check_read", false);
    const bool allow_write = params.value("allow_write_check", false);
    const std::string object_name = params.value("object_name", std::string());
    json out;
    out["provider"] = "google_cloud_storage";
    out["write_checks_default"] = false;
    out["results"] = json::array();
    for (const std::string& bucket : buckets) {
        if (call_expired())
            return tool_result_t::error("Cloud discovery cancelled or deadline reached", out);
        json item;
        item["bucket"] = bucket;
        if (!valid_dnsish(bucket, 3, 222, true, true)) {
            item["valid_name"] = false;
            item["error"] = "invalid_bucket_name";
            out["results"].push_back(item);
            continue;
        }
        const std::string api_host = "storage.googleapis.com";
        const std::string meta_path = "/storage/v1/b/" + url_path_escape(bucket);
        http_probe_t meta = http_probe("GET", api_host, meta_path, {}, {}, 5000, 2048);
        item["metadata_check"] = probe_json("bucket_metadata", "GET", api_host, meta_path, meta);
        item["exists_evidence"] = status_bucket_exists(meta.status);
        item["public_metadata_evidence"] = status_public(meta.status);
        if (check_list) {
            const std::string list_path = "/storage/v1/b/" + url_path_escape(bucket) + "/o?maxResults=1&fields=kind,nextPageToken";
            http_probe_t list = http_probe("GET", api_host, list_path, {}, {}, 5000, 2048);
            item["list_check"] = probe_json("object_list_limited", "GET", api_host, list_path, list);
            item["list_allowed_evidence"] = status_public(list.status);
        }
        if (check_read && !object_name.empty()) {
            const std::string path = "/" + url_path_escape(bucket) + "/" + url_path_escape(object_name);
            http_probe_t read = http_probe("HEAD", api_host, path, {}, {}, 5000, 1024);
            item["read_check"] = probe_json("head_object", "HEAD", api_host, path, read);
            item["read_allowed_evidence"] = status_public(read.status);
        }
        if (allow_write) {
            const std::string marker = params.value("marker_name", std::string("aida-public-write-probe.txt"));
            item["write_check"] = write_probe("gcs", api_host, "/" + url_path_escape(bucket) + "/" + url_path_escape(marker), {});
        }
        out["results"].push_back(item);
    }
    return tool_result_t::ok("GCS discovery complete", out);
}

tool_result_t discover_azure_blob(const json& params) {
    diag::log_tagged("cloud_tools", "discover_azure_blob entry");
    const auto accounts = string_array_param(params, "account_names", 64);
    if (accounts.empty())
        return tool_result_t::error("account_names must be a non-empty array");
    const auto containers = string_array_param(params, "container_names", 128);
    const bool check_list = params.value("check_list", false);
    const bool check_read = params.value("check_read", false);
    const bool allow_write = params.value("allow_write_check", false);
    const std::string blob_name = params.value("blob_name", std::string());
    json out;
    out["provider"] = "azure_blob";
    out["write_checks_default"] = false;
    out["results"] = json::array();
    for (const std::string& account : accounts) {
        if (call_expired())
            return tool_result_t::error("Cloud discovery cancelled or deadline reached", out);
        json item;
        item["account"] = account;
        if (!valid_azure_account(account)) {
            item["valid_name"] = false;
            item["error"] = "invalid_account_name";
            out["results"].push_back(item);
            continue;
        }
        const std::string host = account + ".blob.core.windows.net";
        http_probe_t root = check_list
            ? http_probe("GET", host, "/?comp=list&maxresults=1", {{"x-ms-version", "2021-08-06"}}, {}, 5000, 2048)
            : http_probe("HEAD", host, "/", {{"x-ms-version", "2021-08-06"}}, {}, 5000, 1024);
        item["account_check"] = probe_json(check_list ? "account_container_list_limited" : "account_head", check_list ? "GET" : "HEAD", host, check_list ? "/?comp=list&maxresults=1" : "/", root);
        item["exists_evidence"] = status_bucket_exists(root.status) || root.status == 400;
        item["container_results"] = json::array();
        for (const std::string& container : containers) {
            if (call_expired())
                return tool_result_t::error("Cloud discovery cancelled or deadline reached", out);
            json c;
            c["container"] = container;
            if (!valid_dnsish(container, 3, 63, false, false)) {
                c["valid_name"] = false;
                c["error"] = "invalid_container_name";
                item["container_results"].push_back(c);
                continue;
            }
            const std::string base = "/" + url_path_escape(container);
            const std::string head_path = base + "?restype=container";
            http_probe_t head = http_probe("HEAD", host, head_path, {{"x-ms-version", "2021-08-06"}}, {}, 5000, 1024);
            c["container_check"] = probe_json("container_head", "HEAD", host, head_path, head);
            c["exists_evidence"] = status_bucket_exists(head.status);
            if (check_list) {
                const std::string list_path = base + "?restype=container&comp=list&maxresults=1";
                http_probe_t list = http_probe("GET", host, list_path, {{"x-ms-version", "2021-08-06"}}, {}, 5000, 2048);
                c["list_check"] = probe_json("blob_list_limited", "GET", host, list_path, list);
                c["list_allowed_evidence"] = status_public(list.status);
            }
            if (check_read && !blob_name.empty()) {
                const std::string path = base + "/" + url_path_escape(blob_name);
                http_probe_t read = http_probe("HEAD", host, path, {{"x-ms-version", "2021-08-06"}}, {}, 5000, 1024);
                c["read_check"] = probe_json("head_blob", "HEAD", host, path, read);
                c["read_allowed_evidence"] = status_public(read.status);
            }
            if (allow_write) {
                const std::string marker = params.value("marker_name", std::string("aida-public-write-probe.txt"));
                c["write_check"] = write_probe("azure_blob", host, base + "/" + url_path_escape(marker), {{"x-ms-version", "2021-08-06"}, {"x-ms-blob-type", "BlockBlob"}});
            }
            item["container_results"].push_back(c);
        }
        out["results"].push_back(item);
    }
    return tool_result_t::ok("Azure Blob discovery complete", out);
}

}

void register_cloud_tools(mcp_standalone::server_t& srv) {
    diag::log_tagged("cloud_tools", "register_cloud_tools entry");
    register_compat(srv, {
        std::string("aida.cloud.discover_s3"), std::string("network"),
        std::string("Probe public AWS S3 bucket endpoints with bounded HEAD/metadata checks and optional explicit list/read/write marker checks."),
        {{std::string("bucket_names"), std::string("array"), std::string("Bucket names to probe, capped at 64."), true},
         {std::string("region"), std::string("string"), std::string("Optional AWS region for regional S3 hostname."), false},
         {std::string("check_list"), std::string("boolean"), std::string("Explicitly perform a limited list check with max-keys=0."), false},
         {std::string("check_read"), std::string("boolean"), std::string("Explicitly HEAD object_key when supplied."), false},
         {std::string("object_key"), std::string("string"), std::string("Object key for explicit read check."), false},
         {std::string("allow_write_check"), std::string("boolean"), std::string("Explicit permission to PUT a marker object and attempt cleanup."), false},
         {std::string("marker_name"), std::string("string"), std::string("Marker object name for explicit write check."), false}},
        discover_s3, false});

    register_compat(srv, {
        std::string("aida.cloud.discover_gcs"), std::string("network"),
        std::string("Probe public Google Cloud Storage buckets with bounded metadata checks and optional explicit list/read/write marker checks."),
        {{std::string("bucket_names"), std::string("array"), std::string("Bucket names to probe, capped at 64."), true},
         {std::string("check_list"), std::string("boolean"), std::string("Explicitly perform a limited object list check."), false},
         {std::string("check_read"), std::string("boolean"), std::string("Explicitly HEAD object_name when supplied."), false},
         {std::string("object_name"), std::string("string"), std::string("Object name for explicit read check."), false},
         {std::string("allow_write_check"), std::string("boolean"), std::string("Explicit permission to PUT a marker object and attempt cleanup."), false},
         {std::string("marker_name"), std::string("string"), std::string("Marker object name for explicit write check."), false}},
        discover_gcs, false});

    register_compat(srv, {
        std::string("aida.cloud.discover_azure_blob"), std::string("network"),
        std::string("Probe public Azure Blob accounts and specified containers with bounded metadata checks and optional explicit list/read/write marker checks."),
        {{std::string("account_names"), std::string("array"), std::string("Storage account names to probe, capped at 64."), true},
         {std::string("container_names"), std::string("array"), std::string("Optional container names to probe, capped at 128."), false},
         {std::string("check_list"), std::string("boolean"), std::string("Explicitly perform limited account/container list checks."), false},
         {std::string("check_read"), std::string("boolean"), std::string("Explicitly HEAD blob_name when supplied."), false},
         {std::string("blob_name"), std::string("string"), std::string("Blob name for explicit read check."), false},
         {std::string("allow_write_check"), std::string("boolean"), std::string("Explicit permission to PUT a marker blob and attempt cleanup."), false},
         {std::string("marker_name"), std::string("string"), std::string("Marker blob name for explicit write check."), false}},
        discover_azure_blob, false});
    diag::log_tagged("cloud_tools", "register_cloud_tools complete");
}

}
}
