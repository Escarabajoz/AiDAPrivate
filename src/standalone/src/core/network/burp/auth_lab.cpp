#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#ifdef small
#undef small
#endif

#include "auth_lab.hpp"
#include "audit_http.hpp"

#include "../../../helpers/diag_log.hpp"

#include <httplib.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <limits>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include <zlib.h>

#include <nlohmann/json.hpp>

#pragma comment(lib, "Bcrypt.lib")

namespace aida {
namespace burp {
namespace auth_lab {

namespace {

struct state_t
{
    std::atomic<bool>   initialized{false};
    std::mutex          err_mtx;
    std::string         last_err;
};

state_t& s()
{
    static state_t st;
    return st;
}

void set_err(const std::string& msg)
{
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    st.last_err = msg;
}

const char kB64Std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64std_index(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

std::string base64_encode_internal(const uint8_t* data, size_t len)
{
    std::string out;
    if (len == 0) return out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        const uint32_t t = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8) | uint32_t(data[i+2]);
        out.push_back(kB64Std[(t >> 18) & 63]);
        out.push_back(kB64Std[(t >> 12) & 63]);
        out.push_back(kB64Std[(t >> 6) & 63]);
        out.push_back(kB64Std[t & 63]);
        i += 3;
    }
    const size_t rem = len - i;
    if (rem == 1) {
        const uint32_t t = uint32_t(data[i]) << 16;
        out.push_back(kB64Std[(t >> 18) & 63]);
        out.push_back(kB64Std[(t >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t t = (uint32_t(data[i]) << 16) | (uint32_t(data[i+1]) << 8);
        out.push_back(kB64Std[(t >> 18) & 63]);
        out.push_back(kB64Std[(t >> 12) & 63]);
        out.push_back(kB64Std[(t >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::string base64url_encode_no_pad(const uint8_t* data, size_t len)
{
    std::string out = base64_encode_internal(data, len);
    while (!out.empty() && out.back() == '=') out.pop_back();
    for (auto& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

bool base64_decode_internal(const std::string& in, std::string& out)
{
    out.clear();
    out.reserve((in.size() * 3) / 4 + 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        const int v = b64std_index(c);
        if (v < 0) return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return true;
}

std::string url_encode(const std::string& in)
{
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

std::string ascii_lower(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if (c >= 'A' && c <= 'Z') out.push_back(static_cast<char>(c + 32));
        else                       out.push_back(c);
    }
    return out;
}

std::string trim(const std::string& in)
{
    size_t b = 0;
    while (b < in.size() && (in[b] == ' ' || in[b] == '\t' || in[b] == '\r' || in[b] == '\n')) ++b;
    size_t e = in.size();
    while (e > b && (in[e-1] == ' ' || in[e-1] == '\t' || in[e-1] == '\r' || in[e-1] == '\n')) --e;
    return in.substr(b, e - b);
}

std::string hex_lower(const uint8_t* data, size_t len)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

bool evp_digest(const EVP_MD* md, const std::string& data, std::vector<uint8_t>& out)
{
    out.clear();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) == 1) {
        out.assign(EVP_MAX_MD_SIZE, 0);
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx, out.data(), &len) == 1) {
            out.resize(len);
            ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool evp_digest_bytes(const EVP_MD* md, const uint8_t* data, size_t len_in, std::vector<uint8_t>& out)
{
    out.clear();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, data, len_in) == 1) {
        out.assign(EVP_MAX_MD_SIZE, 0);
        unsigned int olen = 0;
        if (EVP_DigestFinal_ex(ctx, out.data(), &olen) == 1) {
            out.resize(olen);
            ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

uint32_t md4_rol(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (32u - bits));
}

bool md4_fallback_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
{
    if (!data && len != 0)
        return false;

    std::vector<uint8_t> msg;
    msg.reserve(len + 72);
    msg.insert(msg.end(), data, data + len);
    msg.push_back(0x80);
    while ((msg.size() & 63u) != 56u)
        msg.push_back(0);

    const uint64_t bit_len = static_cast<uint64_t>(len) * 8u;
    for (int i = 0; i < 8; ++i)
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFFu));

    uint32_t a0 = 0x67452301u;
    uint32_t b0 = 0xefcdab89u;
    uint32_t c0 = 0x98badcfeu;
    uint32_t d0 = 0x10325476u;

    auto f = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
    auto g = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); };
    auto h = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t x[16];
        for (int i = 0; i < 16; ++i) {
            const size_t p = off + static_cast<size_t>(i) * 4u;
            x[i] = static_cast<uint32_t>(msg[p]) |
                   (static_cast<uint32_t>(msg[p + 1]) << 8) |
                   (static_cast<uint32_t>(msg[p + 2]) << 16) |
                   (static_cast<uint32_t>(msg[p + 3]) << 24);
        }

        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        auto r1 = [&](uint32_t& aa, uint32_t bb, uint32_t cc, uint32_t dd, int k, uint32_t sft) {
            aa = md4_rol(aa + f(bb, cc, dd) + x[k], sft);
        };
        auto r2 = [&](uint32_t& aa, uint32_t bb, uint32_t cc, uint32_t dd, int k, uint32_t sft) {
            aa = md4_rol(aa + g(bb, cc, dd) + x[k] + 0x5a827999u, sft);
        };
        auto r3 = [&](uint32_t& aa, uint32_t bb, uint32_t cc, uint32_t dd, int k, uint32_t sft) {
            aa = md4_rol(aa + h(bb, cc, dd) + x[k] + 0x6ed9eba1u, sft);
        };

        r1(a, b, c, d, 0, 3);  r1(d, a, b, c, 1, 7);  r1(c, d, a, b, 2, 11);  r1(b, c, d, a, 3, 19);
        r1(a, b, c, d, 4, 3);  r1(d, a, b, c, 5, 7);  r1(c, d, a, b, 6, 11);  r1(b, c, d, a, 7, 19);
        r1(a, b, c, d, 8, 3);  r1(d, a, b, c, 9, 7);  r1(c, d, a, b, 10, 11); r1(b, c, d, a, 11, 19);
        r1(a, b, c, d, 12, 3); r1(d, a, b, c, 13, 7); r1(c, d, a, b, 14, 11); r1(b, c, d, a, 15, 19);

        r2(a, b, c, d, 0, 3);  r2(d, a, b, c, 4, 5);  r2(c, d, a, b, 8, 9);   r2(b, c, d, a, 12, 13);
        r2(a, b, c, d, 1, 3);  r2(d, a, b, c, 5, 5);  r2(c, d, a, b, 9, 9);   r2(b, c, d, a, 13, 13);
        r2(a, b, c, d, 2, 3);  r2(d, a, b, c, 6, 5);  r2(c, d, a, b, 10, 9);  r2(b, c, d, a, 14, 13);
        r2(a, b, c, d, 3, 3);  r2(d, a, b, c, 7, 5);  r2(c, d, a, b, 11, 9);  r2(b, c, d, a, 15, 13);

        r3(a, b, c, d, 0, 3);  r3(d, a, b, c, 8, 9);  r3(c, d, a, b, 4, 11);  r3(b, c, d, a, 12, 15);
        r3(a, b, c, d, 2, 3);  r3(d, a, b, c, 10, 9); r3(c, d, a, b, 6, 11);  r3(b, c, d, a, 14, 15);
        r3(a, b, c, d, 1, 3);  r3(d, a, b, c, 9, 9);  r3(c, d, a, b, 5, 11);  r3(b, c, d, a, 13, 15);
        r3(a, b, c, d, 3, 3);  r3(d, a, b, c, 11, 9); r3(c, d, a, b, 7, 11);  r3(b, c, d, a, 15, 15);

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    out.assign(16, 0);
    const uint32_t words[4] = { a0, b0, c0, d0 };
    for (int i = 0; i < 4; ++i) {
        out[static_cast<size_t>(i) * 4u] = static_cast<uint8_t>(words[i] & 0xFFu);
        out[static_cast<size_t>(i) * 4u + 1u] = static_cast<uint8_t>((words[i] >> 8) & 0xFFu);
        out[static_cast<size_t>(i) * 4u + 2u] = static_cast<uint8_t>((words[i] >> 16) & 0xFFu);
        out[static_cast<size_t>(i) * 4u + 3u] = static_cast<uint8_t>((words[i] >> 24) & 0xFFu);
    }
    return true;
}

bool evp_md4_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
{
    return md4_fallback_bytes(data, len, out);
}

bool evp_md5_bytes(const uint8_t* data, size_t len, std::vector<uint8_t>& out)
{
    return evp_digest_bytes(EVP_md5(), data, len, out);
}

bool hmac_md5_bytes(const uint8_t* key, size_t key_len,
                    const uint8_t* data, size_t data_len,
                    std::vector<uint8_t>& out)
{
    if ((!key && key_len != 0) || (!data && data_len != 0))
        return false;
    if (key_len > static_cast<size_t>(std::numeric_limits<ULONG>::max()) ||
        data_len > static_cast<size_t>(std::numeric_limits<ULONG>::max()))
        return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hash_len = 0;
    DWORD cb = 0;
    bool ok = false;

    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;

    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len),
        sizeof(hash_len), &cb, 0);
    if (!BCRYPT_SUCCESS(st) || hash_len == 0) goto cleanup;

    st = BCryptCreateHash(alg, &hash, nullptr, 0,
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(key)),
        static_cast<ULONG>(key_len), 0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;

    st = BCryptHashData(hash,
        const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data)),
        static_cast<ULONG>(data_len), 0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;

    out.assign(hash_len, 0);
    st = BCryptFinishHash(hash, reinterpret_cast<PUCHAR>(out.data()), hash_len, 0);
    ok = BCRYPT_SUCCESS(st);
    if (!ok)
        out.clear();

cleanup:
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

std::string parse_quoted_or_token(const std::string& v, size_t& pos)
{
    while (pos < v.size() && (v[pos] == ' ' || v[pos] == '\t')) ++pos;
    if (pos >= v.size()) return std::string();
    if (v[pos] == '"') {
        ++pos;
        std::string out;
        while (pos < v.size() && v[pos] != '"') {
            if (v[pos] == '\\' && pos + 1 < v.size()) { out.push_back(v[pos+1]); pos += 2; continue; }
            out.push_back(v[pos++]);
        }
        if (pos < v.size() && v[pos] == '"') ++pos;
        return out;
    }
    size_t start = pos;
    while (pos < v.size() && v[pos] != ',' && v[pos] != ' ' && v[pos] != '\t') ++pos;
    return v.substr(start, pos - start);
}

std::vector<std::pair<std::string, std::string>> parse_auth_header(const std::string& header)
{
    std::vector<std::pair<std::string, std::string>> out;
    size_t pos = 0;
    while (pos < header.size() && header[pos] != ' ') ++pos;
    while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t')) ++pos;
    while (pos < header.size()) {
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t' || header[pos] == ',')) ++pos;
        if (pos >= header.size()) break;
        size_t key_start = pos;
        while (pos < header.size() && header[pos] != '=' && header[pos] != ',' && header[pos] != ' ') ++pos;
        std::string key = header.substr(key_start, pos - key_start);
        while (pos < header.size() && (header[pos] == ' ' || header[pos] == '\t')) ++pos;
        if (pos < header.size() && header[pos] == '=') {
            ++pos;
            std::string val = parse_quoted_or_token(header, pos);
            out.emplace_back(ascii_lower(key), val);
        } else {
            out.emplace_back(ascii_lower(key), std::string());
        }
        while (pos < header.size() && header[pos] != ',') ++pos;
        if (pos < header.size() && header[pos] == ',') ++pos;
    }
    return out;
}

std::string get_param(const std::vector<std::pair<std::string, std::string>>& kv, const std::string& key)
{
    for (const auto& p : kv) if (p.first == key) return p.second;
    return std::string();
}

std::vector<uint8_t> random_bytes(size_t n)
{
    std::vector<uint8_t> out(n, 0);
    BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return out;
}

struct url_log_t
{
    std::string scheme;
    std::string host;
    std::string path;
    uint16_t port = 0;
    bool has_query = false;
    size_t length = 0;
};

url_log_t summarize_url_for_log(const std::string& url)
{
    url_log_t out;
    out.length = url.size();
    size_t schema_end = url.find("://");
    size_t cursor = 0;
    if (schema_end != std::string::npos)
    {
        out.scheme = ascii_lower(url.substr(0, schema_end));
        cursor = schema_end + 3;
    }
    size_t path_start = url.find('/', cursor);
    size_t auth_end = path_start == std::string::npos ? url.find_first_of("?#", cursor) : path_start;
    if (auth_end == std::string::npos) auth_end = url.size();
    std::string authority = auth_end > cursor ? url.substr(cursor, auth_end - cursor) : std::string();
    size_t colon = authority.find(':');
    out.host = colon == std::string::npos ? authority : authority.substr(0, colon);
    if (colon != std::string::npos)
    {
        int v = 0;
        for (char c : authority.substr(colon + 1))
        {
            if (c < '0' || c > '9') { v = 0; break; }
            v = v * 10 + (c - '0');
        }
        if (v > 0 && v <= 65535) out.port = static_cast<uint16_t>(v);
    }
    if (out.port == 0) out.port = out.scheme == "http" ? 80 : 443;
    out.has_query = url.find('?', cursor) != std::string::npos;
    size_t path_end = url.size();
    size_t q = url.find('?', cursor);
    size_t f = url.find('#', cursor);
    if (q != std::string::npos) path_end = q;
    if (f != std::string::npos && f < path_end) path_end = f;
    if (path_start != std::string::npos && path_start < path_end) out.path = url.substr(path_start, path_end - path_start);
    if (out.path.empty()) out.path = "/";
    if (out.host.empty()) out.host = "<missing>";
    if (out.path.size() > 240)
    {
        out.path.resize(240);
        out.path += "...";
    }
    return out;
}

bool is_loopback_host(const std::string& host)
{
    std::string h = ascii_lower(host);
    return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]";
}

std::string header_safe(std::string s)
{
    for (char& c : s)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F)
            c = '_';
    }
    return s;
}

bool http_post_form_audit_fallback(const std::string& host,
                                   uint16_t port,
                                   const std::string& path,
                                   bool is_https,
                                   const std::string& body,
                                   std::string& body_out,
                                   std::string& transport_error)
{
    std::string req;
    req.reserve(512 + body.size());
    req += "POST ";
    req += path.empty() ? "/" : path;
    req += " HTTP/1.1\r\nHost: ";
    req += header_safe(host);
    req += ":";
    req += std::to_string(port);
    req += "\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\nUser-Agent: AiDA-AuthLab/1.0\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: ";
    req += std::to_string(body.size());
    req += "\r\n\r\n";
    req += body;
    std::vector<uint8_t> raw(req.begin(), req.end());
    audit_http::send_options_t opts;
    opts.timeout_ms = 15000;
    opts.follow_redirects = false;
    opts.enforce_scope = false;
    auto ex = audit_http::send(raw, host, port, is_https, opts);
    if (!ex)
    {
        transport_error = audit_http::last_error();
        diag::log_tagged_fmt("auth_lab", "http_post_form fallback_no_response host=%s port=%u path=%s tls=%d err=%s",
            host.c_str(),
            static_cast<unsigned>(port),
            path.c_str(),
            is_https ? 1 : 0,
            transport_error.c_str());
        return false;
    }
    body_out.assign(reinterpret_cast<const char*>(ex->resp_body.data()), ex->resp_body.size());
    diag::log_tagged_fmt("auth_lab", "http_post_form fallback_response status=%d response_len=%zu host=%s port=%u path=%s",
        ex->status_code,
        body_out.size(),
        host.c_str(),
        static_cast<unsigned>(port),
        path.c_str());
    if (ex->status_code < 200 || ex->status_code >= 300)
    {
        transport_error = "HTTP " + std::to_string(ex->status_code);
        return false;
    }
    return true;
}

bool http_post_form(const std::string& token_endpoint,
                    const std::vector<std::pair<std::string, std::string>>& form,
                    std::string& body_out)
{
    body_out.clear();
    const url_log_t endpoint_log = summarize_url_for_log(token_endpoint);
    bool has_client_id = false;
    bool has_code = false;
    bool has_redirect_uri = false;
    bool has_code_verifier = false;
    bool has_refresh_token = false;
    for (const auto& kv : form)
    {
        if (kv.first == "client_id") has_client_id = !kv.second.empty();
        else if (kv.first == "code") has_code = !kv.second.empty();
        else if (kv.first == "redirect_uri") has_redirect_uri = !kv.second.empty();
        else if (kv.first == "code_verifier") has_code_verifier = !kv.second.empty();
        else if (kv.first == "refresh_token") has_refresh_token = !kv.second.empty();
    }
    diag::log_tagged_fmt("auth_lab", "http_post_form entry scheme=%s host=%s port=%u path=%s query=%d fields=%zu has_client_id=%d has_code=%d has_redirect_uri=%d has_verifier=%d has_refresh=%d endpoint_len=%zu",
        endpoint_log.scheme.c_str(), endpoint_log.host.c_str(), static_cast<unsigned>(endpoint_log.port), endpoint_log.path.c_str(),
        (int)endpoint_log.has_query, form.size(), (int)has_client_id, (int)has_code, (int)has_redirect_uri,
        (int)has_code_verifier, (int)has_refresh_token, endpoint_log.length);
    std::string scheme, host, path;
    uint16_t port = 0;
    bool is_https = false;
    {
        std::string u = token_endpoint;
        size_t schema_end = u.find("://");
        if (schema_end == std::string::npos) {
            diag::log_tagged_fmt("auth_lab", "http_post_form invalid_endpoint endpoint_len=%zu", token_endpoint.size());
            set_err("invalid token endpoint");
            return false;
        }
        scheme = ascii_lower(u.substr(0, schema_end));
        is_https = (scheme == "https");
        size_t cursor = schema_end + 3;
        size_t path_start = u.find('/', cursor);
        std::string authority = (path_start == std::string::npos) ? u.substr(cursor) : u.substr(cursor, path_start - cursor);
        size_t colon = authority.find(':');
        if (colon == std::string::npos) {
            host = authority;
            port = is_https ? 443 : 80;
        } else {
            host = authority.substr(0, colon);
            const std::string ps = authority.substr(colon + 1);
            int v = 0;
            for (char c : ps) { if (c < '0' || c > '9') { v = -1; break; } v = v * 10 + (c - '0'); }
            port = (v <= 0 || v > 65535) ? (is_https ? 443 : 80) : static_cast<uint16_t>(v);
        }
        path = (path_start == std::string::npos) ? std::string("/") : u.substr(path_start);
    }

    std::string body;
    for (size_t i = 0; i < form.size(); ++i) {
        if (i > 0) body.push_back('&');
        body.append(url_encode(form[i].first));
        body.push_back('=');
        body.append(url_encode(form[i].second));
    }
    diag::log_tagged_fmt("auth_lab", "http_post_form body_built body_len=%zu host=%s path=%s", body.size(), host.c_str(), endpoint_log.path.c_str());

    httplib::Headers headers = {
        { "Content-Type", "application/x-www-form-urlencoded" },
        { "Accept", "application/json" },
        { "User-Agent", "AiDA-AuthLab/1.0" }
    };
    std::string origin = (is_https ? "https://" : "http://") + host + ":" + std::to_string(port);
    std::string last_transport_error;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        httplib::Client cli(origin);
        cli.set_connection_timeout(15, 0);
        cli.set_read_timeout(20, 0);
        cli.set_write_timeout(20, 0);
        cli.enable_server_certificate_verification(true);
        cli.set_follow_location(false);
        auto res = cli.Post(path, headers, body, "application/x-www-form-urlencoded");
        if (res) {
            body_out = res->body;
            diag::log_tagged_fmt("auth_lab", "http_post_form response attempt=%d status=%d response_len=%zu host=%s path=%s",
                attempt, res->status, body_out.size(), host.c_str(), endpoint_log.path.c_str());
            if (res->status < 200 || res->status >= 300) {
                set_err("http_post_form: HTTP " + std::to_string(res->status));
                return false;
            }
            return true;
        }
        last_transport_error = httplib::to_string(res.error());
        diag::log_tagged_fmt("auth_lab", "http_post_form no_response attempt=%d host=%s port=%u path=%s body_len=%zu err=%s",
            attempt, host.c_str(), static_cast<unsigned>(port), endpoint_log.path.c_str(), body.size(), last_transport_error.c_str());
        if (is_loopback_host(host)) {
            std::string fallback_error;
            if (http_post_form_audit_fallback(host, port, path, is_https, body, body_out, fallback_error))
                return true;
            if (!fallback_error.empty())
                last_transport_error += "; audit_http=" + fallback_error;
        }
        Sleep(static_cast<DWORD>(25 * attempt));
    }
    set_err(last_transport_error.empty() ? "http_post_form: no response" : ("http_post_form: no response (" + last_transport_error + ")"));
    return false;
}

}

bool initialize()
{
    auto& st = s();
    bool expected = false;
    if (!st.initialized.compare_exchange_strong(expected, true)) return true;
    diag::log_tagged("burp", "auth_lab_initialized");
    return true;
}

void shutdown()
{
    diag::log_tagged_fmt("auth_lab", "shutdown entry");
    auto& st = s();
    if (!st.initialized.exchange(false)) {
        diag::log_tagged_fmt("auth_lab", "shutdown already_stopped");
        return;
    }
    diag::log_tagged_fmt("auth_lab", "shutdown complete");
}

std::string base64_encode_std(const uint8_t* data, size_t len)
{
    return base64_encode_internal(data, len);
}

bool base64_decode_std(const std::string& in, std::string& out)
{
    return base64_decode_internal(in, out);
}

std::string basic_encode(const std::string& user, const std::string& pass)
{
    diag::log_tagged_fmt("auth_lab", "basic_encode entry user=%s pass_len=%zu", user.c_str(), pass.size());
    std::string raw = user + ":" + pass;
    std::string enc = base64_encode_internal(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    diag::log_tagged_fmt("auth_lab", "basic_encode ok enc_len=%zu", enc.size());
    return std::string("Basic ") + enc;
}

bool basic_decode(const std::string& header, std::string& user, std::string& pass)
{
    diag::log_tagged_fmt("auth_lab", "basic_decode entry header_len=%zu", header.size());
    user.clear();
    pass.clear();
    std::string h = trim(header);
    if (h.size() < 6) {
        diag::log_tagged_fmt("auth_lab", "basic_decode error header_too_short len=%zu", h.size());
        return false;
    }
    std::string lo = ascii_lower(h.substr(0, 6));
    if (lo != "basic ") {
        diag::log_tagged_fmt("auth_lab", "basic_decode error not_basic_scheme prefix=%s", lo.c_str());
        return false;
    }
    std::string b = trim(h.substr(6));
    std::string raw;
    if (!base64_decode_internal(b, raw)) {
        diag::log_tagged_fmt("auth_lab", "basic_decode error b64_decode_failed");
        return false;
    }
    size_t colon = raw.find(':');
    if (colon == std::string::npos) {
        diag::log_tagged_fmt("auth_lab", "basic_decode error no_colon_in_decoded");
        return false;
    }
    user = raw.substr(0, colon);
    pass = raw.substr(colon + 1);
    diag::log_tagged_fmt("auth_lab", "basic_decode ok user=%s pass_len=%zu", user.c_str(), pass.size());
    return true;
}

std::string digest_solve(const std::string& method,
                         const std::string& uri,
                         const std::string& body,
                         const std::string& www_auth_header,
                         const std::string& user,
                         const std::string& pass,
                         const std::string& cnonce_in)
{
    diag::log_tagged_fmt("auth_lab", "digest_solve entry method=%s uri=%s user=%s body_len=%zu",
        method.c_str(), uri.c_str(), user.c_str(), body.size());
    auto kv = parse_auth_header(www_auth_header);
    std::string realm = get_param(kv, "realm");
    std::string nonce = get_param(kv, "nonce");
    std::string qop = get_param(kv, "qop");
    std::string opaque = get_param(kv, "opaque");
    std::string algorithm = get_param(kv, "algorithm");
    if (algorithm.empty()) algorithm = "MD5";
    diag::log_tagged_fmt("auth_lab", "digest_solve realm=%s nonce_len=%zu qop=%s algorithm=%s",
        get_param(kv, "realm").c_str(), get_param(kv, "nonce").size(), get_param(kv, "qop").c_str(), algorithm.c_str());

    std::string algorithm_up;
    for (char c : algorithm) algorithm_up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    const bool sess = (algorithm_up.find("-SESS") != std::string::npos);
    const EVP_MD* md = EVP_md5();
    if (algorithm_up.find("SHA-512-256") != std::string::npos) md = EVP_sha512_256();
    else if (algorithm_up.find("SHA-256") != std::string::npos) md = EVP_sha256();
    else md = EVP_md5();

    std::string qop_sel;
    {
        std::string lq = ascii_lower(qop);
        if (lq.find("auth-int") != std::string::npos) qop_sel = "auth-int";
        else if (lq.find("auth") != std::string::npos) qop_sel = "auth";
    }

    std::string cnonce = cnonce_in;
    if (cnonce.empty()) {
        const auto rb = random_bytes(16);
        cnonce = hex_lower(rb.data(), rb.size());
    }

    auto hex_md = [&](const std::string& data) -> std::string {
        std::vector<uint8_t> out;
        evp_digest(md, data, out);
        return hex_lower(out.data(), out.size());
    };

    std::string a1 = user + ":" + realm + ":" + pass;
    std::string ha1 = hex_md(a1);
    if (sess) {
        ha1 = hex_md(ha1 + ":" + nonce + ":" + cnonce);
    }

    std::string a2 = method + ":" + uri;
    if (qop_sel == "auth-int") {
        a2 += ":" + hex_md(body);
    }
    std::string ha2 = hex_md(a2);

    std::string nc = "00000001";
    std::string response_input;
    if (qop_sel == "auth" || qop_sel == "auth-int") {
        response_input = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop_sel + ":" + ha2;
    } else {
        response_input = ha1 + ":" + nonce + ":" + ha2;
    }
    std::string response_hash = hex_md(response_input);

    std::string out = "Digest username=\"" + user + "\"";
    out += ", realm=\"" + realm + "\"";
    out += ", nonce=\"" + nonce + "\"";
    out += ", uri=\"" + uri + "\"";
    out += ", algorithm=" + algorithm;
    if (!qop_sel.empty()) {
        out += ", qop=" + qop_sel;
        out += ", nc=" + nc;
        out += ", cnonce=\"" + cnonce + "\"";
    }
    out += ", response=\"" + response_hash + "\"";
    if (!opaque.empty()) out += ", opaque=\"" + opaque + "\"";
    diag::log_tagged_fmt("auth_lab", "digest_solve result_len=%zu qop_sel=%s sess=%d", out.size(), qop_sel.c_str(), (int)sess);
    return out;
}

std::string ntlm_type1(const std::string& domain, const std::string& workstation)
{
    diag::log_tagged_fmt("auth_lab", "ntlm_type1 entry domain=%s workstation=%s", domain.c_str(), workstation.c_str());
    if (domain.size() > 65535 || workstation.size() > 65535) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type1 rejected oversized domain=%zu workstation=%zu", domain.size(), workstation.size());
        set_err("ntlm_type1: domain/workstation too large");
        return std::string();
    }
    if (domain.size() + workstation.size() > 65535 - 32) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type1 rejected combined size domain=%zu workstation=%zu", domain.size(), workstation.size());
        set_err("ntlm_type1: combined fields too large");
        return std::string();
    }
    std::vector<uint8_t> msg;
    msg.reserve(64);
    const char sig[] = "NTLMSSP";
    msg.insert(msg.end(), sig, sig + 8);
    auto u32 = [&](uint32_t v) {
        msg.push_back(static_cast<uint8_t>(v & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };
    auto u16 = [&](uint16_t v) {
        msg.push_back(static_cast<uint8_t>(v & 0xFF));
        msg.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    u32(1);
    const uint32_t flags = 0x60088207;
    u32(flags);
    u16(static_cast<uint16_t>(domain.size()));
    u16(static_cast<uint16_t>(domain.size()));
    u32(static_cast<uint32_t>(32 + workstation.size()));
    u16(static_cast<uint16_t>(workstation.size()));
    u16(static_cast<uint16_t>(workstation.size()));
    u32(32);
    msg.insert(msg.end(), workstation.begin(), workstation.end());
    msg.insert(msg.end(), domain.begin(), domain.end());
    std::string result = base64_encode_internal(msg.data(), msg.size());
    diag::log_tagged_fmt("auth_lab", "ntlm_type1 ok msg_bytes=%zu b64_len=%zu", msg.size(), result.size());
    return result;
}

namespace {

std::vector<uint8_t> utf16le_upper(const std::string& s_in)
{
    std::vector<uint8_t> out;
    out.reserve(s_in.size() * 2);
    for (unsigned char c : s_in) {
        unsigned char up = (c >= 'a' && c <= 'z') ? static_cast<unsigned char>(c - 32) : c;
        out.push_back(up);
        out.push_back(0);
    }
    return out;
}

std::vector<uint8_t> utf16le(const std::string& s_in)
{
    std::vector<uint8_t> out;
    out.reserve(s_in.size() * 2);
    for (unsigned char c : s_in) {
        out.push_back(c);
        out.push_back(0);
    }
    return out;
}

}

std::string ntlm_type3(const std::string& type2_b64,
                       const std::string& user,
                       const std::string& pass,
                       const std::string& domain,
                       const std::string& workstation)
{
    diag::log_tagged_fmt("auth_lab", "ntlm_type3 entry user=%s domain=%s workstation=%s type2_b64_len=%zu",
        user.c_str(), domain.c_str(), workstation.c_str(), type2_b64.size());
    std::string raw_type2;
    if (!base64_decode_internal(type2_b64, raw_type2)) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 error type2_b64_decode_failed");
        set_err("ntlm_type3: type2 b64 decode failed");
        return std::string();
    }
    if (raw_type2.size() < 48) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 error type2_too_short size=%zu", raw_type2.size());
        set_err("ntlm_type3: type2 too short");
        return std::string();
    }
    diag::log_tagged_fmt("auth_lab", "ntlm_type3 type2_decoded size=%zu", raw_type2.size());
    const uint8_t* t2 = reinterpret_cast<const uint8_t*>(raw_type2.data());
    uint8_t server_challenge[8];
    std::memcpy(server_challenge, t2 + 24, 8);
    const uint16_t target_info_len = static_cast<uint16_t>(t2[40] | (t2[41] << 8));
    const uint32_t target_info_off = static_cast<uint32_t>(t2[44] | (t2[45] << 8) | (t2[46] << 16) | (t2[47] << 24));
    std::vector<uint8_t> target_info;
    if (target_info_off + target_info_len <= raw_type2.size()) {
        target_info.assign(t2 + target_info_off, t2 + target_info_off + target_info_len);
    }

    std::vector<uint8_t> pass_utf16 = utf16le(pass);
    std::vector<uint8_t> ntlm_hash;
    if (!evp_md4_bytes(pass_utf16.data(), pass_utf16.size(), ntlm_hash) || ntlm_hash.size() != 16) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 error md4_failed");
        set_err("ntlm_type3: md4 failed");
        return std::string();
    }
    diag::log_tagged_fmt("auth_lab", "ntlm_type3 ntlm_hash_ok computing_ntlmv2");

    std::vector<uint8_t> user_dom_utf16;
    {
        std::vector<uint8_t> ub = utf16le_upper(user);
        std::vector<uint8_t> db = utf16le(domain);
        user_dom_utf16.reserve(ub.size() + db.size());
        user_dom_utf16.insert(user_dom_utf16.end(), ub.begin(), ub.end());
        user_dom_utf16.insert(user_dom_utf16.end(), db.begin(), db.end());
    }
    std::vector<uint8_t> ntlmv2_hash;
    if (!hmac_md5_bytes(ntlm_hash.data(), ntlm_hash.size(),
                        user_dom_utf16.data(), user_dom_utf16.size(), ntlmv2_hash) ||
        ntlmv2_hash.size() != 16) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 error hmac_md5_failed");
        set_err("ntlm_type3: hmac-md5 failed");
        return std::string();
    }
    diag::log_tagged_fmt("auth_lab", "ntlm_type3 ntlmv2_hash_ok building_blob");

    uint64_t now_filetime_100ns = 0;
    {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        now_filetime_100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }
    uint8_t client_challenge[8];
    {
        auto rb = random_bytes(8);
        std::memcpy(client_challenge, rb.data(), 8);
    }

    std::vector<uint8_t> blob;
    blob.reserve(28 + target_info.size() + 4);
    blob.push_back(0x01); blob.push_back(0x01);
    blob.push_back(0x00); blob.push_back(0x00);
    blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00);
    for (int i = 0; i < 8; ++i) blob.push_back(static_cast<uint8_t>((now_filetime_100ns >> (i * 8)) & 0xFF));
    blob.insert(blob.end(), client_challenge, client_challenge + 8);
    blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00);
    blob.insert(blob.end(), target_info.begin(), target_info.end());
    blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00); blob.push_back(0x00);

    std::vector<uint8_t> ntlmv2_data;
    ntlmv2_data.reserve(8 + blob.size());
    ntlmv2_data.insert(ntlmv2_data.end(), server_challenge, server_challenge + 8);
    ntlmv2_data.insert(ntlmv2_data.end(), blob.begin(), blob.end());
    std::vector<uint8_t> nt_proof;
    if (!hmac_md5_bytes(ntlmv2_hash.data(), ntlmv2_hash.size(),
                        ntlmv2_data.data(), ntlmv2_data.size(), nt_proof) ||
        nt_proof.size() != 16) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 error nt_proof_hmac_failed");
        set_err("ntlm_type3: nt proof hmac failed");
        return std::string();
    }
    diag::log_tagged_fmt("auth_lab", "ntlm_type3 nt_proof_ok nt_response_bytes=%zu", 16 + blob.size());
    std::vector<uint8_t> nt_response;
    nt_response.reserve(16 + blob.size());
    nt_response.insert(nt_response.end(), nt_proof.begin(), nt_proof.end());
    nt_response.insert(nt_response.end(), blob.begin(), blob.end());

    std::vector<uint8_t> lm_response(24, 0);
    {
        std::vector<uint8_t> lm_data;
        lm_data.reserve(16);
        lm_data.insert(lm_data.end(), server_challenge, server_challenge + 8);
        lm_data.insert(lm_data.end(), client_challenge, client_challenge + 8);
        std::vector<uint8_t> lm_proof;
        if (hmac_md5_bytes(ntlmv2_hash.data(), ntlmv2_hash.size(),
                           lm_data.data(), lm_data.size(), lm_proof) &&
            lm_proof.size() == 16) {
            lm_response.assign(lm_proof.begin(), lm_proof.end());
            lm_response.insert(lm_response.end(), client_challenge, client_challenge + 8);
        }
    }

    std::vector<uint8_t> user_utf16 = utf16le(user);
    std::vector<uint8_t> domain_utf16 = utf16le(domain);
    std::vector<uint8_t> ws_utf16 = utf16le(workstation);
    std::vector<uint8_t> session_key(16, 0);
    auto will_overflow_u32 = [](size_t v) { return v > static_cast<size_t>(UINT32_MAX); };
    auto will_overflow_u16 = [](size_t v) { return v > 65535; };
    if (will_overflow_u16(domain_utf16.size()) || will_overflow_u16(user_utf16.size()) ||
        will_overflow_u16(ws_utf16.size()) || will_overflow_u16(lm_response.size()) ||
        will_overflow_u16(nt_response.size()) || will_overflow_u16(session_key.size()) ||
        will_overflow_u32(domain_utf16.size()) || will_overflow_u32(user_utf16.size()) ||
        will_overflow_u32(ws_utf16.size()) || will_overflow_u32(lm_response.size()) ||
        will_overflow_u32(nt_response.size()) || will_overflow_u32(session_key.size())) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 rejected oversized field sizes");
        set_err("ntlm_type3: field too large");
        return std::string();
    }

    const uint32_t header_size = 64;
    const uint32_t off_domain = header_size;
    const uint32_t off_user = off_domain + static_cast<uint32_t>(domain_utf16.size());
    const uint32_t off_ws = off_user + static_cast<uint32_t>(user_utf16.size());
    const uint32_t off_lm = off_ws + static_cast<uint32_t>(ws_utf16.size());
    const uint32_t off_nt = off_lm + static_cast<uint32_t>(lm_response.size());
    const uint32_t off_sk = off_nt + static_cast<uint32_t>(nt_response.size());
    const uint32_t total = off_sk + static_cast<uint32_t>(session_key.size());
    if (total < header_size || total > 65535 + 64) {
        diag::log_tagged_fmt("auth_lab", "ntlm_type3 rejected total size %u", total);
        set_err("ntlm_type3: total message too large");
        return std::string();
    }

    std::vector<uint8_t> msg(total, 0);
    std::memcpy(msg.data(), "NTLMSSP\0", 8);
    auto put_u32 = [&](uint32_t offset, uint32_t v) {
        msg[offset]     = static_cast<uint8_t>(v & 0xFF);
        msg[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        msg[offset + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        msg[offset + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    };
    auto put_u16 = [&](uint32_t offset, uint16_t v) {
        msg[offset]     = static_cast<uint8_t>(v & 0xFF);
        msg[offset + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    };
    put_u32(8, 3);
    put_u16(12, static_cast<uint16_t>(lm_response.size()));
    put_u16(14, static_cast<uint16_t>(lm_response.size()));
    put_u32(16, off_lm);
    put_u16(20, static_cast<uint16_t>(nt_response.size()));
    put_u16(22, static_cast<uint16_t>(nt_response.size()));
    put_u32(24, off_nt);
    put_u16(28, static_cast<uint16_t>(domain_utf16.size()));
    put_u16(30, static_cast<uint16_t>(domain_utf16.size()));
    put_u32(32, off_domain);
    put_u16(36, static_cast<uint16_t>(user_utf16.size()));
    put_u16(38, static_cast<uint16_t>(user_utf16.size()));
    put_u32(40, off_user);
    put_u16(44, static_cast<uint16_t>(ws_utf16.size()));
    put_u16(46, static_cast<uint16_t>(ws_utf16.size()));
    put_u32(48, off_ws);
    put_u16(52, static_cast<uint16_t>(session_key.size()));
    put_u16(54, static_cast<uint16_t>(session_key.size()));
    put_u32(56, off_sk);
    put_u32(60, 0x60088207);

    std::memcpy(msg.data() + off_domain, domain_utf16.data(), domain_utf16.size());
    std::memcpy(msg.data() + off_user, user_utf16.data(), user_utf16.size());
    std::memcpy(msg.data() + off_ws, ws_utf16.data(), ws_utf16.size());
    std::memcpy(msg.data() + off_lm, lm_response.data(), lm_response.size());
    std::memcpy(msg.data() + off_nt, nt_response.data(), nt_response.size());
    std::memcpy(msg.data() + off_sk, session_key.data(), session_key.size());

    std::string result = base64_encode_internal(msg.data(), msg.size());
    diag::log_tagged_fmt("auth_lab", "ntlm_type3 ok msg_bytes=%zu b64_len=%zu", msg.size(), result.size());
    return result;
}

std::string bearer_header(const std::string& token)
{
    diag::log_tagged_fmt("auth_lab", "bearer_header entry token_len=%zu", token.size());
    return std::string("Bearer ") + token;
}

oauth2_pkce_t generate_pkce_pair()
{
    diag::log_tagged_fmt("auth_lab", "generate_pkce_pair entry");
    oauth2_pkce_t out;
    auto rb = random_bytes(32);
    out.verifier = base64url_encode_no_pad(rb.data(), rb.size());
    std::vector<uint8_t> sha;
    evp_digest_bytes(EVP_sha256(),
                     reinterpret_cast<const uint8_t*>(out.verifier.data()),
                     out.verifier.size(), sha);
    out.challenge = base64url_encode_no_pad(sha.data(), sha.size());
    diag::log_tagged_fmt("auth_lab", "generate_pkce_pair ok verifier_len=%zu challenge_len=%zu",
        out.verifier.size(), out.challenge.size());
    return out;
}

std::string oauth2_build_auth_url(const std::string& authorize_endpoint,
                                  const std::string& client_id,
                                  const std::string& redirect_uri,
                                  const std::string& scope,
                                  const std::string& state,
                                  const std::string& code_challenge)
{
    const url_log_t endpoint_log = summarize_url_for_log(authorize_endpoint);
    diag::log_tagged_fmt("auth_lab", "oauth2_build_auth_url entry host=%s port=%u path=%s query=%d endpoint_len=%zu client_id_len=%zu scope_len=%zu redirect_uri_len=%zu has_state=%d has_pkce=%d",
        endpoint_log.host.c_str(), static_cast<unsigned>(endpoint_log.port), endpoint_log.path.c_str(),
        (int)endpoint_log.has_query, endpoint_log.length, client_id.size(), scope.size(),
        redirect_uri.size(), (int)!state.empty(), !code_challenge.empty());
    std::string out = authorize_endpoint;
    out += (authorize_endpoint.find('?') == std::string::npos) ? "?" : "&";
    out += "response_type=code";
    out += "&client_id=" + url_encode(client_id);
    out += "&redirect_uri=" + url_encode(redirect_uri);
    if (!scope.empty()) out += "&scope=" + url_encode(scope);
    if (!state.empty()) out += "&state=" + url_encode(state);
    if (!code_challenge.empty()) {
        out += "&code_challenge=" + url_encode(code_challenge);
        out += "&code_challenge_method=S256";
    }
    diag::log_tagged_fmt("auth_lab", "oauth2_build_auth_url ok url_len=%zu", out.size());
    return out;
}

bool oauth2_exchange_code(const std::string& token_endpoint,
                          const std::string& client_id,
                          const std::string& code,
                          const std::string& redirect_uri,
                          const std::string& code_verifier,
                          std::string& access_token,
                          std::string& refresh_token,
                          int& expires_in)
{
    const url_log_t endpoint_log = summarize_url_for_log(token_endpoint);
    diag::log_tagged_fmt("auth_lab", "oauth2_exchange_code entry host=%s port=%u path=%s query=%d endpoint_len=%zu client_id_len=%zu code_len=%zu redirect_uri_len=%zu has_verifier=%d",
        endpoint_log.host.c_str(), static_cast<unsigned>(endpoint_log.port), endpoint_log.path.c_str(),
        (int)endpoint_log.has_query, endpoint_log.length, client_id.size(), code.size(),
        redirect_uri.size(), !code_verifier.empty());
    access_token.clear();
    refresh_token.clear();
    expires_in = 0;
    std::vector<std::pair<std::string, std::string>> form;
    form.emplace_back("grant_type", "authorization_code");
    form.emplace_back("client_id", client_id);
    form.emplace_back("code", code);
    form.emplace_back("redirect_uri", redirect_uri);
    if (!code_verifier.empty()) form.emplace_back("code_verifier", code_verifier);
    std::string body;
    if (!http_post_form(token_endpoint, form, body)) {
        diag::log_tagged_fmt("auth_lab", "oauth2_exchange_code error http_post_failed host=%s path=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str());
        return false;
    }
    diag::log_tagged_fmt("auth_lab", "oauth2_exchange_code http_ok body_len=%zu parsing_response", body.size());
    nlohmann::json j;
    try { j = nlohmann::json::parse(body, nullptr, false); } catch (...) { j = {}; }
    if (j.is_discarded() || !j.is_object()) {
        diag::log_tagged_fmt("auth_lab", "oauth2_exchange_code error response_not_json");
        set_err("token response not JSON");
        return false;
    }
    if (j.contains("access_token") && j["access_token"].is_string()) access_token = j["access_token"].get<std::string>();
    if (j.contains("refresh_token") && j["refresh_token"].is_string()) refresh_token = j["refresh_token"].get<std::string>();
    if (j.contains("expires_in")) {
        if (j["expires_in"].is_number_integer()) expires_in = j["expires_in"].get<int>();
        else if (j["expires_in"].is_number_unsigned()) expires_in = static_cast<int>(j["expires_in"].get<uint64_t>());
    }
    diag::log_tagged_fmt("auth_lab", "oauth2_exchange_code result access_token_len=%zu has_refresh=%d expires_in=%d",
        access_token.size(), !refresh_token.empty(), expires_in);
    return !access_token.empty();
}

bool oauth2_refresh(const std::string& token_endpoint,
                    const std::string& client_id,
                    const std::string& refresh_token,
                    std::string& access_token,
                    int& expires_in)
{
    const url_log_t endpoint_log = summarize_url_for_log(token_endpoint);
    diag::log_tagged_fmt("auth_lab", "oauth2_refresh entry host=%s port=%u path=%s query=%d endpoint_len=%zu client_id_len=%zu refresh_token_len=%zu",
        endpoint_log.host.c_str(), static_cast<unsigned>(endpoint_log.port), endpoint_log.path.c_str(),
        (int)endpoint_log.has_query, endpoint_log.length, client_id.size(), refresh_token.size());
    access_token.clear();
    expires_in = 0;
    std::vector<std::pair<std::string, std::string>> form;
    form.emplace_back("grant_type", "refresh_token");
    form.emplace_back("client_id", client_id);
    form.emplace_back("refresh_token", refresh_token);
    std::string body;
    if (!http_post_form(token_endpoint, form, body)) {
        diag::log_tagged_fmt("auth_lab", "oauth2_refresh error http_post_failed host=%s path=%s",
            endpoint_log.host.c_str(), endpoint_log.path.c_str());
        return false;
    }
    diag::log_tagged_fmt("auth_lab", "oauth2_refresh http_ok body_len=%zu parsing_response", body.size());
    nlohmann::json j;
    try { j = nlohmann::json::parse(body, nullptr, false); } catch (...) { j = {}; }
    if (j.is_discarded() || !j.is_object()) {
        diag::log_tagged_fmt("auth_lab", "oauth2_refresh error response_not_json");
        set_err("refresh response not JSON");
        return false;
    }
    if (j.contains("access_token") && j["access_token"].is_string()) access_token = j["access_token"].get<std::string>();
    if (j.contains("expires_in")) {
        if (j["expires_in"].is_number_integer()) expires_in = j["expires_in"].get<int>();
        else if (j["expires_in"].is_number_unsigned()) expires_in = static_cast<int>(j["expires_in"].get<uint64_t>());
    }
    diag::log_tagged_fmt("auth_lab", "oauth2_refresh result access_token_len=%zu expires_in=%d",
        access_token.size(), expires_in);
    return !access_token.empty();
}

namespace {

std::string pretty_xml(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 64);
    int depth = 0;
    std::string buf;
    auto emit_indent = [&]() {
        if (!out.empty() && out.back() != '\n') out.push_back('\n');
        for (int i = 0; i < depth; ++i) out.append("  ");
    };
    size_t i = 0;
    while (i < in.size()) {
        char c = in[i];
        if (c == '<') {
            if (!buf.empty()) {
                std::string t = trim(buf);
                if (!t.empty()) out.append(t);
                buf.clear();
            }
            const bool is_close = (i + 1 < in.size() && in[i + 1] == '/');
            const bool is_decl = (i + 1 < in.size() && (in[i + 1] == '?' || in[i + 1] == '!'));
            std::string tag = "<";
            ++i;
            while (i < in.size() && in[i] != '>') {
                tag.push_back(in[i]);
                ++i;
            }
            if (i < in.size()) tag.push_back('>');
            ++i;
            const bool is_self_close = (tag.size() >= 2 && tag[tag.size() - 2] == '/');
            if (is_decl) {
                emit_indent();
                out.append(tag);
            } else if (is_close) {
                --depth;
                emit_indent();
                out.append(tag);
            } else if (is_self_close) {
                emit_indent();
                out.append(tag);
            } else {
                emit_indent();
                out.append(tag);
                ++depth;
            }
        } else {
            buf.push_back(c);
            ++i;
        }
    }
    if (!buf.empty()) {
        std::string t = trim(buf);
        if (!t.empty()) out.append(t);
    }
    return out;
}

}

std::string saml_decode_request(const std::string& saml_b64)
{
    diag::log_tagged_fmt("auth_lab", "saml_decode_request entry b64_len=%zu", saml_b64.size());
    std::string urldecoded;
    {
        std::string s_in = saml_b64;
        std::string tmp;
        tmp.reserve(s_in.size());
        for (size_t i = 0; i < s_in.size(); ++i) {
            char c = s_in[i];
            if (c == '+') tmp.push_back('+');
            else if (c == '%' && i + 2 < s_in.size()) {
                int hi = -1, lo = -1;
                char h = s_in[i + 1], l = s_in[i + 2];
                if (h >= '0' && h <= '9') hi = h - '0';
                else if (h >= 'a' && h <= 'f') hi = 10 + h - 'a';
                else if (h >= 'A' && h <= 'F') hi = 10 + h - 'A';
                if (l >= '0' && l <= '9') lo = l - '0';
                else if (l >= 'a' && l <= 'f') lo = 10 + l - 'a';
                else if (l >= 'A' && l <= 'F') lo = 10 + l - 'A';
                if (hi >= 0 && lo >= 0) { tmp.push_back(static_cast<char>((hi << 4) | lo)); i += 2; }
                else tmp.push_back(c);
            } else tmp.push_back(c);
        }
        urldecoded = tmp;
    }
    diag::log_tagged_fmt("auth_lab", "saml_decode_request url_decoded_len=%zu had_url_encoding=%d",
        urldecoded.size(), (int)(urldecoded.size() != saml_b64.size() || saml_b64.find('%') != std::string::npos));
    std::string raw;
    if (!base64_decode_internal(urldecoded, raw)) {
        diag::log_tagged_fmt("auth_lab", "saml_decode_request error b64_decode_failed");
        set_err("saml_decode_request: base64 decode failed");
        return std::string();
    }
    std::string raw_trimmed = trim(raw);
    if (!raw_trimmed.empty() && raw_trimmed.front() == '<') {
        diag::log_tagged_fmt("auth_lab", "saml_decode_request raw_xml_len=%zu formatting_xml", raw.size());
        return pretty_xml(raw);
    }
    diag::log_tagged_fmt("auth_lab", "saml_decode_request b64_ok raw_len=%zu inflating", raw.size());
    std::vector<uint8_t> inflated;
    inflated.reserve(raw.size() * 4 + 32);
    z_stream strm{};
    if (inflateInit2(&strm, -15) != Z_OK) {
        diag::log_tagged_fmt("auth_lab", "saml_decode_request inflate_init_failed raw_len=%zu using_raw_xml", raw.size());
        return pretty_xml(raw);
    }
    strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(raw.data()));
    strm.avail_in = static_cast<uInt>(raw.size());
    uint8_t chunk[8192];
    int ret = Z_OK;
    while (ret == Z_OK) {
        strm.next_out = chunk;
        strm.avail_out = sizeof(chunk);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_BUF_ERROR) {
            inflateEnd(&strm);
            diag::log_tagged_fmt("auth_lab", "saml_decode_request inflate_failed ret=%d raw_len=%zu using_raw_xml", ret, raw.size());
            return pretty_xml(raw);
        }
        const size_t produced = sizeof(chunk) - strm.avail_out;
        inflated.insert(inflated.end(), chunk, chunk + produced);
        if (ret == Z_STREAM_END) break;
        if (produced == 0) {
            inflateEnd(&strm);
            diag::log_tagged_fmt("auth_lab", "saml_decode_request inflate_no_progress ret=%d raw_len=%zu using_raw_xml", ret, raw.size());
            return pretty_xml(raw);
        }
    }
    inflateEnd(&strm);
    if (ret != Z_STREAM_END || inflated.empty()) {
        diag::log_tagged_fmt("auth_lab", "saml_decode_request inflate_incomplete ret=%d inflated_len=%zu using_raw_xml",
            ret, inflated.size());
        return pretty_xml(raw);
    }
    std::string xml(reinterpret_cast<const char*>(inflated.data()), inflated.size());
    diag::log_tagged_fmt("auth_lab", "saml_decode_request inflated_len=%zu formatting_xml", inflated.size());
    return pretty_xml(xml);
}

std::string saml_decode_response(const std::string& saml_b64)
{
    diag::log_tagged_fmt("auth_lab", "saml_decode_response entry b64_len=%zu", saml_b64.size());
    std::string raw;
    if (!base64_decode_internal(saml_b64, raw)) {
        diag::log_tagged_fmt("auth_lab", "saml_decode_response error b64_decode_failed");
        set_err("saml_decode_response: base64 decode failed");
        return std::string();
    }
    diag::log_tagged_fmt("auth_lab", "saml_decode_response ok raw_len=%zu formatting_xml", raw.size());
    return pretty_xml(raw);
}

std::string last_error()
{
    diag::log_tagged_fmt("auth_lab", "last_error queried");
    auto& st = s();
    std::lock_guard<std::mutex> lk(st.err_mtx);
    diag::log_tagged_fmt("auth_lab", "last_error value_len=%zu", st.last_err.size());
    return st.last_err;
}

}
}
}
