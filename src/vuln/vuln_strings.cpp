#include "../aida_pro.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include <bytes.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <strlist.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace strings_engine
{

namespace
{

struct credential_pattern_t
{
    const char*  label;
    const char*  pattern;
    severity_t   severity;
    confidence_t confidence;
    int          cwe_id;
};

inline const std::array<credential_pattern_t, 10>& credential_patterns()
{
    static const std::array<credential_pattern_t, 10> patterns = { {
        {
            "stripe_secret_key",
            R"((?:^|[^A-Za-z0-9_])sk_(?:test|live)?_?[A-Za-z0-9]{24,})",
            severity_t::high,
            confidence_t::likely,
            798,
        },
        {
            "aws_access_key_id",
            R"(AKIA[0-9A-Z]{16})",
            severity_t::critical,
            confidence_t::confirmed,
            798,
        },
        {
            "json_web_token",
            R"(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+)",
            severity_t::medium,
            confidence_t::likely,
            798,
        },
        {
            "kv_secret_assignment",
            R"((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|bearer|client[_-]?secret)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?)",
            severity_t::high,
            confidence_t::likely,
            798,
        },
        {
            "pem_private_key",
            R"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |)PRIVATE KEY-----)",
            severity_t::critical,
            confidence_t::confirmed,
            798,
        },
        {
            "github_personal_access_token",
            R"(ghp_[A-Za-z0-9]{30,})",
            severity_t::critical,
            confidence_t::confirmed,
            798,
        },
        {
            "slack_token",
            R"(xox[abp]-[A-Za-z0-9-]{10,})",
            severity_t::high,
            confidence_t::likely,
            798,
        },
        {
            "google_api_key",
            R"(AIza[0-9A-Za-z_-]{30,})",
            severity_t::high,
            confidence_t::likely,
            798,
        },
        {
            "mongodb_connection_string",
            R"(mongodb(?:\+srv)?://[^\s]+:[^\s@]+@)",
            severity_t::high,
            confidence_t::likely,
            798,
        },
        {
            "sql_connection_string",
            R"((?:postgres|postgresql|mysql)://[^\s]+:[^\s@]+@)",
            severity_t::high,
            confidence_t::likely,
            798,
        },
    } };
    return patterns;
}

struct compiled_pattern_t
{
    const credential_pattern_t* meta = nullptr;
    std::regex                  re;
};

inline const std::vector<compiled_pattern_t>& compiled_credential_patterns()
{
    static const std::vector<compiled_pattern_t> compiled = []() {
        std::vector<compiled_pattern_t> result;
        const auto& patterns = credential_patterns();
        result.reserve(patterns.size());
        for (const auto& p : patterns)
        {
            compiled_pattern_t cp;
            cp.meta = &p;
            try
            {
                cp.re = std::regex(p.pattern, std::regex::icase | std::regex::ECMAScript);
            }
            catch (...)
            {
                continue;
            }
            result.push_back(std::move(cp));
        }
        return result;
    }();
    return compiled;
}

inline std::string preview_value(const std::string& value, std::size_t max_len = 64)
{
    if (value.size() <= max_len)
        return value;
    return value.substr(0, max_len) + "...";
}

inline std::string make_finding_id(const char* prefix, ea_t ea, const std::string& value)
{
    std::ostringstream key_stream;
    key_stream << std::hex << static_cast<std::uint64_t>(ea) << '|' << value;
    std::size_t hashed = std::hash<std::string>{}(key_stream.str());
    std::ostringstream id_stream;
    id_stream << prefix << std::hex << static_cast<std::uint64_t>(ea) << '_' << hashed;
    return id_stream.str();
}

inline double shannon_entropy(const std::string& data)
{
    if (data.empty())
        return 0.0;
    std::array<std::size_t, 256> counts{};
    for (unsigned char c : data)
        counts[c]++;
    double entropy = 0.0;
    const double total = static_cast<double>(data.size());
    for (std::size_t i = 0; i < counts.size(); ++i)
    {
        if (counts[i] == 0)
            continue;
        double p = static_cast<double>(counts[i]) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

inline double byte_entropy(const std::vector<std::uint8_t>& bytes)
{
    if (bytes.empty())
        return 0.0;
    std::array<std::size_t, 256> counts{};
    for (auto b : bytes)
        counts[b]++;
    double entropy = 0.0;
    const double total = static_cast<double>(bytes.size());
    for (std::size_t i = 0; i < counts.size(); ++i)
    {
        if (counts[i] == 0)
            continue;
        double p = static_cast<double>(counts[i]) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

inline cwe_t make_cwe(int id, const char* name)
{
    cwe_t c;
    c.id   = id;
    c.name = name;
    return c;
}

inline std::string string_type_to_label(int type)
{
    if (type == STRTYPE_C)         return "C";
    if (type == STRTYPE_C_16)      return "C16";
    if (type == STRTYPE_C_32)      return "C32";
    if (type == STRTYPE_PASCAL)    return "Pascal";
    if (type == STRTYPE_PASCAL_16) return "Pascal16";
    if (type == STRTYPE_LEN2)      return "Len2";
    if (type == STRTYPE_LEN2_16)   return "Len2-16";
    if (type == STRTYPE_LEN4)      return "Len4";
    if (type == STRTYPE_LEN4_16)   return "Len4-16";
    return std::to_string(type);
}

inline std::string make_address_string(ea_t ea)
{
    return agent_tools::helpers::format_address(ea);
}

inline bool is_segment_read_only(ea_t ea)
{
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return false;
    if (seg->type == SEG_CODE)
        return true;
    if ((seg->perm != 0) && ((seg->perm & SEGPERM_WRITE) == 0))
        return true;
    qstring sname;
    if (get_segm_name(&sname, seg) > 0 && !sname.empty())
    {
        std::string s(sname.c_str());
        std::string lower;
        lower.resize(s.size());
        std::transform(s.begin(), s.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find(".rdata") != std::string::npos ||
            lower.find("__const") != std::string::npos ||
            lower.find("rodata")  != std::string::npos ||
            lower.find(".text")   != std::string::npos)
            return true;
    }
    return false;
}

inline bool read_byte_array(ea_t ea, std::size_t length, std::vector<std::uint8_t>& out)
{
    out.clear();
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i)
    {
        ea_t cur = ea + static_cast<ea_t>(i);
        if (!is_loaded(cur))
            return false;
        out.push_back(static_cast<std::uint8_t>(get_byte(cur)));
    }
    return true;
}

inline bool string_is_token_alphabet(const std::string& s)
{
    if (s.size() < 16 || s.size() > 256)
        return false;
    static const std::regex token_re(R"(^[A-Za-z0-9+/=_-]{16,}$)");
    return std::regex_match(s, token_re);
}

inline std::string clean_string_for_match(const qstring& src)
{
    std::string out;
    out.reserve(src.length());
    for (std::size_t i = 0; i < src.length(); ++i)
    {
        char c = src[static_cast<int>(i)];
        if (c == '\0')
            break;
        out.push_back(c);
    }
    return out;
}

inline severity_t severity_for_weak_hash(const std::string& callee)
{
    std::string lower(callee);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.find("md4") != std::string::npos ||
        lower.find("md5") != std::string::npos)
        return severity_t::high;
    if (lower.find("sha1") != std::string::npos)
        return severity_t::medium;
    return severity_t::medium;
}

inline severity_t severity_for_weak_cipher(const std::string& callee)
{
    std::string lower(callee);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.find("rc4") != std::string::npos ||
        lower.find("rc2") != std::string::npos ||
        lower.find("des") != std::string::npos)
        return severity_t::high;
    return severity_t::medium;
}

inline bool is_likely_iv_setup_call(const std::string& name)
{
    std::string lower(name);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.find("set_iv") != std::string::npos)
        return true;
    if (lower.find("set_initial_vector") != std::string::npos)
        return true;
    if (lower.find("setiv") != std::string::npos)
        return true;
    if (lower.find("evp_encryptinit_ex") != std::string::npos)
        return true;
    if (lower.find("evp_decryptinit_ex") != std::string::npos)
        return true;
    if (lower.find("cbc_encrypt") != std::string::npos)
        return true;
    if (lower.find("ctr_encrypt") != std::string::npos)
        return true;
    if (lower.find("gcm_init") != std::string::npos)
        return true;
    if (lower.find("ccm_init") != std::string::npos)
        return true;
    return false;
}

struct nearby_calls_visitor_t : public ctree_visitor_t
{
    cfunc_t* cfunc;
    std::vector<std::pair<ea_t, std::string>> calls;
    std::vector<std::pair<ea_t, std::vector<ea_t>>> call_obj_args;

    nearby_calls_visitor_t(cfunc_t* cf)
        : ctree_visitor_t(CV_FAST), cfunc(cf) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr == nullptr || expr->op != cot_call)
            return 0;

        std::string callee_name;
        if (expr->x != nullptr && expr->x->op == cot_obj)
        {
            qstring nm;
            if (get_name(&nm, expr->x->obj_ea) > 0 && !nm.empty())
                callee_name = nm.c_str();
        }
        else if (expr->x != nullptr && expr->x->op == cot_helper && expr->x->helper != nullptr)
        {
            callee_name = expr->x->helper;
        }

        std::vector<ea_t> obj_args;
        if (expr->a != nullptr)
        {
            for (std::size_t i = 0; i < expr->a->size(); ++i)
            {
                const carg_t& arg = (*expr->a)[i];
                if (arg.op == cot_obj)
                    obj_args.push_back(arg.obj_ea);
                else if (arg.op == cot_ref && arg.x != nullptr && arg.x->op == cot_obj)
                    obj_args.push_back(arg.x->obj_ea);
                else if (arg.op == cot_cast && arg.x != nullptr && arg.x->op == cot_obj)
                    obj_args.push_back(arg.x->obj_ea);
                else if (arg.op == cot_cast && arg.x != nullptr && arg.x->op == cot_ref &&
                         arg.x->x != nullptr && arg.x->x->op == cot_obj)
                    obj_args.push_back(arg.x->x->obj_ea);
            }
        }

        calls.emplace_back(expr->ea, callee_name);
        call_obj_args.emplace_back(expr->ea, std::move(obj_args));
        return 0;
    }
};

struct caller_analysis_t
{
    std::vector<std::pair<ea_t, std::string>>         calls;
    std::vector<std::pair<ea_t, std::vector<ea_t>>>   call_obj_args;
    bool                                              decompiled = false;
};

inline caller_analysis_t analyze_caller(ea_t func_ea)
{
    caller_analysis_t analysis;
    if (func_ea == BADADDR)
        return analysis;

    if (!init_hexrays_plugin())
        return analysis;

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return analysis;

    if (!ida_utils::is_safely_decompilable(pfn))
        return analysis;

    try
    {
        cfuncptr_t cfunc = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        if (!cfunc)
            return analysis;

        cfunc_t* cf = cfunc;
        nearby_calls_visitor_t visitor(cf);
        visitor.apply_to(&cfunc->body, nullptr);
        analysis.calls         = std::move(visitor.calls);
        analysis.call_obj_args = std::move(visitor.call_obj_args);
        analysis.decompiled    = true;
    }
    catch (const vd_failure_t&)
    {
        return analysis;
    }
    catch (...)
    {
        return analysis;
    }

    return analysis;
}

inline bool detect_ecb_indicator(const caller_analysis_t& analysis,
                                 ea_t                     anchor_call_ea)
{
    if (!analysis.decompiled)
        return false;
    bool has_iv = false;
    bool has_anchor = false;
    for (const auto& kv : analysis.calls)
    {
        if (kv.first == anchor_call_ea)
            has_anchor = true;
        if (is_likely_iv_setup_call(kv.second))
            has_iv = true;
    }
    if (!has_anchor)
        return false;
    return !has_iv;
}

inline std::vector<std::vector<std::uint8_t>> extract_hardcoded_keys(
    const caller_analysis_t& analysis,
    ea_t                     anchor_call_ea)
{
    std::vector<std::vector<std::uint8_t>> keys;
    if (!analysis.decompiled)
        return keys;

    for (const auto& kv : analysis.call_obj_args)
    {
        if (kv.first != anchor_call_ea)
            continue;
        for (ea_t arg_ea : kv.second)
        {
            if (arg_ea == BADADDR)
                continue;
            if (!is_loaded(arg_ea))
                continue;
            if (!is_segment_read_only(arg_ea))
                continue;
            for (std::size_t key_size : { 16u, 24u, 32u, 8u })
            {
                std::vector<std::uint8_t> bytes;
                if (!read_byte_array(arg_ea, key_size, bytes))
                    continue;
                keys.push_back(std::move(bytes));
                break;
            }
        }
    }
    return keys;
}

inline std::string format_byte_preview(const std::vector<std::uint8_t>& bytes,
                                       std::size_t                      max_bytes = 32)
{
    std::ostringstream ss;
    ss << std::hex;
    std::size_t limit = std::min(bytes.size(), max_bytes);
    for (std::size_t i = 0; i < limit; ++i)
    {
        if (i > 0)
            ss << ' ';
        unsigned int v = bytes[i];
        if (v < 0x10) ss << '0';
        ss << v;
    }
    if (bytes.size() > limit)
        ss << " ...";
    return ss.str();
}

inline bool callee_is_weak_hash(const std::string& callee)
{
    for (const auto& entry : sig::WEAK_HASH_FUNCS)
    {
        if (callee == std::string(entry.name))
            return true;
    }
    return false;
}

inline bool callee_is_weak_cipher(const std::string& callee)
{
    for (const auto& entry : sig::WEAK_CIPHER_FUNCS)
    {
        if (callee == std::string(entry.name))
            return true;
    }
    return false;
}

inline std::vector<std::string> build_weak_crypto_targets()
{
    std::vector<std::string> names;
    names.reserve(std::size(sig::WEAK_HASH_FUNCS) + std::size(sig::WEAK_CIPHER_FUNCS));
    for (const auto& entry : sig::WEAK_HASH_FUNCS)
        names.emplace_back(entry.name);
    for (const auto& entry : sig::WEAK_CIPHER_FUNCS)
        names.emplace_back(entry.name);
    return names;
}

}

std::vector<vuln_finding_t> find_hardcoded_credentials(int max_findings)
{
    std::vector<vuln_finding_t> findings;
    if (max_findings <= 0)
        return findings;

    std::size_t total = get_strlist_qty();
    if (total == 0)
    {
        build_strlist();
        total = get_strlist_qty();
    }
    if (total == 0)
        return findings;

    const auto& patterns = compiled_credential_patterns();
    if (patterns.empty())
        return findings;

    static const std::regex named_secret_re(
        R"((?:key|secret|token|api|pwd|password|cred|pass|salt|priv|hmac|cert|pem|seed))",
        std::regex::icase);

    std::unordered_set<std::uint64_t> matched_eas;

    for (std::size_t i = 0; i < total; ++i)
    {
        if (static_cast<int>(findings.size()) >= max_findings)
            break;

        string_info_t si;
        if (!get_strlist_item(&si, i))
            continue;

        qstring raw;
        if (get_strlit_contents(&raw, si.ea, si.length, si.type) <= 0)
            continue;

        std::string str = clean_string_for_match(raw);
        if (str.empty())
            continue;

        bool matched = false;
        for (const auto& cp : patterns)
        {
            if (cp.meta == nullptr)
                continue;
            std::smatch sm;
            if (!std::regex_search(str, sm, cp.re))
                continue;

            vuln_finding_t finding;
            finding.id          = make_finding_id("HARDCODED_CRED_", si.ea, str);
            finding.severity    = cp.meta->severity;
            finding.confidence  = cp.meta->confidence;
            finding.primary_ea  = si.ea;
            finding.cwes.push_back(make_cwe(cp.meta->cwe_id, "Use of Hard-coded Credentials"));
            finding.title       = std::string("Hardcoded credential detected: ") + cp.meta->label;
            finding.rationale   = std::string("String literal at ") + make_address_string(si.ea) +
                                  " matches known credential pattern '" + cp.meta->label +
                                  "'. Hardcoded credentials in shipped binaries are recoverable via "
                                  "static analysis and constitute a Use of Hard-coded Credentials weakness (CWE-798).";
            finding.evidence = nlohmann::json{
                {"matched_pattern", cp.meta->label},
                {"value_preview",   preview_value(str, 64)},
                {"string_address",  make_address_string(si.ea)},
                {"string_type",     si.type},
                {"string_type_label", string_type_to_label(si.type)},
                {"string_length",   si.length},
                {"detection",       "regex"},
            };
            findings.push_back(std::move(finding));
            matched_eas.insert(static_cast<std::uint64_t>(si.ea));
            matched = true;
            break;
        }

        if (matched)
            continue;

        if (str.size() < 16 || str.size() > 256)
            continue;

        if (!string_is_token_alphabet(str))
            continue;

        qstring qname;
        if (get_name(&qname, si.ea) <= 0 || qname.empty())
            continue;

        std::string global_name = qname.c_str();
        if (!std::regex_search(global_name, named_secret_re))
            continue;

        double entropy = shannon_entropy(str);
        if (entropy < 4.5)
            continue;

        if (matched_eas.count(static_cast<std::uint64_t>(si.ea)) != 0)
            continue;

        vuln_finding_t finding;
        finding.id         = make_finding_id("HARDCODED_CRED_HENT_", si.ea, str);
        finding.severity   = severity_t::medium;
        finding.confidence = confidence_t::plausible;
        finding.primary_ea = si.ea;
        finding.cwes.push_back(make_cwe(798, "Use of Hard-coded Credentials"));
        finding.title      = std::string("High-entropy named secret literal: ") + global_name;
        finding.rationale  = std::string("Global symbol '") + global_name +
                             "' at " + make_address_string(si.ea) +
                             " holds a high-entropy string (" + std::to_string(entropy) +
                             " bits/char) over the base64/base32/hex alphabet. "
                             "The symbol name suggests a secret/credential role; embedding such "
                             "values inline ships them with the binary (CWE-798).";
        finding.evidence = nlohmann::json{
            {"matched_pattern",   "high_entropy_named_global"},
            {"value_preview",     preview_value(str, 64)},
            {"string_address",    make_address_string(si.ea)},
            {"string_type",       si.type},
            {"string_type_label", string_type_to_label(si.type)},
            {"string_length",     si.length},
            {"global_name",       global_name},
            {"shannon_entropy",   entropy},
            {"detection",         "entropy"},
        };
        findings.push_back(std::move(finding));
        matched_eas.insert(static_cast<std::uint64_t>(si.ea));
    }

    return findings;
}

std::vector<vuln_finding_t> find_weak_crypto(int max_findings)
{
    std::vector<vuln_finding_t> findings;
    if (max_findings <= 0)
        return findings;

    std::vector<std::string> targets = build_weak_crypto_targets();
    if (targets.empty())
        return findings;

    std::vector<callsite_t> sites = aida::vuln::callsites::all_calls_to(targets);
    if (sites.empty())
        return findings;

    std::unordered_set<std::uint64_t> emitted_pass_a_ea;

    for (const auto& cs : sites)
    {
        if (static_cast<int>(findings.size()) >= max_findings)
            break;
        if (cs.call_ea == BADADDR)
            continue;
        if (emitted_pass_a_ea.count(static_cast<std::uint64_t>(cs.call_ea)) != 0)
            continue;

        const std::string& callee = cs.callee_name;
        if (callee.empty())
            continue;

        bool is_hash   = callee_is_weak_hash(callee);
        bool is_cipher = callee_is_weak_cipher(callee);
        if (!is_hash && !is_cipher)
            continue;

        vuln_finding_t finding;
        finding.id         = make_finding_id("WEAK_CRYPTO_", cs.call_ea, callee);
        finding.confidence = confidence_t::likely;
        finding.primary_ea = cs.call_ea;
        if (cs.func_ea != BADADDR)
            finding.related_eas.push_back(cs.func_ea);

        if (is_hash)
        {
            finding.severity = severity_for_weak_hash(callee);
            finding.cwes.push_back(make_cwe(328, "Use of Weak Hash"));
            finding.title    = std::string("Use of weak hash primitive: ") + callee;
            finding.rationale = std::string("Direct call to weak/broken hash function '") + callee +
                                "' from " + make_address_string(cs.func_ea) +
                                " at call site " + make_address_string(cs.call_ea) +
                                ". MD4/MD5/SHA-1 are collision-vulnerable and unsuitable "
                                "for any security-relevant context (signatures, integrity, password storage). "
                                "Migrate to SHA-256/SHA-3/BLAKE2 or HMAC-equivalents (CWE-328).";
        }
        else
        {
            finding.severity = severity_for_weak_cipher(callee);
            finding.cwes.push_back(make_cwe(327, "Use of a Broken or Risky Cryptographic Algorithm"));
            finding.title    = std::string("Use of broken/risky cipher primitive: ") + callee;
            finding.rationale = std::string("Direct call to broken cipher '") + callee +
                                "' from " + make_address_string(cs.func_ea) +
                                " at call site " + make_address_string(cs.call_ea) +
                                ". RC4/RC2/DES/3DES are deprecated and considered broken for "
                                "confidentiality. Replace with AES-GCM or ChaCha20-Poly1305 (CWE-327).";
        }

        nlohmann::json arg_json = nlohmann::json::array();
        for (std::size_t i = 0; i < cs.arg_summaries.size(); ++i)
        {
            nlohmann::json a;
            a["summary"]    = cs.arg_summaries[i];
            a["is_literal"] = i < cs.arg_is_literal.size() ? cs.arg_is_literal[i] : false;
            arg_json.push_back(std::move(a));
        }

        finding.evidence = nlohmann::json{
            {"callee",       callee},
            {"call_ea",      make_address_string(cs.call_ea)},
            {"caller_ea",    make_address_string(cs.func_ea)},
            {"args",         arg_json},
            {"category",     is_hash ? "weak_hash" : "broken_cipher"},
            {"detection",    "xref_to_known_primitive"},
        };

        findings.push_back(std::move(finding));
        emitted_pass_a_ea.insert(static_cast<std::uint64_t>(cs.call_ea));
    }

    std::unordered_set<std::uint64_t> ecb_emitted;
    std::unordered_set<std::uint64_t> hardkey_emitted;

    for (const auto& cs : sites)
    {
        if (static_cast<int>(findings.size()) >= max_findings)
            break;
        if (cs.call_ea == BADADDR || cs.func_ea == BADADDR)
            continue;
        if (!callee_is_weak_cipher(cs.callee_name))
            continue;

        caller_analysis_t analysis = analyze_caller(cs.func_ea);
        if (!analysis.decompiled)
            continue;

        if (ecb_emitted.count(static_cast<std::uint64_t>(cs.call_ea)) == 0 &&
            detect_ecb_indicator(analysis, cs.call_ea))
        {
            vuln_finding_t finding;
            finding.id         = make_finding_id("WEAK_CRYPTO_ECB_", cs.call_ea, cs.callee_name);
            finding.severity   = severity_t::medium;
            finding.confidence = confidence_t::plausible;
            finding.primary_ea = cs.call_ea;
            finding.related_eas.push_back(cs.func_ea);
            finding.cwes.push_back(make_cwe(327, "Use of a Broken or Risky Cryptographic Algorithm"));
            finding.title      = std::string("Likely ECB-mode block cipher usage near ") + cs.callee_name;
            finding.rationale  = std::string("Caller ") + make_address_string(cs.func_ea) +
                                 " invokes the cipher primitive '" + cs.callee_name +
                                 "' at " + make_address_string(cs.call_ea) +
                                 " without any IV/nonce-setup call (set_iv / set_initial_vector / "
                                 "EVP_*Init_ex / *_cbc_encrypt / *_ctr_encrypt / *_gcm_init / *_ccm_init) "
                                 "in the same decompiled function. ECB leaks plaintext patterns and "
                                 "must not be used for confidentiality (CWE-327).";
            finding.evidence = nlohmann::json{
                {"callee",      cs.callee_name},
                {"call_ea",     make_address_string(cs.call_ea)},
                {"caller_ea",   make_address_string(cs.func_ea)},
                {"detection",   "absence_of_iv_setup"},
                {"category",    "ecb_indicator"},
            };
            findings.push_back(std::move(finding));
            ecb_emitted.insert(static_cast<std::uint64_t>(cs.call_ea));
            if (static_cast<int>(findings.size()) >= max_findings)
                break;
        }

        if (hardkey_emitted.count(static_cast<std::uint64_t>(cs.call_ea)) != 0)
            continue;

        std::vector<std::vector<std::uint8_t>> keys = extract_hardcoded_keys(analysis, cs.call_ea);
        if (keys.empty())
            continue;

        for (const auto& key : keys)
        {
            if (static_cast<int>(findings.size()) >= max_findings)
                break;
            if (key.size() != 16 && key.size() != 24 && key.size() != 32 && key.size() != 8)
                continue;

            double key_entropy = byte_entropy(key);

            vuln_finding_t finding;
            finding.id         = make_finding_id("HARDCODED_CRYPTO_KEY_", cs.call_ea, cs.callee_name);
            finding.severity   = severity_t::critical;
            finding.confidence = key_entropy < 3.0 ? confidence_t::plausible : confidence_t::likely;
            finding.primary_ea = cs.call_ea;
            finding.related_eas.push_back(cs.func_ea);
            finding.cwes.push_back(make_cwe(321, "Use of Hard-coded Cryptographic Key"));
            finding.title      = std::string("Hardcoded cryptographic key passed to ") + cs.callee_name;
            finding.rationale  = std::string("Call to '") + cs.callee_name + "' at " +
                                 make_address_string(cs.call_ea) +
                                 " uses an argument referencing a read-only global of " +
                                 std::to_string(key.size()) +
                                 " bytes; this matches a fixed cryptographic key embedded in the binary "
                                 "(entropy=" + std::to_string(key_entropy) +
                                 " bits/byte). Hardcoded keys allow trivial recovery from the shipped "
                                 "binary and break the entire confidentiality model (CWE-321).";
            finding.evidence = nlohmann::json{
                {"callee",         cs.callee_name},
                {"call_ea",        make_address_string(cs.call_ea)},
                {"caller_ea",      make_address_string(cs.func_ea)},
                {"key_length",     key.size()},
                {"key_entropy",    key_entropy},
                {"key_bytes_hex",  format_byte_preview(key, 32)},
                {"detection",      "global_read_only_key_arg"},
                {"category",       "hardcoded_crypto_key"},
            };
            findings.push_back(std::move(finding));
            hardkey_emitted.insert(static_cast<std::uint64_t>(cs.call_ea));
            break;
        }
    }

    return findings;
}

namespace tools
{

namespace
{

inline int extract_limit(const nlohmann::json& params, int default_limit)
{
    if (!params.is_object())
        return default_limit;
    auto it = params.find("limit");
    if (it == params.end() || it->is_null())
        return default_limit;
    try
    {
        if (it->is_number_integer())
        {
            const std::int64_t value = it->get<std::int64_t>();
            if (value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return default_limit;
            return static_cast<int>(value);
        }
        if (it->is_number_unsigned())
        {
            const std::uint64_t value = it->get<std::uint64_t>();
            if (value > static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                return default_limit;
            return static_cast<int>(value);
        }
        if (it->is_number())
        {
            const double value = it->get<double>();
            if (!std::isfinite(value) || value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return default_limit;
            return static_cast<int>(value);
        }
        if (it->is_string())
        {
            const std::string s = it->get<std::string>();
            if (s.empty())
                return default_limit;
            return std::stoi(s);
        }
    }
    catch (...)
    {
        return default_limit;
    }
    return default_limit;
}

inline nlohmann::json findings_to_json(const std::vector<vuln_finding_t>& findings)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

}

agent_tools::tool_result_t handle_find_hardcoded_credentials(const nlohmann::json& params)
{
    int limit = extract_limit(params, 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    std::vector<vuln_finding_t> findings = find_hardcoded_credentials(limit);

    nlohmann::json data;
    data["findings"]      = findings_to_json(findings);
    data["finding_count"] = findings.size();
    data["limit"]         = limit;
    data["primary_cwe"]   = 798;

    std::string msg = std::string("Hardcoded-credential scan: ") +
                      std::to_string(findings.size()) +
                      std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg, data);
}

agent_tools::tool_result_t handle_find_weak_crypto(const nlohmann::json& params)
{
    int limit = extract_limit(params, 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    std::vector<vuln_finding_t> findings = find_weak_crypto(limit);

    nlohmann::json data;
    data["findings"]      = findings_to_json(findings);
    data["finding_count"] = findings.size();
    data["limit"]         = limit;
    data["primary_cwe"]   = 327;

    std::string msg = std::string("Weak-crypto scan: ") +
                      std::to_string(findings.size()) +
                      std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg, data);
}

void register_tier1_string_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        std::string("find_hardcoded_credentials"),
        std::string("vuln"),
        std::string("Scan the loaded binary's string list for hardcoded credentials, API keys, "
               "tokens, PEM private keys, JWTs, and connection strings with embedded passwords. "
               "Combines a known-pattern regex set (CWE-798) with a high-entropy heuristic on "
               "named globals whose symbol matches secret-shaped naming."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 256, max 4096)"), false},
        },
        handle_find_hardcoded_credentials,
        true,
    });

    registry.register_tool({
        std::string("find_weak_crypto"),
        std::string("vuln"),
        std::string("Locate uses of broken or risky cryptographic primitives (MD4/MD5/SHA-1, "
               "RC4/RC2/DES/3DES) by xref to known function names, plus heuristic detection "
               "of likely ECB-mode usage and hardcoded crypto keys (CWE-321/327/328) "
               "in the caller's decompiled body."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 256, max 4096)"), false},
        },
        handle_find_weak_crypto,
        true,
    });
}

}

}
}
}
