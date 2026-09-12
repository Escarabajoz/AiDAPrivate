#include "../aida_pro.hpp"

#include "verification_engine.hpp"

#include "microcode_engine.hpp"
#include "smt_solver.hpp"
#include "symbolic_engine.hpp"
#include "vuln_signatures.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <funcs.hpp>
#include <hexrays.hpp>
#include <nalt.hpp>
#include <netnode.hpp>
#include <tryblks.hpp>

namespace aida
{
namespace vuln
{
namespace verify
{

namespace
{

constexpr int    k_default_bv_width = 64;
constexpr size_t k_max_inputs_in_summary = 16;
constexpr const char* k_verify_ledger_node = "$ AiDA.verify.ledger";
constexpr nodeidx_t k_verify_ledger_blob_start = 1;
constexpr uchar k_verify_ledger_blob_tag = 'V';
constexpr size_t k_verify_ledger_page_size = 512 * 1024;

std::atomic<bool> g_verify_cancel{false};
std::atomic<int>  g_verify_in_flight{0};

uint64_t now_ms()
{
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::string ea_to_hex(ea_t ea)
{
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<uint64_t>(ea);
    return ss.str();
}

bool should_cancel()
{
    return g_verify_cancel.load(std::memory_order_relaxed);
}

struct inflight_guard_t
{
    inflight_guard_t()
    {
        int prev = g_verify_in_flight.fetch_add(1, std::memory_order_relaxed);
        if (prev == 0)
            g_verify_cancel.store(false, std::memory_order_relaxed);
    }
    ~inflight_guard_t()
    {
        g_verify_in_flight.fetch_sub(1, std::memory_order_relaxed);
    }
};

std::vector<ea_t> collect_cited_eas(const std::vector<symbolic::path_constraint_t>& constraints)
{
    std::vector<ea_t> out;
    std::set<ea_t> seen;
    for (const auto& c : constraints)
    {
        if (c.branch_ea == BADADDR)
            continue;
        if (seen.insert(c.branch_ea).second)
            out.push_back(c.branch_ea);
    }
    return out;
}

bool has_seh_path(const std::vector<symbolic::path_constraint_t>& constraints)
{
    for (const auto& c : constraints)
    {
        if (c.via_seh_handler)
            return true;
    }
    return false;
}

std::string binary_md5_hex()
{
    uchar md5[16] = {};
    if (!retrieve_input_file_md5(md5))
        return "unknown";
    char buf[33] = {};
    for (int i = 0; i < 16; ++i)
        ::qsnprintf(buf + (i * 2), 3, "%02x", md5[i]);
    return std::string(buf);
}

std::string cache_key_string(const cache_key_t& k)
{
    std::ostringstream ss;
    ss << std::hex << static_cast<uint64_t>(k.func_ea) << ":"
       << static_cast<uint64_t>(k.source_ea) << ":"
       << static_cast<uint64_t>(k.sink_ea) << ":"
       << std::dec << k.sig_db_rev;
    return ss.str();
}

verdict_t smt_result_to_verdict(const smt::solve_result_t& r)
{
    if (r.result == smt::result_t::sat)
        return verdict_t::confirmed;
    if (r.result == smt::result_t::unsat)
        return verdict_t::refuted;
    if (r.reason.find("timeout") != std::string::npos || r.reason.find("canceled") != std::string::npos)
        return verdict_t::timeout;
    return verdict_t::inconclusive;
}

const std::unordered_set<std::string>& smt_keyword_set()
{
    static const std::unordered_set<std::string> keywords = {
        "_", "as", "let", "forall", "exists", "match", "par",
        "and", "or", "xor", "not", "ite", "implies", "iff",
        "true", "false", "BitVec", "Bool", "Int", "Real", "Array",
        "bvadd", "bvsub", "bvmul", "bvudiv", "bvurem", "bvsdiv",
        "bvsrem", "bvsmod", "bvshl", "bvlshr", "bvashr",
        "bvand", "bvor", "bvxor", "bvnand", "bvnor", "bvxnor",
        "bvnot", "bvneg", "bvcomp",
        "bvult", "bvule", "bvugt", "bvuge",
        "bvslt", "bvsle", "bvsgt", "bvsge",
        "concat", "extract", "zero_extend", "sign_extend",
        "rotate_left", "rotate_right", "repeat",
        "select", "store",
        "distinct", "=", "=>",
        "assert", "check-sat", "get-model", "get-value",
        "declare-fun", "declare-const", "define-fun", "set-logic",
        "set-option", "push", "pop", "reset", "exit",
        "to_int", "to_real", "is_int"
    };
    return keywords;
}

bool is_identifier_start(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 'A' && uc <= 'Z') ||
           (uc >= 'a' && uc <= 'z') ||
           uc == '_';
}

bool is_identifier_continue(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return is_identifier_start(c) ||
           (uc >= '0' && uc <= '9') ||
           uc == '!' || uc == '.' || uc == '@' || uc == '$';
}

bool is_numeric_token(const std::string& tok)
{
    if (tok.empty())
        return false;
    for (char c : tok)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!(uc >= '0' && uc <= '9'))
            return false;
    }
    return true;
}

int detect_width_from_text(const std::string& text, const std::string& var)
{
    int detected = 0;
    const std::string ext_prefix = "((_ extract ";
    size_t pos = 0;
    while ((pos = text.find(ext_prefix, pos)) != std::string::npos)
    {
        size_t cursor = pos + ext_prefix.size();
        size_t end_high = cursor;
        while (end_high < text.size() && std::isdigit(static_cast<unsigned char>(text[end_high])))
            ++end_high;
        if (end_high == cursor || end_high >= text.size() || text[end_high] != ' ')
        {
            ++pos;
            continue;
        }
        int high = std::atoi(text.substr(cursor, end_high - cursor).c_str());
        size_t low_start = end_high + 1;
        size_t low_end = low_start;
        while (low_end < text.size() && std::isdigit(static_cast<unsigned char>(text[low_end])))
            ++low_end;
        if (low_end == low_start || low_end >= text.size() || text[low_end] != ')')
        {
            ++pos;
            continue;
        }
        size_t inner_start = text.find(' ', low_end + 1);
        if (inner_start == std::string::npos)
        {
            ++pos;
            continue;
        }
        size_t name_start = inner_start + 1;
        while (name_start < text.size() && std::isspace(static_cast<unsigned char>(text[name_start])))
            ++name_start;
        if (name_start + var.size() <= text.size() &&
            text.compare(name_start, var.size(), var) == 0)
        {
            char after = name_start + var.size() < text.size() ? text[name_start + var.size()] : ')';
            if (!is_identifier_continue(after))
            {
                int width = high + 1;
                if (width > detected)
                    detected = width;
            }
        }
        pos = end_high;
    }
    return detected;
}

std::vector<std::string> tokenize_identifiers(const std::string& text)
{
    std::vector<std::string> out;
    out.reserve(16);
    std::set<std::string> seen;
    const auto& keywords = smt_keyword_set();
    const size_t n = text.size();
    for (size_t i = 0; i < n;)
    {
        char c = text[i];
        if (c == ';')
        {
            while (i < n && text[i] != '\n')
                ++i;
            continue;
        }
        if (c == '|')
        {
            size_t end = text.find('|', i + 1);
            if (end == std::string::npos)
                break;
            std::string name = text.substr(i + 1, end - i - 1);
            if (!name.empty() && seen.insert(name).second)
                out.push_back(std::move(name));
            i = end + 1;
            continue;
        }
        if (is_identifier_start(c))
        {
            size_t start = i;
            ++i;
            while (i < n && is_identifier_continue(text[i]))
                ++i;
            std::string tok = text.substr(start, i - start);
            if (keywords.find(tok) != keywords.end())
                continue;
            if (is_numeric_token(tok))
                continue;
            if (tok.size() >= 2 && tok[0] == 'b' && tok[1] == 'v')
            {
                bool all_digits_after = tok.size() > 2;
                for (size_t k = 2; k < tok.size() && all_digits_after; ++k)
                {
                    unsigned char uc = static_cast<unsigned char>(tok[k]);
                    if (!(uc >= '0' && uc <= '9'))
                        all_digits_after = false;
                }
                if (all_digits_after)
                    continue;
            }
            if (seen.insert(tok).second)
                out.push_back(std::move(tok));
            continue;
        }
        ++i;
    }
    return out;
}

bool name_looks_like_input(const std::string& name)
{
    if (name.size() >= 4 && name.compare(0, 4, "lvar") == 0)
        return true;
    if (name.size() >= 5 && name.compare(0, 5, "param") == 0)
        return true;
    if (name.size() >= 5 && name.compare(0, 5, "input") == 0)
        return true;
    if (name.size() >= 3 && name.compare(0, 3, "arg") == 0)
        return true;
    if (name.size() >= 3 && name.compare(0, 3, "reg") == 0)
        return true;
    if (name.size() >= 3 && name.compare(0, 3, "stk") == 0)
        return true;
    return false;
}

std::string format_hex64(uint64_t v)
{
    char buf[24];
    ::qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

void append_concrete_bytes_le(std::vector<uint8_t>& dst, uint64_t value, int width_bits)
{
    int width_bytes = width_bits / 8;
    if (width_bytes <= 0)
        width_bytes = 1;
    if (width_bytes > 8)
        width_bytes = 8;
    for (int b = 0; b < width_bytes; ++b)
    {
        dst.push_back(static_cast<uint8_t>((value >> (b * 8)) & 0xFFu));
    }
}

std::string ensure_assertion(const std::string& predicate, bool negate)
{
    std::string trimmed;
    trimmed.reserve(predicate.size());
    size_t start = 0;
    while (start < predicate.size() && std::isspace(static_cast<unsigned char>(predicate[start])))
        ++start;
    size_t end = predicate.size();
    while (end > start && std::isspace(static_cast<unsigned char>(predicate[end - 1])))
        --end;
    trimmed.assign(predicate, start, end - start);
    if (trimmed.empty())
        trimmed = "true";
    std::ostringstream ss;
    ss << "(assert ";
    if (negate)
        ss << "(not " << trimmed << ")";
    else
        ss << trimmed;
    ss << ")";
    return ss.str();
}

bool emit_declarations(smt::SmtContext& smt,
                       const std::vector<symbolic::path_constraint_t>& constraints,
                       std::unordered_map<std::string, int>& declared_widths)
{
    if (!smt.is_available())
        return false;
    std::unordered_map<std::string, int> wanted;
    for (const auto& c : constraints)
    {
        const std::string& text = c.predicate_smt2;
        auto names = tokenize_identifiers(text);
        for (const auto& n : names)
        {
            int w = detect_width_from_text(text, n);
            if (w <= 0)
                w = k_default_bv_width;
            auto it = wanted.find(n);
            if (it == wanted.end() || w > it->second)
                wanted[n] = w;
        }
    }
    for (const auto& kv : wanted)
    {
        if (kv.second <= 0 || kv.second > 4096)
            continue;
        if (!smt.declare_bv(kv.first, kv.second))
        {
            continue;
        }
        declared_widths[kv.first] = kv.second;
    }
    return true;
}

bool assert_constraints(smt::SmtContext& smt,
                        const std::vector<symbolic::path_constraint_t>& constraints,
                        std::string& failure_reason)
{
    failure_reason.clear();
    for (const auto& c : constraints)
    {
        if (c.predicate_smt2.empty() || c.predicate_smt2.find("<smt-error>") != std::string::npos)
            continue;
        std::string formula = ensure_assertion(c.predicate_smt2, false);
        if (!smt.assert_smtlib2(formula))
        {
            const char* err = smt.last_error();
            if (failure_reason.empty())
            {
                failure_reason = err != nullptr ? std::string(err) : std::string("unknown assert failure");
            }
        }
    }
    return failure_reason.empty();
}

void assert_input_shape_constraints(smt::SmtContext& smt,
                                    const std::vector<smt::model_entry_t>& existing_inputs,
                                    const exploit_constraints_t& shape)
{
    for (const auto& entry : existing_inputs)
    {
        if (!entry.is_bitvector || entry.name.empty())
            continue;
        int width = entry.bv_width > 0 ? entry.bv_width : 8;
        if (width <= 0 || width > 64)
            continue;
        smt.declare_bv(entry.name, width);
        uint64_t max_byte = shape.max_byte;
        if (shape.printable_only)
        {
            smt.assert_bv_ugt(entry.name, 0x1Fu, width);
            if (max_byte > 0x7Eu)
                max_byte = 0x7Eu;
        }
        if (shape.ascii_only && max_byte > 0x7Fu)
            max_byte = 0x7Fu;
        if (max_byte < 255u)
            smt.assert_bv_ult(entry.name, max_byte + 1u, width);
        if (shape.no_null_bytes)
            smt.assert_bv_ugt(entry.name, 0u, width);
    }
}

bool block_has_back_edge(const mba_t& mba, const mblock_t& blk)
{
    for (size_t i = 0; i < blk.succset.size(); ++i)
    {
        int succ = blk.succset[i];
        if (succ <= blk.serial)
        {
            const mblock_t* dst = mba.get_mblock(static_cast<uint>(succ));
            if (dst != nullptr)
                return true;
        }
    }
    return false;
}

bool function_has_loop(const mba_t& mba)
{
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        if (block_has_back_edge(mba, *blk))
            return true;
    }
    return false;
}

bool find_induction_lvar(mba_t& mba, int& out_idx, int& out_width_bits)
{
    out_idx = -1;
    out_width_bits = 0;
    for (size_t v = 0; v < mba.vars.size(); ++v)
    {
        auto chain = aida::vuln::microcode::def_use_chain_for_lvar(mba, static_cast<int>(v));
        if (chain.defs.empty() || chain.uses.empty())
            continue;
        bool def_in_back_edge_block = false;
        for (ea_t def_ea : chain.defs)
        {
            for (int b = 0; b < mba.qty; ++b)
            {
                const mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
                if (blk == nullptr)
                    continue;
                bool covers = false;
                for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
                {
                    if (m->ea == def_ea)
                    {
                        covers = true;
                        break;
                    }
                }
                if (!covers && def_ea >= blk->start && def_ea < blk->end)
                    covers = true;
                if (covers && block_has_back_edge(mba, *blk))
                {
                    def_in_back_edge_block = true;
                    break;
                }
            }
            if (def_in_back_edge_block)
                break;
        }
        if (!def_in_back_edge_block)
            continue;
        const lvar_t& lv = mba.vars[v];
        int w = lv.width > 0 ? lv.width : 4;
        if (w > 8)
            w = 8;
        out_idx = static_cast<int>(v);
        out_width_bits = w * 8;
        return true;
    }
    return false;
}

}

bool cache_key_t::operator==(const cache_key_t& o) const
{
    return func_ea == o.func_ea &&
           sink_ea == o.sink_ea &&
           source_ea == o.source_ea &&
           sig_db_rev == o.sig_db_rev;
}

size_t cache_key_hash_t::operator()(const cache_key_t& k) const noexcept
{
    uint64_t h = static_cast<uint64_t>(k.func_ea);
    h ^= static_cast<uint64_t>(k.sink_ea) + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
    h ^= static_cast<uint64_t>(k.source_ea) + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
    h ^= static_cast<uint64_t>(k.sig_db_rev) + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
    return static_cast<size_t>(h);
}

struct VerificationEngine::impl_t
{
    aida::vuln::symbolic::SymbolicEngine        sym;
    aida::vuln::smt::SmtContextPool             smt_pool;
    std::string                                 last_err;
    mutable std::mutex                          mu;
    std::unordered_map<std::string, int>        verdict_counts;
    std::unordered_map<cache_key_t, path_verification_t, cache_key_hash_t> verdict_cache;

    impl_t() = default;

    void bump_verdict(verdict_t v)
    {
        std::lock_guard<std::mutex> lk(mu);
        verdict_counts[verdict_str(v)] += 1;
    }
};

VerificationEngine::VerificationEngine()
    : m_impl(std::make_unique<impl_t>())
{
    if (!m_impl)
        return;
    if (!m_impl->sym.is_available())
    {
        const char* e = m_impl->sym.last_error();
        m_impl->last_err = e != nullptr && *e ? std::string("symbolic: ") + e
                                              : std::string("symbolic engine unavailable");
    }
    auto probe = m_impl->smt_pool.create_context();
    if (!probe || !probe->is_available())
    {
        const char* e = probe ? probe->last_error() : "";
        if (!m_impl->last_err.empty())
            m_impl->last_err.append("; ");
        m_impl->last_err.append(e != nullptr && *e ? std::string("smt: ") + e
                                                   : std::string("smt context unavailable"));
    }
}

VerificationEngine::~VerificationEngine() = default;

bool VerificationEngine::is_available() const
{
    if (!m_impl)
        return false;
    auto probe = m_impl->smt_pool.create_context();
    return m_impl->sym.is_available() && probe && probe->is_available();
}

const char* VerificationEngine::last_error() const
{
    if (!m_impl)
        return "";
    return m_impl->last_err.c_str();
}

path_verification_t VerificationEngine::verify_taint_path(ea_t source_ea,
                                                          ea_t sink_ea,
                                                          uint32_t timeout_ms)
{
    inflight_guard_t in_flight;
    path_verification_t out;
    if (!m_impl)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "verification engine not initialized";
        return out;
    }
    if (!is_available())
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = m_impl->last_err.empty() ? std::string("z3/triton unavailable") : m_impl->last_err;
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "no enclosing function for sink";
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    cache_key_t key{pfn->start_ea, sink_ea, source_ea, sig::SIGNATURE_DATABASE_REVISION};
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        auto it = m_impl->verdict_cache.find(key);
        if (it != m_impl->verdict_cache.end())
            return it->second;
    }

    if (should_cancel())
    {
        out.verdict = verdict_t::timeout;
        out.rationale = "verification cancelled before symbolic load";
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.verdict = verdict_t::unsupported;
        const char* e = m_impl->sym.last_error();
        out.rationale = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                           : std::string("symbolic load failed");
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    if (source_ea != BADADDR)
        m_impl->sym.constrain_taint_source_at(source_ea);

    out.constraints = m_impl->sym.collect_path_to(sink_ea, 64);
    out.cited_eas = collect_cited_eas(out.constraints);
    out.via_seh_handler = has_seh_path(out.constraints);

    if (out.constraints.empty())
    {
        out.verdict = verdict_t::confirmed;
        out.smt_result = smt::result_t::sat;
        out.adjusted_confidence = confidence_t::likely;
        out.rationale = "no path constraints; sink reachable unconditionally";
        out.cached_at = now_ms();
        {
            std::lock_guard<std::mutex> lk(m_impl->mu);
            m_impl->verdict_cache[key] = out;
        }
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    if (should_cancel())
    {
        out.verdict = verdict_t::timeout;
        out.smt_result = smt::result_t::unknown;
        out.rationale = "verification cancelled before SMT solve";
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    auto local_ptr = m_impl->smt_pool.create_context();
    smt::SmtContext& local = *local_ptr;
    if (!local.is_available())
    {
        out.verdict = verdict_t::unsupported;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                           : std::string("smt unavailable");
        m_impl->bump_verdict(out.verdict);
        return out;
    }

    std::unordered_map<std::string, int> declared;
    emit_declarations(local, out.constraints, declared);

    std::string assert_err;
    assert_constraints(local, out.constraints, assert_err);

    auto t0 = std::chrono::steady_clock::now();
    smt::solve_result_t r = local.check_with_timeout(timeout_ms);
    auto t1 = std::chrono::steady_clock::now();
    out.solve_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    if (out.solve_ms == 0 && r.solve_ms > 0)
        out.solve_ms = r.solve_ms;

    out.smt_result = r.result;
    switch (r.result)
    {
    case smt::result_t::sat:
        out.verdict = verdict_t::confirmed;
        out.adjusted_confidence = confidence_t::confirmed;
        out.witness = r.model;
        {
            std::ostringstream rs;
            rs << "path satisfiable; model has " << r.model.size() << " variable(s)";
            if (!assert_err.empty())
                rs << "; partial constraints: " << assert_err;
            out.rationale = rs.str();
        }
        break;
    case smt::result_t::unsat:
        out.verdict = verdict_t::refuted;
        out.adjusted_confidence = confidence_t::speculative;
        out.rationale = "path unsatisfiable; finding is a ghost / dead-code";
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        break;
    case smt::result_t::unknown:
    default:
        if (r.reason.find("timeout") != std::string::npos ||
            r.reason.find("canceled") != std::string::npos)
        {
            out.verdict = verdict_t::timeout;
            out.rationale = "z3 timeout reached";
        }
        else
        {
            out.verdict = verdict_t::inconclusive;
            out.rationale = r.reason.empty() ? std::string("solver returned unknown") : r.reason;
        }
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        break;
    }

    out.cached_at = now_ms();
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        m_impl->verdict_cache[key] = out;
    }
    m_impl->bump_verdict(out.verdict);
    return out;
}

exploit_input_t VerificationEngine::solve_for_exploit_input(ea_t source_ea,
                                                            ea_t sink_ea,
                                                            uint32_t timeout_ms,
                                                            const exploit_constraints_t& input_shape)
{
    inflight_guard_t in_flight;
    exploit_input_t out;
    if (!m_impl)
    {
        out.found = false;
        out.rationale = "verification engine not initialized";
        return out;
    }
    if (!is_available())
    {
        out.found = false;
        out.rationale = m_impl->last_err.empty() ? std::string("z3/triton unavailable") : m_impl->last_err;
        return out;
    }

    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
    {
        out.found = false;
        out.rationale = "no enclosing function for sink";
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.found = false;
        const char* e = m_impl->sym.last_error();
        out.rationale = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                           : std::string("symbolic load failed");
        return out;
    }

    if (source_ea != BADADDR)
        m_impl->sym.constrain_taint_source_at(source_ea);

    auto constraints = m_impl->sym.collect_path_to(sink_ea, 64);
    out.cited_eas = collect_cited_eas(constraints);

    if (should_cancel())
    {
        out.found = false;
        out.rationale = "verification cancelled before SMT solve";
        return out;
    }

    auto local_ptr = m_impl->smt_pool.create_context();
    smt::SmtContext& local = *local_ptr;
    if (!local.is_available())
    {
        out.found = false;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                           : std::string("smt unavailable");
        return out;
    }

    std::unordered_map<std::string, int> declared;
    emit_declarations(local, constraints, declared);

    std::string assert_err;
    assert_constraints(local, constraints, assert_err);

    if (input_shape.alignment > 1)
    {
        std::ostringstream align_note;
        align_note << "alignment=" << input_shape.alignment;
        if (!assert_err.empty())
            assert_err.append("; ");
        assert_err.append(align_note.str());
    }

    smt::solve_result_t r = local.check_with_timeout(timeout_ms);

    if (r.result != smt::result_t::sat)
    {
        out.found = false;
        if (r.result == smt::result_t::unsat)
            out.rationale = "path unsatisfiable; no exploit input exists for this path";
        else if (r.reason.find("timeout") != std::string::npos)
            out.rationale = "solver timeout while searching for exploit input";
        else
            out.rationale = r.reason.empty() ? std::string("solver returned unknown") : r.reason;
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        return out;
    }

    out.found = true;
    out.inputs = r.model;

    if (input_shape.ascii_only || input_shape.no_null_bytes || input_shape.printable_only || input_shape.max_byte < 255)
    {
        smt::SmtContext shaped;
        if (shaped.is_available())
        {
            emit_declarations(shaped, constraints, declared);
            std::string shaped_err;
            assert_constraints(shaped, constraints, shaped_err);
            assert_input_shape_constraints(shaped, out.inputs, input_shape);
            auto shaped_result = shaped.check_with_timeout(timeout_ms);
            if (shaped_result.result == smt::result_t::sat)
            {
                out.inputs = shaped_result.model;
                r = shaped_result;
            }
        }
    }

    std::vector<const smt::model_entry_t*> input_entries;
    input_entries.reserve(out.inputs.size());
    for (const auto& m : out.inputs)
    {
        if (!m.is_bitvector)
            continue;
        if (name_looks_like_input(m.name))
            input_entries.push_back(&m);
    }
    if (input_entries.empty())
    {
        for (const auto& m : out.inputs)
        {
            if (m.is_bitvector)
                input_entries.push_back(&m);
        }
    }

    std::sort(input_entries.begin(), input_entries.end(),
              [](const smt::model_entry_t* a, const smt::model_entry_t* b) {
                  return a->name < b->name;
              });

    std::ostringstream trigger;
    trigger << "Trigger: ";
    size_t emitted = 0;
    for (const smt::model_entry_t* m : input_entries)
    {
        if (emitted >= k_max_inputs_in_summary)
        {
            trigger << ", ...";
            break;
        }
        if (emitted > 0)
            trigger << ", ";
        trigger << m->name << " = " << format_hex64(m->bv_value);
        if (m->bv_width > 0)
            trigger << " (" << m->bv_width << "b)";
        ++emitted;
    }
    if (input_entries.empty())
        trigger << "<no concrete inputs in model>";

    for (const smt::model_entry_t* m : input_entries)
    {
        int width = m->bv_width > 0 ? m->bv_width : 64;
        append_concrete_bytes_le(out.concrete_bytes, m->bv_value, width);
    }

    std::ostringstream bytes_str;
    bytes_str << ". Concrete bytes (little-endian):";
    if (out.concrete_bytes.empty())
    {
        bytes_str << " <none>";
    }
    else
    {
        char hex_buf[4];
        for (uint8_t b : out.concrete_bytes)
        {
            ::qsnprintf(hex_buf, sizeof(hex_buf), " %02x", b);
            bytes_str << hex_buf;
        }
    }

    out.summary = trigger.str() + bytes_str.str();
    std::ostringstream rs;
    rs << "z3 produced satisfying assignment in " << r.solve_ms << " ms with "
       << input_entries.size() << " input variable(s)";
    if (!assert_err.empty())
        rs << "; partial constraints: " << assert_err;
    out.rationale = rs.str();
    return out;
}

loop_bound_proof_t VerificationEngine::prove_loop_bound(ea_t loop_func_ea,
                                                        int64_t buffer_size,
                                                        uint32_t timeout_ms)
{
    inflight_guard_t in_flight;
    loop_bound_proof_t out;
    out.buffer_size = buffer_size;

    if (!m_impl || !is_available())
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.rationale.empty())
            out.rationale = "z3/triton unavailable";
        return out;
    }

    func_t* pfn = get_func(loop_func_ea);
    if (pfn == nullptr)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "no enclosing function";
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.verdict = verdict_t::unsupported;
        const char* e = m_impl->sym.last_error();
        out.rationale = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                           : std::string("symbolic load failed");
        return out;
    }

    auto handle_opt = aida::vuln::microcode::generate(pfn->start_ea, MMAT_LVARS);
    if (!handle_opt.has_value() || handle_opt->mba.get() == nullptr)
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "could not generate microcode for loop function";
        return out;
    }
    mba_t* mba_ptr = handle_opt->mba.get();

    if (!function_has_loop(*mba_ptr))
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "no back-edge / loop in CFG";
        return out;
    }

    int induction_idx = -1;
    int induction_width_bits = 0;
    if (!find_induction_lvar(*mba_ptr, induction_idx, induction_width_bits))
    {
        out.verdict = verdict_t::unsupported;
        out.rationale = "could not identify loop induction variable";
        return out;
    }
    if (induction_width_bits <= 0 || induction_width_bits > 64)
        induction_width_bits = 32;

    std::ostringstream var_name_ss;
    if (induction_idx >= 0 && static_cast<size_t>(induction_idx) < mba_ptr->vars.size())
    {
        const lvar_t& lv = mba_ptr->vars[induction_idx];
        if (!lv.name.empty())
            var_name_ss << "lvar_" << lv.name.c_str() << "_" << induction_idx;
        else
            var_name_ss << "lvar_" << induction_idx;
    }
    else
    {
        var_name_ss << "lvar_" << induction_idx;
    }
    std::string ind_name = var_name_ss.str();

    auto local_ptr = m_impl->smt_pool.create_context();
    smt::SmtContext& local = *local_ptr;
    if (!local.is_available())
    {
        out.verdict = verdict_t::unsupported;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                           : std::string("smt unavailable");
        return out;
    }

    if (!local.declare_bv(ind_name, induction_width_bits))
    {
        out.verdict = verdict_t::unsupported;
        const char* e = local.last_error();
        out.rationale = e != nullptr && *e ? std::string("declare failed: ") + e
                                           : std::string("declare failed");
        return out;
    }

    auto last_constraints = m_impl->sym.all_path_constraints(64);
    std::unordered_map<std::string, int> declared;
    emit_declarations(local, last_constraints, declared);
    std::string assert_err;
    assert_constraints(local, last_constraints, assert_err);

    if (buffer_size > 0)
    {
        const uint64_t mask = induction_width_bits >= 64 ? ~static_cast<uint64_t>(0)
                                                         : ((static_cast<uint64_t>(1) << induction_width_bits) - 1u);
        uint64_t bound = static_cast<uint64_t>(buffer_size);
        if (bound > mask)
            bound = mask;
        std::ostringstream upper;
        upper << "(assert (bvule " << ind_name << " (_ bv" << bound << " " << induction_width_bits << ")))";
        local.assert_smtlib2(upper.str());
    }

    if (should_cancel())
    {
        out.verdict = verdict_t::timeout;
        out.rationale = "verification cancelled before optimization";
        return out;
    }

    auto max_opt = local.max_value_bv(ind_name, induction_width_bits, timeout_ms);
    auto min_opt = local.min_value_bv(ind_name, induction_width_bits, timeout_ms);

    if (!max_opt.has_value())
    {
        out.verdict = verdict_t::inconclusive;
        out.rationale = "could not derive max index for induction variable";
        if (!assert_err.empty())
            out.rationale.append("; partial constraints: ").append(assert_err);
        return out;
    }

    out.max_index = static_cast<int64_t>(*max_opt);
    out.min_index = min_opt.has_value() ? static_cast<int64_t>(*min_opt) : 0;

    if (buffer_size > 0 && out.max_index >= buffer_size)
    {
        out.overflow_provable = true;
        out.verdict = verdict_t::confirmed;
        std::ostringstream rs;
        rs << "induction var " << ind_name << " can reach " << out.max_index
           << " (>= buffer_size " << buffer_size << "); overflow provable";
        out.rationale = rs.str();
    }
    else if (buffer_size > 0)
    {
        out.overflow_provable = false;
        out.verdict = verdict_t::refuted;
        std::ostringstream rs;
        rs << "induction var " << ind_name << " bounded to [" << out.min_index << ", "
           << out.max_index << "]; below buffer_size " << buffer_size;
        out.rationale = rs.str();
    }
    else
    {
        out.verdict = verdict_t::inconclusive;
        std::ostringstream rs;
        rs << "induction var " << ind_name << " bounded to [" << out.min_index << ", "
           << out.max_index << "]; no buffer size to compare";
        out.rationale = rs.str();
    }
    if (!assert_err.empty())
        out.rationale.append("; partial constraints: ").append(assert_err);
    return out;
}

symbolic::alias_proof_t VerificationEngine::prove_pointer_alias(ea_t func_ea,
                                                                const std::string& ptr1_spec,
                                                                const std::string& ptr2_spec,
                                                                uint32_t timeout_ms)
{
    inflight_guard_t in_flight;
    symbolic::alias_proof_t out;
    if (!m_impl || !is_available())
    {
        out.reason = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.reason.empty())
            out.reason = "z3/triton unavailable";
        return out;
    }

    if (!m_impl->sym.load_function(func_ea))
    {
        const char* e = m_impl->sym.last_error();
        out.reason = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                        : std::string("symbolic load failed");
        return out;
    }

    if (should_cancel())
    {
        out.verdict = symbolic::alias_proof_t::verdict_t::inconclusive;
        out.verdict_label = "inconclusive";
        out.reason = "verification cancelled before alias solve";
        return out;
    }

    return m_impl->sym.prove_alias(ptr1_spec, ptr2_spec, timeout_ms);
}

symbolic::simplification_t VerificationEngine::simplify_function_arithmetic(ea_t func_ea,
                                                                            int max_insns)
{
    symbolic::simplification_t out;
    if (!m_impl || !is_available())
    {
        out.before_text = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.before_text.empty())
            out.before_text = "z3/triton unavailable";
        out.after_text = out.before_text;
        return out;
    }

    if (!m_impl->sym.load_function(func_ea))
    {
        const char* e = m_impl->sym.last_error();
        out.before_text = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                             : std::string("symbolic load failed");
        out.after_text = out.before_text;
        return out;
    }

    return m_impl->sym.simplify_function_arithmetic(max_insns);
}

smt::solve_result_t VerificationEngine::check_path_satisfiability(const std::vector<ea_t>& branch_eas,
                                                                  uint32_t timeout_ms)
{
    smt::solve_result_t out;
    if (!m_impl || !is_available())
    {
        out.result = smt::result_t::unknown;
        out.reason = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        if (out.reason.empty())
            out.reason = "z3/triton unavailable";
        return out;
    }
    if (branch_eas.empty())
    {
        out.result = smt::result_t::sat;
        out.reason = "no branches; trivially satisfiable";
        return out;
    }

    func_t* pfn = get_func(branch_eas.front());
    if (pfn == nullptr)
    {
        out.result = smt::result_t::unknown;
        out.reason = "no enclosing function for first branch";
        return out;
    }

    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.result = smt::result_t::unknown;
        const char* e = m_impl->sym.last_error();
        out.reason = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                        : std::string("symbolic load failed");
        return out;
    }

    std::vector<symbolic::path_constraint_t> merged;
    std::set<ea_t> seen;
    for (ea_t ea : branch_eas)
    {
        auto pcs = m_impl->sym.collect_path_to(ea, 64);
        for (auto& pc : pcs)
        {
            if (pc.branch_ea != BADADDR && !seen.insert(pc.branch_ea).second)
                continue;
            merged.push_back(std::move(pc));
        }
    }

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.result = smt::result_t::unknown;
        const char* e = local.last_error();
        out.reason = e != nullptr && *e ? std::string("smt unavailable: ") + e
                                        : std::string("smt unavailable");
        return out;
    }

    std::unordered_map<std::string, int> declared;
    emit_declarations(local, merged, declared);
    std::string assert_err;
    assert_constraints(local, merged, assert_err);

    smt::solve_result_t r = local.check_with_timeout(timeout_ms);
    if (!assert_err.empty())
    {
        if (!r.reason.empty())
            r.reason.append("; ");
        r.reason.append("partial constraints: ").append(assert_err);
    }
    return r;
}

smt::solve_result_t VerificationEngine::solve_smtlib2(const std::string& formula,
                                                      uint32_t timeout_ms)
{
    smt::solve_result_t out;
    out.solve_ms = 0;
    if (!m_impl)
    {
        out.result = smt::result_t::unknown;
        out.reason = "verification engine not initialized";
        return out;
    }
    if (!smt::ensure_z3_runtime())
    {
        out.result = smt::result_t::unknown;
        out.reason = "z3 runtime unavailable";
        return out;
    }

    smt::SmtContext local;
    if (!local.is_available())
    {
        out.result = smt::result_t::unknown;
        const char* e = local.last_error();
        out.reason = e != nullptr && *e ? std::string(e) : std::string("smt unavailable");
        return out;
    }

    if (!local.assert_smtlib2(formula))
    {
        smt::result_t quick = smt::result_t::unknown;
        auto t0 = std::chrono::steady_clock::now();
        bool ok = smt::SmtContext::smtlib2_quick_check(formula, quick, timeout_ms);
        auto t1 = std::chrono::steady_clock::now();
        out.solve_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
        out.result = quick;
        if (!ok)
        {
            const char* e = local.last_error();
            out.reason = e != nullptr && *e ? std::string("formula invalid: ") + e
                                            : std::string("formula invalid or z3 unavailable");
        }
        return out;
    }

    out = local.check_with_timeout(timeout_ms);
    return out;
}

triage_result_t VerificationEngine::triage_sink(ea_t source_ea,
                                                ea_t sink_ea,
                                                uint32_t cheap_timeout_ms,
                                                uint32_t deep_timeout_ms,
                                                const std::string& stop_at)
{
    inflight_guard_t in_flight;
    triage_result_t out;
    out.stage_reached = "sat_check";
    if (!m_impl || !is_available())
    {
        out.final_verdict = verdict_t::unsupported;
        out.sat_check.result = smt::result_t::unknown;
        out.sat_check.reason = m_impl ? m_impl->last_err : std::string("verification engine not initialized");
        return out;
    }
    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
    {
        out.final_verdict = verdict_t::unsupported;
        out.sat_check.result = smt::result_t::unknown;
        out.sat_check.reason = "no enclosing function for sink";
        return out;
    }
    if (!m_impl->sym.load_function(pfn->start_ea))
    {
        out.final_verdict = verdict_t::unsupported;
        out.sat_check.result = smt::result_t::unknown;
        const char* e = m_impl->sym.last_error();
        out.sat_check.reason = e != nullptr && *e ? std::string("symbolic load failed: ") + e
                                                  : std::string("symbolic load failed");
        return out;
    }
    if (source_ea != BADADDR)
        m_impl->sym.constrain_taint_source_at(source_ea);
    auto constraints = m_impl->sym.collect_path_to(sink_ea, 64);
    auto local = m_impl->smt_pool.create_context();
    if (!local || !local->is_available())
    {
        out.final_verdict = verdict_t::unsupported;
        out.sat_check.result = smt::result_t::unknown;
        out.sat_check.reason = local ? local->last_error() : "smt unavailable";
        return out;
    }
    std::unordered_map<std::string, int> declared;
    emit_declarations(*local, constraints, declared);
    std::string assert_err;
    assert_constraints(*local, constraints, assert_err);
    out.sat_check = local->check_with_timeout(cheap_timeout_ms);
    if (!assert_err.empty())
    {
        if (!out.sat_check.reason.empty())
            out.sat_check.reason.append("; ");
        out.sat_check.reason.append("partial constraints: ").append(assert_err);
    }
    out.final_verdict = smt_result_to_verdict(out.sat_check);
    if (out.final_verdict == verdict_t::refuted || stop_at == "sat_check" || should_cancel())
        return out;

    out.stage_reached = "taint_check";
    out.taint_check = verify_taint_path(source_ea, sink_ea, cheap_timeout_ms * 4u);
    out.final_verdict = out.taint_check.verdict;
    if (out.final_verdict == verdict_t::confirmed || stop_at == "taint_check" || should_cancel())
        return out;

    out.stage_reached = "exploit_input";
    out.exploit_input = solve_for_exploit_input(source_ea, sink_ea, deep_timeout_ms);
    if (out.exploit_input.found)
        out.final_verdict = verdict_t::confirmed;
    return out;
}

std::vector<path_verification_t> VerificationEngine::list_verified(verdict_t filter,
                                                                   bool use_filter,
                                                                   ea_t sink_ea,
                                                                   size_t max_entries) const
{
    std::vector<path_verification_t> out;
    if (!m_impl)
        return out;
    if (max_entries == 0)
        max_entries = 100;
    std::lock_guard<std::mutex> lk(m_impl->mu);
    for (const auto& kv : m_impl->verdict_cache)
    {
        if (use_filter && kv.second.verdict != filter)
            continue;
        if (sink_ea != BADADDR && kv.first.sink_ea != sink_ea)
            continue;
        out.push_back(kv.second);
        if (out.size() >= max_entries)
            break;
    }
    return out;
}

nlohmann::json VerificationEngine::persist_ledger(const std::string& action)
{
    nlohmann::json result;
    result["action"] = action;
    result["entries_saved_or_loaded"] = 0;
    result["ledger_size_bytes"] = 0;
    netnode nn(k_verify_ledger_node, 0, action == "save");
    if (action == "clear")
    {
        if (nn != BADNODE)
            nn.kill();
        result["cleared"] = true;
        return result;
    }
    if (action == "save")
    {
        nlohmann::json root;
        root["binary_md5"] = binary_md5_hex();
        root["sig_db_rev"] = sig::SIGNATURE_DATABASE_REVISION;
        root["entries"] = nlohmann::json::array();
        {
            std::lock_guard<std::mutex> lk(m_impl->mu);
            for (const auto& kv : m_impl->verdict_cache)
            {
                nlohmann::json e = to_json(kv.second);
                e["key"] = cache_key_string(kv.first);
                e["func_ea"] = ea_to_hex(kv.first.func_ea);
                e["source_ea"] = ea_to_hex(kv.first.source_ea);
                e["sink_ea"] = ea_to_hex(kv.first.sink_ea);
                e["sig_db_rev"] = kv.first.sig_db_rev;
                root["entries"].push_back(std::move(e));
            }
        }
        std::vector<std::uint8_t> packed = nlohmann::json::to_msgpack(root);
        result["ledger_size_bytes"] = packed.size();
        for (nodeidx_t i = 0; i < 128; ++i)
            nn.delblob(k_verify_ledger_blob_start + i, k_verify_ledger_blob_tag);
        size_t offset = 0;
        nodeidx_t page = 0;
        while (offset < packed.size())
        {
            size_t chunk = std::min(k_verify_ledger_page_size, packed.size() - offset);
            nn.setblob(packed.data() + offset, chunk, k_verify_ledger_blob_start + page, k_verify_ledger_blob_tag);
            offset += chunk;
            ++page;
        }
        result["pages"] = page;
        result["entries_saved_or_loaded"] = root["entries"].size();
        return result;
    }
    if (action == "load")
    {
        if (nn == BADNODE)
            return result;
        std::vector<std::uint8_t> packed;
        for (nodeidx_t page = 0; page < 128; ++page)
        {
            size_t sz = nn.blobsize(k_verify_ledger_blob_start + page, k_verify_ledger_blob_tag);
            if (sz == 0)
                break;
            void* blob = nn.getblob(nullptr, &sz, k_verify_ledger_blob_start + page, k_verify_ledger_blob_tag);
            if (blob == nullptr)
                break;
            const std::unique_ptr<void, decltype(&qfree)> blob_guard(blob, &qfree);
            const std::uint8_t* bytes = static_cast<const std::uint8_t*>(blob_guard.get());
            packed.insert(packed.end(), bytes, bytes + sz);
        }
        result["ledger_size_bytes"] = packed.size();
        if (packed.empty())
            return result;
        nlohmann::json root = nlohmann::json::from_msgpack(packed, true, false);
        if (!root.is_object() || root.value("binary_md5", "") != binary_md5_hex())
            return result;
        size_t loaded = 0;
        std::lock_guard<std::mutex> lk(m_impl->mu);
        if (root.contains("entries") && root["entries"].is_array())
        {
            for (const auto& e : root["entries"])
            {
                cache_key_t key;
                auto parse_ea = [](const nlohmann::json& obj, const char* field) -> ea_t {
                    if (!obj.contains(field) || !obj[field].is_string())
                        return BADADDR;
                    const std::string s = obj[field].get<std::string>();
                    if (s.empty())
                        return BADADDR;
                    char* endp = nullptr;
                    uint64_t v = _strtoui64(s.c_str(), &endp, 0);
                    if (endp == s.c_str())
                        return BADADDR;
                    return static_cast<ea_t>(v);
                };
                key.func_ea = parse_ea(e, "func_ea");
                key.source_ea = parse_ea(e, "source_ea");
                key.sink_ea = parse_ea(e, "sink_ea");
                key.sig_db_rev = e.value("sig_db_rev", sig::SIGNATURE_DATABASE_REVISION);
                if (key.func_ea == BADADDR || key.sink_ea == BADADDR || key.sig_db_rev != sig::SIGNATURE_DATABASE_REVISION)
                    continue;
                path_verification_t v;
                std::string verdict = e.value("verdict", "inconclusive");
                if (verdict == "confirmed") v.verdict = verdict_t::confirmed;
                else if (verdict == "refuted") v.verdict = verdict_t::refuted;
                else if (verdict == "timeout") v.verdict = verdict_t::timeout;
                else if (verdict == "unsupported") v.verdict = verdict_t::unsupported;
                else v.verdict = verdict_t::inconclusive;
                std::string smtr = e.value("smt_result", "unknown");
                if (smtr == "sat") v.smt_result = smt::result_t::sat;
                else if (smtr == "unsat") v.smt_result = smt::result_t::unsat;
                else v.smt_result = smt::result_t::unknown;
                v.solve_ms = e.value("solve_ms", 0ull);
                v.rationale = e.value("rationale", "");
                v.cached_at = e.value("cached_at", now_ms());
                m_impl->verdict_cache[key] = std::move(v);
                ++loaded;
            }
        }
        result["entries_saved_or_loaded"] = loaded;
    }
    return result;
}

void VerificationEngine::cancel()
{
    g_verify_cancel.store(true, std::memory_order_relaxed);
}

int VerificationEngine::in_flight_count() const
{
    return g_verify_in_flight.load(std::memory_order_relaxed);
}

wire_path_constraints_t VerificationEngine::extract_wire_path_constraints(ea_t source_ea,
                                                                          ea_t sink_ea,
                                                                          int max_branches)
{
    wire_path_constraints_t out;
    out.source_ea = source_ea;
    out.sink_ea = sink_ea;
    if (!m_impl || !is_available())
        return out;
    func_t* pfn = get_func(sink_ea);
    if (pfn == nullptr)
        return out;
    if (!m_impl->sym.load_function(pfn->start_ea))
        return out;
    if (source_ea != BADADDR)
        m_impl->sym.constrain_taint_source_at(source_ea);
    auto constraints = m_impl->sym.collect_path_to(sink_ea, max_branches);
    out.smt2_formula = m_impl->sym.path_smtlib2(sink_ea, max_branches);
    uint64_t offset = 0;
    for (const auto& c : constraints)
    {
        if (c.branch_ea == BADADDR)
            continue;
        wire_constraint_t wc;
        wc.buffer_offset = offset++;
        wc.width_bytes = 1;
        wc.op = c.taken ? "branch_taken" : "branch_not_taken";
        wc.comparison_ea = c.branch_ea;
        wc.rationale = c.predicate_text.empty() ? c.predicate_smt2 : c.predicate_text;
        out.constraints.push_back(std::move(wc));
    }
    out.implied_min_buffer_size = out.constraints.empty() ? 0 : out.constraints.back().buffer_offset + 1;
    return out;
}

exploit_input_t VerificationEngine::synthesize_exploit_payload(ea_t source_ea,
                                                               ea_t sink_ea,
                                                               uint32_t timeout_ms,
                                                               const exploit_constraints_t& constraints)
{
    auto wire = extract_wire_path_constraints(source_ea, sink_ea, 64);
    exploit_input_t out = solve_for_exploit_input(source_ea, sink_ea, timeout_ms, constraints);
    if (out.found && out.concrete_bytes.size() < wire.implied_min_buffer_size)
        out.concrete_bytes.resize(wire.implied_min_buffer_size, 0);
    if (out.found && out.summary.find("python struct.pack") == std::string::npos)
    {
        std::ostringstream py;
        py << " python struct.pack('<" << out.concrete_bytes.size() << "B'";
        for (uint8_t b : out.concrete_bytes)
            py << ", " << static_cast<unsigned>(b);
        py << ")";
        out.summary.append(py.str());
    }
    return out;
}

nlohmann::json VerificationEngine::verdict_summary() const
{
    nlohmann::json j;
    if (!m_impl)
    {
        j["available"] = false;
        j["sym_error"] = "";
        j["smt_error"] = "";
        return j;
    }
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        for (const auto& kv : m_impl->verdict_counts)
            j[kv.first] = kv.second;
        j["cache_entries"] = m_impl->verdict_cache.size();
    }
    for (const char* k : {"confirmed", "refuted", "timeout", "inconclusive", "unsupported"})
    {
        if (!j.contains(k))
            j[k] = 0;
    }
    j["available"] = is_available();
    const char* se = m_impl->sym.last_error();
    auto probe = m_impl->smt_pool.create_context();
    const char* me = probe ? probe->last_error() : "";
    j["sym_error"] = se != nullptr ? std::string(se) : std::string("");
    j["smt_error"] = me != nullptr ? std::string(me) : std::string("");
    return j;
}

VerificationEngine& engine()
{
    static VerificationEngine inst;
    return inst;
}

nlohmann::json to_json(const path_verification_t& v)
{
    nlohmann::json j;
    j["verdict"] = verdict_str(v.verdict);
    j["smt_result"] = smt::result_str(v.smt_result);
    j["solve_ms"] = v.solve_ms;
    j["cached_at"] = v.cached_at;
    j["via_seh_handler"] = v.via_seh_handler;
    j["adjusted_confidence"] = confidence_str(v.adjusted_confidence);
    j["rationale"] = v.rationale;
    j["cited_eas"] = nlohmann::json::array();
    for (ea_t ea : v.cited_eas)
        j["cited_eas"].push_back(ea_to_hex(ea));
    j["constraints"] = nlohmann::json::array();
    for (const auto& c : v.constraints)
        j["constraints"].push_back(symbolic::to_json(c));
    j["witness"] = nlohmann::json::array();
    for (const auto& w : v.witness)
        j["witness"].push_back(smt::to_json(w));
    return j;
}

nlohmann::json to_json(const exploit_input_t& e)
{
    nlohmann::json j;
    j["found"] = e.found;
    j["summary"] = e.summary;
    j["rationale"] = e.rationale;
    j["cited_eas"] = nlohmann::json::array();
    for (ea_t ea : e.cited_eas)
        j["cited_eas"].push_back(ea_to_hex(ea));
    j["inputs"] = nlohmann::json::array();
    for (const auto& i : e.inputs)
        j["inputs"].push_back(smt::to_json(i));
    nlohmann::json bytes = nlohmann::json::array();
    for (uint8_t b : e.concrete_bytes)
        bytes.push_back(static_cast<int>(b));
    j["concrete_bytes"] = bytes;
    std::string hex_dump;
    char hex_buf[3];
    for (uint8_t b : e.concrete_bytes)
    {
        ::qsnprintf(hex_buf, sizeof(hex_buf), "%02x", b);
        if (!hex_dump.empty())
            hex_dump.push_back(' ');
        hex_dump.append(hex_buf);
    }
    j["concrete_bytes_hex"] = hex_dump;
    return j;
}

nlohmann::json to_json(const loop_bound_proof_t& p)
{
    nlohmann::json j;
    j["verdict"] = verdict_str(p.verdict);
    j["max_index"] = p.max_index;
    j["min_index"] = p.min_index;
    j["buffer_size"] = p.buffer_size;
    j["overflow_provable"] = p.overflow_provable;
    j["rationale"] = p.rationale;
    return j;
}

nlohmann::json to_json(const triage_result_t& t)
{
    nlohmann::json j;
    j["stage_reached"] = t.stage_reached;
    j["final_verdict"] = verdict_str(t.final_verdict);
    j["sat_check"] = smt::to_json(t.sat_check);
    j["taint_check"] = to_json(t.taint_check);
    j["exploit_input"] = to_json(t.exploit_input);
    return j;
}

nlohmann::json to_json(const wire_constraint_t& c)
{
    nlohmann::json j;
    j["buffer_offset"] = c.buffer_offset;
    j["width_bytes"] = c.width_bytes;
    j["equal_to"] = c.equal_to;
    j["op"] = c.op;
    j["comparison_ea"] = ea_to_hex(c.comparison_ea);
    j["rationale"] = c.rationale;
    return j;
}

nlohmann::json to_json(const wire_path_constraints_t& w)
{
    nlohmann::json j;
    j["source_ea"] = ea_to_hex(w.source_ea);
    j["sink_ea"] = ea_to_hex(w.sink_ea);
    j["implied_min_buffer_size"] = w.implied_min_buffer_size;
    j["constraints"] = nlohmann::json::array();
    for (const auto& c : w.constraints)
        j["constraints"].push_back(to_json(c));
    j["smt2_formula"] = w.smt2_formula;
    return j;
}

}
}
}
