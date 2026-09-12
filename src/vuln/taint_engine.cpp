#include "../aida_pro.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <netnode.hpp>
#include <xref.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "microcode_engine.hpp"
#include "taint_engine.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace taint
{

namespace
{

constexpr int kMaxFunctionsToAnalyze = 8192;
constexpr int kMaxFixpointIterations = 4;
constexpr int kMaxBlocksPerFunction = 4096;
constexpr std::size_t kMaxFreedTrackingPerFunc = 16;

std::string ea_to_hex(ea_t ea)
{
    if (ea == BADADDR)
        return std::string("0x0");
    std::ostringstream ss;
    ss << "0x" << std::hex << std::uppercase << static_cast<std::uint64_t>(ea);
    return ss.str();
}

std::string ascii_lower(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        out.push_back(static_cast<char>(uc >= 'A' && uc <= 'Z' ? uc + ('a' - 'A') : uc));
    }
    return out;
}

std::string strip_known_prefixes(const std::string& raw)
{
    static const char* const prefixes[] = {
        "__imp_", "__imp__", "_imp_", "_imp__", "imp_",
        "j_", "j_imp_", "thunk_", "_thunk_",
    };
    std::string out = raw;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const char* p : prefixes)
        {
            const std::size_t plen = std::strlen(p);
            if (out.size() > plen && out.compare(0, plen, p) == 0)
            {
                out.erase(0, plen);
                changed = true;
                break;
            }
        }
    }
    if (out.size() > 1 && out.front() == '_')
    {
        bool only_alnum = true;
        for (char c : out)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '@' || c == '?'))
            {
                only_alnum = false;
                break;
            }
        }
        if (only_alnum)
            out.erase(0, 1);
    }
    auto at_pos = out.find('@');
    if (at_pos != std::string::npos)
        out.erase(at_pos);
    return out;
}

bool name_matches_signature(const std::string& callee, const std::string_view sig)
{
    if (callee.empty() || sig.empty())
        return false;
    const std::string sig_l = ascii_lower(std::string(sig));
    const std::string call_l = ascii_lower(callee);
    if (call_l == sig_l)
        return true;
    const std::string stripped = ascii_lower(strip_known_prefixes(callee));
    if (stripped == sig_l)
        return true;
    if (call_l.size() > sig_l.size() &&
        call_l.compare(call_l.size() - sig_l.size(), sig_l.size(), sig_l) == 0)
        return true;
    if (stripped.size() > sig_l.size() &&
        stripped.compare(stripped.size() - sig_l.size(), sig_l.size(), sig_l) == 0)
        return true;
    if (call_l.find(sig_l) != std::string::npos)
        return true;
    if (!stripped.empty() && stripped.find(sig_l) != std::string::npos)
        return true;
    return false;
}

struct source_match_t
{
    const sig::source_signature_t* source = nullptr;
    taint_kind_t                   kind = taint_kind_t::untainted;
};

template <std::size_t N>
source_match_t find_source_in_table(const std::string& name,
                                    const sig::source_signature_t (&table)[N],
                                    taint_kind_t kind)
{
    for (const auto& s : table)
    {
        if (name_matches_signature(name, s.name))
            return { &s, kind };
    }
    return {};
}

source_match_t find_input_source_match(const std::string& name)
{
    source_match_t m = find_source_in_table(name, sig::RPC_SERVER_SINKS, taint_kind_t::rpc_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::COM_SERVER_SINKS, taint_kind_t::com_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::ALPC_SOURCES, taint_kind_t::alpc_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::NAMED_PIPE_SOURCES, taint_kind_t::named_pipe_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::SOCKET_ACCEPT_SOURCES, taint_kind_t::socket_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::HTTP_SERVER_SOURCES, taint_kind_t::http_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::WEBSOCKET_SOURCES, taint_kind_t::websocket_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::NDIS_WSK_SOURCES, taint_kind_t::ndis_wsk_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::KERNEL_IRP_SOURCES, taint_kind_t::kernel_irp_input);
    if (m.source != nullptr) return m;
    m = find_source_in_table(name, sig::INPUT_SOURCES, taint_kind_t::user_input);
    if (m.source != nullptr) return m;
    return {};
}

struct sink_match_t
{
    const sig::sink_signature_t* sink = nullptr;
    std::string                  category;
    int                          primary_cwe = 0;
    int                          format_arg_index = -1;
    int                          len_arg_index = -1;
    int                          sensitive_arg_index = -1;

    bool matched() const
    {
        return sink != nullptr || !category.empty();
    }
};

void assign_sink_match(sink_match_t& out, const sig::sink_signature_t& s, const char* category)
{
    out.sink = &s;
    out.category = category;
    out.primary_cwe = s.primary_cwe;
    out.format_arg_index = s.format_arg_index;
    out.len_arg_index = s.len_arg_index;
    out.sensitive_arg_index = s.sensitive_arg_index;
}

template <std::size_t N>
bool find_sink_in_table(const std::string& name,
                        const sig::sink_signature_t (&table)[N],
                        const char* category,
                        sink_match_t& out)
{
    for (const auto& s : table)
    {
        if (name_matches_signature(name, s.name))
        {
            assign_sink_match(out, s, category);
            return true;
        }
    }
    return false;
}

sink_match_t sink_match_from_role(funcrole_t role)
{
    sink_match_t out;
    switch (role)
    {
    case ROLE_MEMCPY:
    case ROLE_WMEMCPY:
    case ROLE_MEMSET:
    case ROLE_WMEMSET:
    case ROLE_MEMSET32:
    case ROLE_MEMSET64:
        out.category = "buffer_overflow";
        out.primary_cwe = 120;
        out.len_arg_index = 2;
        break;
    case ROLE_STRCPY:
    case ROLE_WCSCPY:
    case ROLE_STRCAT:
    case ROLE_WCSCAT:
        out.category = "buffer_overflow";
        out.primary_cwe = 120;
        out.sensitive_arg_index = 1;
        break;
    default:
        break;
    }
    return out;
}

const char* sink_role_name(funcrole_t role)
{
    switch (role)
    {
    case ROLE_MEMCPY: return "ROLE_MEMCPY";
    case ROLE_WMEMCPY: return "ROLE_WMEMCPY";
    case ROLE_MEMSET: return "ROLE_MEMSET";
    case ROLE_WMEMSET: return "ROLE_WMEMSET";
    case ROLE_MEMSET32: return "ROLE_MEMSET32";
    case ROLE_MEMSET64: return "ROLE_MEMSET64";
    case ROLE_STRCPY: return "ROLE_STRCPY";
    case ROLE_WCSCPY: return "ROLE_WCSCPY";
    case ROLE_STRCAT: return "ROLE_STRCAT";
    case ROLE_WCSCAT: return "ROLE_WCSCAT";
    default: return "ROLE_UNK";
    }
}

sink_match_t find_sink_signature(const std::string& name)
{
    sink_match_t out;
    if (find_sink_in_table(name, sig::BUFFER_OVERFLOW_SINKS, "buffer_overflow", out)) return out;
    if (find_sink_in_table(name, sig::COMMAND_INJECTION_SINKS, "command_injection", out)) return out;
    if (find_sink_in_table(name, sig::PATH_TRAVERSAL_SINKS, "path_traversal", out)) return out;
    if (find_sink_in_table(name, sig::FORMAT_STRING_FUNCS, "format_string", out)) return out;
    if (find_sink_in_table(name, sig::SAFEARRAY_PARSER_SINKS, "safearray_parser", out)) return out;
    if (find_sink_in_table(name, sig::DESERIALIZATION_SINKS, "deserialization", out)) return out;
    return out;
}

bool is_sink_name(const std::string& name)
{
    return find_sink_signature(name).matched();
}

bool is_validator_name(const std::string& name)
{
    for (const auto& v : sig::KERNEL_VALIDATORS)
    {
        if (name_matches_signature(name, v))
            return true;
    }
    return false;
}

bool is_alloc_name(const std::string& name)
{
    for (const auto& a : sig::ALLOC_FUNCS)
    {
        if (name_matches_signature(name, a))
            return true;
    }
    return false;
}

bool is_free_name(const std::string& name)
{
    for (const auto& f : sig::FREE_FUNCS)
    {
        if (name_matches_signature(name, f))
            return true;
    }
    return false;
}

bool is_realloc_name(const std::string& name)
{
    for (const auto& r : sig::REALLOC_FUNCS)
    {
        if (name_matches_signature(name, r))
            return true;
    }
    return false;
}

taint_kind_t kind_from_source_name(const std::string& name)
{
    source_match_t src = find_input_source_match(name);
    if (src.kind != taint_kind_t::untainted && src.kind != taint_kind_t::user_input)
        return src.kind;
    const std::string l = ascii_lower(name);
    if (l.find("recv") != std::string::npos ||
        l.find("winhttp") != std::string::npos ||
        l.find("internet") != std::string::npos ||
        l.find("httpquery") != std::string::npos ||
        l.find("wsa") != std::string::npos)
        return taint_kind_t::network_input;
    if (l.find("readfile") != std::string::npos ||
        l.find("ntreadfile") != std::string::npos ||
        l.find("zwreadfile") != std::string::npos ||
        l.find("fread") != std::string::npos ||
        l == "read" || l == "_read")
        return taint_kind_t::file_input;
    if (l.find("getenv") != std::string::npos ||
        l.find("environment") != std::string::npos ||
        l.find("commandline") != std::string::npos)
        return taint_kind_t::env_input;
    if (l.find("regquery") != std::string::npos ||
        l.find("reggetvalue") != std::string::npos)
        return taint_kind_t::registry_input;
    return taint_kind_t::user_input;
}

const char* vulnerability_label_from_cwe(int cwe)
{
    switch (cwe)
    {
    case 22:  return "path_traversal";
    case 78:  return "command_injection";
    case 120: return "buffer_overflow";
    case 134: return "format_string";
    case 190: return "integer_overflow";
    case 242: return "dangerous_function";
    case 415: return "double_free";
    case 416: return "use_after_free";
    case 457: return "uninitialized_use";
    case 770: return "resource_exhaustion";
    default:  return "tainted_sink";
    }
}

const char* cwe_name_for(int id)
{
    switch (id)
    {
    case 22:  return "Path Traversal";
    case 78:  return "OS Command Injection";
    case 120: return "Buffer Copy without Checking Size of Input";
    case 129: return "Improper Validation of Array Index";
    case 134: return "Use of Externally-Controlled Format String";
    case 190: return "Integer Overflow or Wraparound";
    case 242: return "Use of Inherently Dangerous Function";
    case 415: return "Double Free";
    case 416: return "Use After Free";
    case 457: return "Use of Uninitialized Variable";
    case 770: return "Allocation of Resources Without Limits or Throttling";
    default:  return "Unknown CWE";
    }
}

std::string func_name_for(ea_t func_ea)
{
    qstring nm;
    if (get_func_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring vn;
    if (get_name(&vn, func_ea) > 0 && !vn.empty())
        return std::string(vn.c_str());
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << static_cast<std::uint64_t>(func_ea);
    return ss.str();
}

bool function_is_skippable(func_t* pfn)
{
    if (pfn == nullptr)
        return true;
    if ((pfn->flags & FUNC_THUNK) != 0)
        return true;
    if ((pfn->flags & FUNC_LIB) != 0)
        return true;
    return false;
}

int compute_cyclomatic_from_mba(const mba_t& mba)
{
    int nodes = 0;
    int edges = 0;
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        ++nodes;
        edges += static_cast<int>(blk->succset.size());
    }
    if (nodes <= 0)
        return 1;
    int cc = edges - nodes + 2;
    if (cc < 1)
        cc = 1;
    return cc;
}

int param_index_for_lvar(const mba_t& mba, int lvar_idx)
{
    if (lvar_idx < 0)
        return -1;
    for (size_t i = 0; i < mba.argidx.size(); ++i)
    {
        if (mba.argidx[i] == lvar_idx)
            return static_cast<int>(i);
    }
    return -1;
}

bool is_call_op(mcode_t op)
{
    return op == m_call || op == m_icall;
}

bool is_arith_op(mcode_t op)
{
    switch (op)
    {
    case m_add:
    case m_sub:
    case m_mul:
    case m_or:
    case m_and:
    case m_xor:
    case m_shl:
    case m_shr:
    case m_sar:
        return true;
    default:
        return false;
    }
}

bool is_overflow_arith(mcode_t op)
{
    return op == m_add || op == m_sub || op == m_mul;
}

bool is_move_op(mcode_t op)
{
    switch (op)
    {
    case m_mov:
    case m_xds:
    case m_xdu:
    case m_low:
    case m_high:
    case m_neg:
    case m_lnot:
    case m_bnot:
        return true;
    default:
        return false;
    }
}

bool resolve_callee_simple(const minsn_t& ins, std::string& callee_name, ea_t& callee_ea)
{
    callee_ea = BADADDR;
    callee_name.clear();
    return microcode::resolve_call_target(ins, callee_ea, callee_name);
}

bool collect_first_pointer_arg(const minsn_t& call_ins, mop_t& out_ptr)
{
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return false;
    const mcallargs_t& args = call_ins.d.f->args;
    if (args.empty())
        return false;
    out_ptr = static_cast<const mop_t&>(args[0]);
    return true;
}

int call_arg_count(const minsn_t& call_ins)
{
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return 0;
    return static_cast<int>(call_ins.d.f->args.size());
}

const mop_t* call_arg_at(const minsn_t& call_ins, int idx)
{
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return nullptr;
    const mcallargs_t& args = call_ins.d.f->args;
    if (idx < 0 || static_cast<size_t>(idx) >= args.size())
        return nullptr;
    return static_cast<const mop_t*>(&args[idx]);
}

// Slice C1 — per-lvar taint tag map. Replaces a bare unordered_set<int> with
// a richer per-lvar tag carrying the kind, a control-only flag, and the set of
// input-source callsite indices contributing to this lvar.
struct taint_set_t
{
    std::unordered_map<int, taint_tag_t> tainted_lvars;
    std::unordered_set<int>              tainted_param_indices;
    // Slice C2 — base_lvar_idx -> field offsets observed to be tainted via
    // m_ldx loads off an attacker-controlled struct base. Gated by
    // KERNEL_USERPTR_TAINT_FIELDS / function argument membership.
    std::unordered_map<int, std::unordered_set<int>> tainted_fields;
};

bool mop_is_tainted(const mop_t& op, const taint_set_t& ts)
{
    switch (op.t)
    {
    case mop_l:
        if (op.l != nullptr && ts.tainted_lvars.count(op.l->idx))
            return true;
        return false;
    case mop_d:
        if (op.d != nullptr)
        {
            if (mop_is_tainted(op.d->l, ts))
                return true;
            if (mop_is_tainted(op.d->r, ts))
                return true;
        }
        return false;
    case mop_a:
        if (op.a != nullptr)
            return mop_is_tainted(static_cast<const mop_t&>(*op.a), ts);
        return false;
    case mop_f:
        if (op.f != nullptr)
        {
            const mcallargs_t& args = op.f->args;
            for (size_t i = 0; i < args.size(); ++i)
            {
                if (mop_is_tainted(static_cast<const mop_t&>(args[i]), ts))
                    return true;
            }
        }
        return false;
    default:
        return false;
    }
}

// Slice C1 — return the dominant tag for the operand (used to propagate kind
// + callsite_idxs into the destination). Picks the first encountered tag.
const taint_tag_t* mop_first_tag(const mop_t& op, const taint_set_t& ts)
{
    switch (op.t)
    {
    case mop_l:
        if (op.l != nullptr)
        {
            auto it = ts.tainted_lvars.find(op.l->idx);
            if (it != ts.tainted_lvars.end())
                return &it->second;
        }
        return nullptr;
    case mop_d:
        if (op.d != nullptr)
        {
            const taint_tag_t* t = mop_first_tag(op.d->l, ts);
            if (t != nullptr) return t;
            return mop_first_tag(op.d->r, ts);
        }
        return nullptr;
    case mop_a:
        if (op.a != nullptr)
            return mop_first_tag(static_cast<const mop_t&>(*op.a), ts);
        return nullptr;
    case mop_f:
        if (op.f != nullptr)
        {
            const mcallargs_t& args = op.f->args;
            for (size_t i = 0; i < args.size(); ++i)
            {
                const taint_tag_t* t =
                    mop_first_tag(static_cast<const mop_t&>(args[i]), ts);
                if (t != nullptr) return t;
            }
        }
        return nullptr;
    default:
        return nullptr;
    }
}

// Slice C1 — merge two tags. Kind precedence: keep the higher specificity
// (anything > user_input > untainted). Callsite idxs union.
taint_tag_t merge_tags(const taint_tag_t& a, const taint_tag_t& b)
{
    taint_tag_t out;
    // Pick the non-user_input/untainted kind as dominant; otherwise prefer a.
    auto specificity = [](taint_kind_t k) -> int {
        if (k == taint_kind_t::untainted) return 0;
        if (k == taint_kind_t::user_input) return 1;
        return 2;
    };
    out.kind = specificity(b.kind) > specificity(a.kind) ? b.kind : a.kind;
    out.control_only = a.control_only && b.control_only;
    out.source_callsite_idxs = a.source_callsite_idxs;
    for (int x : b.source_callsite_idxs)
        out.source_callsite_idxs.insert(x);
    return out;
}

void collect_tainted_param_origins(const mop_t& op, const taint_set_t& ts, std::set<int>& origins)
{
    if (op.t == mop_l && op.l != nullptr)
    {
        if (ts.tainted_lvars.count(op.l->idx) && ts.tainted_param_indices.count(op.l->idx))
            origins.insert(op.l->idx);
        return;
    }
    if (op.t == mop_d && op.d != nullptr)
    {
        collect_tainted_param_origins(op.d->l, ts, origins);
        collect_tainted_param_origins(op.d->r, ts, origins);
        return;
    }
    if (op.t == mop_a && op.a != nullptr)
    {
        collect_tainted_param_origins(static_cast<const mop_t&>(*op.a), ts, origins);
        return;
    }
    if (op.t == mop_f && op.f != nullptr)
    {
        const mcallargs_t& args = op.f->args;
        for (size_t i = 0; i < args.size(); ++i)
            collect_tainted_param_origins(static_cast<const mop_t&>(args[i]), ts, origins);
    }
}

// Slice C1 — write the new tag into the destination lvar, merging with any
// existing tag at that lvar.
void taint_destination(const mop_t& d, taint_set_t& ts, const taint_tag_t& tag)
{
    if (d.t == mop_l && d.l != nullptr)
    {
        int idx = d.l->idx;
        auto it = ts.tainted_lvars.find(idx);
        if (it == ts.tainted_lvars.end())
            ts.tainted_lvars.emplace(idx, tag);
        else
            it->second = merge_tags(it->second, tag);
    }
}

// Convenience: taint destination using the dominant tag found in `src_op`.
// Falls back to a synthetic user_input tag if no tag is recoverable (paranoia).
void taint_destination_from(const mop_t& d, const mop_t& src_op, taint_set_t& ts)
{
    const taint_tag_t* base = mop_first_tag(src_op, ts);
    if (base != nullptr)
    {
        taint_destination(d, ts, *base);
    }
    else
    {
        taint_tag_t synth;
        synth.kind = taint_kind_t::user_input;
        taint_destination(d, ts, synth);
    }
}

void clear_destination_taint(const mop_t& d, taint_set_t& ts)
{
    if (d.t == mop_l && d.l != nullptr)
    {
        ts.tainted_lvars.erase(d.l->idx);
        ts.tainted_fields.erase(d.l->idx);
    }
}

class TaintCallGraph
{
public:
    void build()
    {
        m_callees.clear();
        m_callers.clear();
        const std::size_t fq = get_func_qty();
        for (std::size_t i = 0; i < fq; ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr)
                continue;
            xrefblk_t xb;
            for (bool ok = xb.first_to(pfn->start_ea, XREF_ALL); ok; ok = xb.next_to())
            {
                if (!xb.iscode)
                    continue;
                if (xb.type != fl_CN && xb.type != fl_CF)
                    continue;
                func_t* caller = get_func(xb.from);
                if (caller == nullptr)
                    continue;
                m_callees[caller->start_ea].push_back(pfn->start_ea);
                m_callers[pfn->start_ea].push_back(caller->start_ea);
            }
        }
        for (auto& kv : m_callees)
        {
            std::sort(kv.second.begin(), kv.second.end());
            kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
        }
        for (auto& kv : m_callers)
        {
            std::sort(kv.second.begin(), kv.second.end());
            kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
        }
    }

    const std::vector<ea_t>& callees_of(ea_t ea) const
    {
        static const std::vector<ea_t> empty;
        auto it = m_callees.find(ea);
        return it == m_callees.end() ? empty : it->second;
    }

    const std::vector<ea_t>& callers_of(ea_t ea) const
    {
        static const std::vector<ea_t> empty;
        auto it = m_callers.find(ea);
        return it == m_callers.end() ? empty : it->second;
    }

    std::vector<ea_t> topological_order(const std::vector<ea_t>& functions) const
    {
        std::unordered_set<ea_t> in_set(functions.begin(), functions.end());
        std::unordered_map<ea_t, int> color;
        std::vector<ea_t> ordered;
        ordered.reserve(functions.size());
        std::function<void(ea_t)> visit = [&](ea_t node) {
            if (in_set.count(node) == 0)
                return;
            int& c = color[node];
            if (c == 1 || c == 2)
                return;
            c = 1;
            const auto& callees = callees_of(node);
            for (ea_t cc : callees)
                visit(cc);
            c = 2;
            ordered.push_back(node);
        };
        for (ea_t f : functions)
            visit(f);
        return ordered;
    }

private:
    std::unordered_map<ea_t, std::vector<ea_t>> m_callees;
    std::unordered_map<ea_t, std::vector<ea_t>> m_callers;
};

struct intra_state_t
{
    taint_set_t                                     ts;
    std::set<int>                                   tainted_param_indices;
    std::set<int>                                   tainted_out_param_indices;
    bool                                            returns_tainted = false;
    bool                                            returns_alloc = false;
    bool                                            returns_free = false;
    std::set<std::string>                           sinks_reached;
    std::set<std::string>                           validators_called;
    std::set<std::string>                           allocs_called;
    std::set<std::string>                           frees_called;
    std::set<std::string>                           input_sources_called;
    std::set<int>                                   params_passed_to_sinks;
    std::set<int>                                   params_validated;
    std::set<int>                                   params_freed;
    std::vector<std::string>                        path_conditions;
    // Slice C3 — per-parameter sink/validator/kind accumulators that mirror the
    // func_summary_t extensions. Populated by process_call_taint.
    std::map<int, std::set<std::tuple<std::string, std::string, int>>>
                                                    param_sink_uses;
    std::map<int, std::set<std::string>>            param_validators_seen;
    std::map<int, std::set<taint_kind_t>>           param_inferred_kinds;
};

void initialize_param_taint(const mba_t& mba, intra_state_t& st)
{
    for (size_t i = 0; i < mba.argidx.size(); ++i)
    {
        int lvar_idx = mba.argidx[i];
        if (lvar_idx < 0)
            continue;
        taint_tag_t tag;
        tag.kind = taint_kind_t::user_input;
        // Parameter taint: callsite is the caller, recorded by the inter-pass.
        st.ts.tainted_lvars.emplace(lvar_idx, std::move(tag));
        st.ts.tainted_param_indices.insert(lvar_idx);
    }
}

// Slice C2 — On m_ldx (load) the offset operand may indicate a struct field
// load off a tainted base lvar. Match the field offset against the known
// kernel IRP field map; if it lands, propagate field-taint into the dest lvar.
// Only fire when the base lvar is a function parameter OR the field matches
// a KERNEL_USERPTR_TAINT_FIELDS pattern (gating per plan).
struct kernel_irp_field_t
{
    int                offset;
    std::string_view   name;
};

// IRP struct field offsets for x64 Windows (Vista+). Engine compares the
// numeric offset operand on m_ldx against this table; if the symbolic name of
// the field is later available, prefer substring match against the names
// listed in KERNEL_USERPTR_TAINT_FIELDS.
inline constexpr kernel_irp_field_t IRP_FIELD_OFFSETS_X64[] = {
    {0x18, "AssociatedIrp.SystemBuffer"},
    {0x08, "Irp->MdlAddress"},
    {0x20, "Irp->UserBuffer"},
};

const kernel_irp_field_t* lookup_irp_field_by_offset(int off)
{
    for (const auto& f : IRP_FIELD_OFFSETS_X64)
    {
        if (f.offset == off)
            return &f;
    }
    return nullptr;
}

bool field_name_is_kernel_userptr(const std::string& nm)
{
    if (nm.empty()) return false;
    const std::string n = ascii_lower(nm);
    for (const auto& sv : sig::KERNEL_USERPTR_TAINT_FIELDS)
    {
        const std::string s = ascii_lower(std::string(sv));
        if (n == s)
            return true;
        if (n.size() >= s.size() &&
            n.compare(n.size() - s.size(), s.size(), s) == 0)
            return true;
        if (s.size() >= n.size() &&
            s.compare(s.size() - n.size(), n.size(), n) == 0)
            return true;
        if (n.find(s) != std::string::npos || s.find(n) != std::string::npos)
            return true;
    }
    return false;
}

// Returns true if the m_ldx instruction loaded from a tainted struct base
// matched the gating criteria and the destination should be tainted.
bool propagate_struct_field_taint(const mba_t& mba, const minsn_t& ins, taint_set_t& ts)
{
    if (ins.opcode != m_ldx) return false;
    if (ins.d.t != mop_l || ins.d.l == nullptr) return false;
    // m_ldx layout: l=segment/selector, r=address mop. We look for r as an
    // mop_a wrapping a base+offset, or r=mop_d holding an m_add of base + imm.
    const mop_t& addr = ins.r;
    int        base_lvar_idx = -1;
    int        offset        = -1;
    std::string field_name;
    if (addr.t == mop_a && addr.a != nullptr)
    {
        const mop_t& base = static_cast<const mop_t&>(*addr.a);
        if (base.t == mop_l && base.l != nullptr)
        {
            base_lvar_idx = base.l->idx;
            offset = 0;
        }
    }
    else if (addr.t == mop_d && addr.d != nullptr && addr.d->opcode == m_add)
    {
        const mop_t& lo = addr.d->l;
        const mop_t& ro = addr.d->r;
        if (lo.t == mop_l && lo.l != nullptr && ro.t == mop_n)
        {
            base_lvar_idx = lo.l->idx;
            offset = static_cast<int>(ro.nnn != nullptr ? ro.nnn->value : 0);
        }
        else if (ro.t == mop_l && ro.l != nullptr && lo.t == mop_n)
        {
            base_lvar_idx = ro.l->idx;
            offset = static_cast<int>(lo.nnn != nullptr ? lo.nnn->value : 0);
        }
    }
    if (base_lvar_idx < 0) return false;

    auto base_tag_it = ts.tainted_lvars.find(base_lvar_idx);
    if (base_tag_it == ts.tainted_lvars.end())
        return false;

    bool base_is_param = false;
    for (size_t a = 0; a < mba.argidx.size(); ++a)
    {
        if (mba.argidx[a] == base_lvar_idx) { base_is_param = true; break; }
    }
    bool field_matches = false;
    if (offset >= 0)
    {
        const kernel_irp_field_t* fld = lookup_irp_field_by_offset(offset);
        if (fld != nullptr)
        {
            field_name.assign(fld->name);
            field_matches = field_name_is_kernel_userptr(field_name);
        }
    }
    if (!field_matches)
        return false;

    taint_tag_t new_tag = base_tag_it->second;
    new_tag.kind = base_is_param ? taint_kind_t::kernel_userptr : new_tag.kind;
    if (new_tag.kind == taint_kind_t::user_input ||
        new_tag.kind == taint_kind_t::kernel_irp_input ||
        new_tag.kind == taint_kind_t::untainted)
        new_tag.kind = taint_kind_t::kernel_userptr;
    new_tag.control_only = false;
    taint_destination(ins.d, ts, new_tag);
    if (offset >= 0)
        ts.tainted_fields[base_lvar_idx].insert(offset);
    return true;
}

void process_call_taint(mba_t& mba, minsn_t& ins, intra_state_t& st)
{
    std::string callee_name;
    ea_t callee_ea = BADADDR;
    const bool resolved = resolve_callee_simple(ins, callee_name, callee_ea);
    const funcrole_t call_role =
        (ins.d.t == mop_f && ins.d.f != nullptr) ? ins.d.f->role : ROLE_UNK;
    if (!resolved && call_role == ROLE_UNK)
        return;
    if (callee_name.empty() && call_role == ROLE_UNK)
        return;

    source_match_t source_match = find_input_source_match(callee_name);
    if (source_match.source != nullptr)
    {
        st.input_sources_called.insert(callee_name);
        const sig::source_signature_t* src = source_match.source;
        if (src != nullptr)
        {
            taint_tag_t tag;
            tag.kind = source_match.kind == taint_kind_t::user_input
                       ? kind_from_source_name(callee_name)
                       : source_match.kind;
            // Record callsite ea as a synthetic int id (low 32 bits of EA) so
            // downstream code can correlate without dragging the full EA into
            // every tag.
            tag.source_callsite_idxs.insert(static_cast<int>(ins.ea & 0xFFFFFFFFu));
            int idx = src->taint_arg_index;
            if (idx >= 0)
            {
                const mop_t* arg = call_arg_at(ins, idx);
                if (arg != nullptr && arg->t == mop_l && arg->l != nullptr)
                    taint_destination(*arg, st.ts, tag);
            }
            else
            {
                if (ins.d.t == mop_l && ins.d.l != nullptr)
                    taint_destination(ins.d, st.ts, tag);
            }
        }
    }

    sink_match_t sink = find_sink_signature(callee_name);
    if (!sink.matched() && call_role != ROLE_UNK)
        sink = sink_match_from_role(call_role);
    if (sink.matched())
    {
        const std::string observed_sink_name =
            callee_name.empty() ? std::string(sink_role_name(call_role)) : callee_name;
        st.sinks_reached.insert(observed_sink_name);
        const int n = call_arg_count(ins);
        for (int i = 0; i < n; ++i)
        {
            const mop_t* arg = call_arg_at(ins, i);
            if (arg == nullptr)
                continue;
            if (mop_is_tainted(*arg, st.ts))
            {
                std::set<int> origins;
                collect_tainted_param_origins(*arg, st.ts, origins);
                for (int oi : origins)
                {
                    int p_idx = param_index_for_lvar(mba, oi);
                    if (p_idx >= 0)
                    {
                        st.params_passed_to_sinks.insert(p_idx);
                        // Slice C3 — per-param sink_use record.
                        st.param_sink_uses[p_idx].emplace(
                            std::make_tuple(observed_sink_name, sink.category, i));
                        // Carry forward kind inference.
                        auto it = st.ts.tainted_lvars.find(oi);
                        if (it != st.ts.tainted_lvars.end())
                            st.param_inferred_kinds[p_idx].insert(it->second.kind);
                    }
                }
            }
        }
    }

    if (is_validator_name(callee_name))
    {
        st.validators_called.insert(callee_name);
        const int n = call_arg_count(ins);
        for (int i = 0; i < n; ++i)
        {
            const mop_t* arg = call_arg_at(ins, i);
            if (arg == nullptr)
                continue;
            if (arg->t == mop_l && arg->l != nullptr)
            {
                int idx = arg->l->idx;
                int p_idx = param_index_for_lvar(mba, idx);
                if (p_idx >= 0)
                {
                    st.params_validated.insert(p_idx);
                    st.param_validators_seen[p_idx].insert(callee_name);
                }
            }
        }
    }

    // Slice C3 — also record LENGTH_VALIDATOR_HELPERS / AUTH_GATE_HELPERS as
    // per-parameter validator events. These overlap KERNEL_VALIDATORS but the
    // signature arrays are distinct.
    for (const auto& v : sig::LENGTH_VALIDATOR_HELPERS)
    {
        if (name_matches_signature(callee_name, v))
        {
            const int n = call_arg_count(ins);
            for (int i = 0; i < n; ++i)
            {
                const mop_t* arg = call_arg_at(ins, i);
                if (arg == nullptr || arg->t != mop_l || arg->l == nullptr)
                    continue;
                int p_idx = param_index_for_lvar(mba, arg->l->idx);
                if (p_idx >= 0)
                    st.param_validators_seen[p_idx].insert(callee_name);
            }
            break;
        }
    }
    for (const auto& v : sig::AUTH_GATE_HELPERS)
    {
        if (name_matches_signature(callee_name, v))
        {
            const int n = call_arg_count(ins);
            for (int i = 0; i < n; ++i)
            {
                const mop_t* arg = call_arg_at(ins, i);
                if (arg == nullptr || arg->t != mop_l || arg->l == nullptr)
                    continue;
                int p_idx = param_index_for_lvar(mba, arg->l->idx);
                if (p_idx >= 0)
                    st.param_validators_seen[p_idx].insert(callee_name);
            }
            break;
        }
    }

    if (is_alloc_name(callee_name))
    {
        st.allocs_called.insert(callee_name);
        if (ins.d.t == mop_l && ins.d.l != nullptr)
            st.ts.tainted_lvars.erase(ins.d.l->idx);
    }

    if (is_free_name(callee_name))
    {
        st.frees_called.insert(callee_name);
        const mop_t* arg0 = call_arg_at(ins, 0);
        if (arg0 != nullptr && arg0->t == mop_l && arg0->l != nullptr)
        {
            int idx = arg0->l->idx;
            int p_idx = param_index_for_lvar(mba, idx);
            if (p_idx >= 0)
                st.params_freed.insert(p_idx);
        }
    }
}

void process_arith_taint(minsn_t& ins, intra_state_t& st)
{
    bool l_t = mop_is_tainted(ins.l, st.ts);
    bool r_t = mop_is_tainted(ins.r, st.ts);
    if (l_t || r_t)
        taint_destination_from(ins.d, l_t ? ins.l : ins.r, st.ts);
}

void process_move_taint(minsn_t& ins, intra_state_t& st)
{
    if (mop_is_tainted(ins.l, st.ts))
        taint_destination_from(ins.d, ins.l, st.ts);
    else
        clear_destination_taint(ins.d, st.ts);
}

void process_load_taint(mba_t& mba, minsn_t& ins, intra_state_t& st)
{
    propagate_struct_field_taint(mba, ins, st.ts);
}

void process_store_taint(minsn_t& ins, intra_state_t& st, mba_t& mba)
{
    if (!mop_is_tainted(ins.l, st.ts))
        return;
    std::set<int> origins;
    collect_tainted_param_origins(ins.l, st.ts, origins);
    for (int oi : origins)
    {
        int p_idx = param_index_for_lvar(mba, oi);
        if (p_idx >= 0)
            st.tainted_out_param_indices.insert(p_idx);
    }
    if (ins.d.t == mop_a && ins.d.a != nullptr)
    {
        const mop_t& base = static_cast<const mop_t&>(*ins.d.a);
        if (base.t == mop_l && base.l != nullptr)
        {
            int p_idx = param_index_for_lvar(mba, base.l->idx);
            if (p_idx >= 0)
                st.tainted_out_param_indices.insert(p_idx);
        }
    }
}

void process_return_taint(minsn_t& ins, intra_state_t& st)
{
    if (mop_is_tainted(ins.l, st.ts))
        st.returns_tainted = true;
}

void process_branch_condition(const minsn_t& ins, intra_state_t& st)
{
    if (!is_mcode_jcond(ins.opcode))
        return;
    qstring qs;
    ins.print(&qs, SHINS_SHORT | SHINS_VALNUM);
    qstring clean;
    tag_remove(&clean, qs);
    if (clean.length() > 0)
        st.path_conditions.emplace_back(clean.c_str());
}

void process_instruction(mba_t& mba, minsn_t& ins, intra_state_t& st)
{
    if (is_call_op(ins.opcode))
    {
        process_call_taint(mba, ins, st);
        return;
    }
    if (is_arith_op(ins.opcode))
    {
        process_arith_taint(ins, st);
        return;
    }
    if (is_move_op(ins.opcode))
    {
        process_move_taint(ins, st);
        return;
    }
    if (ins.opcode == m_ldx)
    {
        process_load_taint(mba, ins, st);
        return;
    }
    if (ins.opcode == m_stx)
    {
        process_store_taint(ins, st, mba);
        return;
    }
    if (ins.opcode == m_ret)
    {
        process_return_taint(ins, st);
        return;
    }
    process_branch_condition(ins, st);
}

void run_intraprocedural_analysis(mba_t& mba, intra_state_t& st)
{
    initialize_param_taint(mba, st);
    for (int idx : st.ts.tainted_param_indices)
    {
        int p_idx = param_index_for_lvar(mba, idx);
        if (p_idx >= 0)
            st.tainted_param_indices.insert(p_idx);
    }
    for (int b = 0; b < mba.qty && b < kMaxBlocksPerFunction; ++b)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
        if (blk == nullptr)
            continue;
        // Slice C1 — detect a control_only block: tail mcode is a jcond and
        // none of the body instructions write to a non-jcond destination. We
        // approximate by tagging any destinations written in jcond-only tail
        // blocks. The cheaper approximation used here is: after running the
        // block, if its tail is a jcond and the block's only outputs are
        // condition results, flag the live taints with control_only=true.
        const bool tail_is_jcond =
            (blk->tail != nullptr && is_mcode_jcond(blk->tail->opcode));
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            process_instruction(mba, *m, st);
        if (tail_is_jcond)
        {
            // Heuristic: do nothing destructive here — control_only is set on
            // tags newly produced by this block's jcond consumers. The richer
            // per-instruction analysis lives in propagate_struct_field_taint
            // and process_call_taint. This block is intentionally a no-op so
            // future passes can refine without changing call-site semantics.
        }
    }
    // Slice C3 — drain accumulator state into the intra_state_t fields.
    // (process_call_taint wrote directly into st.param_*; nothing else to do
    // here, but keep this comment as the canonical home for any future joins.)
}

ea_t containing_func_ea(ea_t ea)
{
    func_t* pfn = get_func(ea);
    if (pfn == nullptr)
        return BADADDR;
    return pfn->start_ea;
}

std::vector<ea_t> walk_call_to_in_func(ea_t func_ea, ea_t target_func_ea)
{
    std::vector<ea_t> out;
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;
    func_item_iterator_t fii(pfn);
    for (bool ok = fii.first(); ok; ok = fii.next_head())
    {
        ea_t cur = fii.current();
        xrefblk_t xb;
        for (bool ix = xb.first_from(cur, XREF_ALL); ix; ix = xb.next_from())
        {
            if (!xb.iscode)
                continue;
            if (xb.type != fl_CN && xb.type != fl_CF)
                continue;
            ea_t to = xb.to;
            if (to == target_func_ea)
            {
                out.push_back(cur);
                break;
            }
            func_t* tgt = get_func(to);
            if (tgt != nullptr && tgt->start_ea == target_func_ea)
            {
                out.push_back(cur);
                break;
            }
        }
    }
    return out;
}

bool intraprocedural_taint_reaches(mba_t& mba, ea_t source_ea, ea_t sink_ea,
                                   std::vector<std::string>& conditions,
                                   int& sink_arg_index_out,
                                   std::string& sink_name_out,
                                   std::string& source_name_out,
                                   taint_kind_t& kind_out)
{
    sink_arg_index_out = -1;
    bool taint_started = false;
    bool reached = false;
    taint_set_t ts;

    auto seed_tag = [&](taint_kind_t k, ea_t src_ea) {
        taint_tag_t t;
        t.kind = k;
        t.source_callsite_idxs.insert(static_cast<int>(src_ea & 0xFFFFFFFFu));
        return t;
    };

    for (int b = 0; b < mba.qty && !reached; ++b)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
        if (blk == nullptr)
            continue;
        for (minsn_t* m = blk->head; m != nullptr && !reached; m = m->next)
        {
            if (m->ea == source_ea && is_call_op(m->opcode))
            {
                std::string nm;
                ea_t ce = BADADDR;
                if (resolve_callee_simple(*m, nm, ce))
                {
                    source_match_t srcm = find_input_source_match(nm);
                    if (srcm.source != nullptr)
                    {
                        source_name_out = nm;
                        kind_out = srcm.kind == taint_kind_t::user_input
                                   ? kind_from_source_name(nm)
                                   : srcm.kind;
                        const sig::source_signature_t* src = srcm.source;
                        if (src != nullptr)
                        {
                            taint_tag_t tag = seed_tag(kind_out, m->ea);
                            int idx = src->taint_arg_index;
                            if (idx >= 0)
                            {
                                const mop_t* arg = call_arg_at(*m, idx);
                                if (arg != nullptr && arg->t == mop_l && arg->l != nullptr)
                                    taint_destination(*arg, ts, tag);
                            }
                            else if (m->d.t == mop_l && m->d.l != nullptr)
                            {
                                taint_destination(m->d, ts, tag);
                            }
                        }
                        taint_started = true;
                        continue;
                    }
                }
            }

            if (!taint_started)
                continue;

            if (m->ea == sink_ea && is_call_op(m->opcode))
            {
                std::string nm;
                ea_t ce = BADADDR;
                const bool resolved = resolve_callee_simple(*m, nm, ce);
                const funcrole_t call_role =
                    (m->d.t == mop_f && m->d.f != nullptr) ? m->d.f->role : ROLE_UNK;
                if (resolved || call_role != ROLE_UNK)
                {
                    sink_match_t sm = find_sink_signature(nm);
                    if (!sm.matched() && call_role != ROLE_UNK)
                        sm = sink_match_from_role(call_role);
                    if (sm.matched())
                    {
                        sink_name_out = nm.empty() ? std::string(sink_role_name(call_role)) : nm;
                        const int n = call_arg_count(*m);
                        for (int i = 0; i < n; ++i)
                        {
                            const mop_t* arg = call_arg_at(*m, i);
                            if (arg == nullptr)
                                continue;
                            if (mop_is_tainted(*arg, ts))
                            {
                                sink_arg_index_out = i;
                                reached = true;
                                break;
                            }
                        }
                    }
                }
                if (reached)
                    break;
            }

            if (is_call_op(m->opcode))
            {
                std::string nm;
                ea_t ce = BADADDR;
                if (resolve_callee_simple(*m, nm, ce))
                {
                    source_match_t srcm = find_input_source_match(nm);
                    if (srcm.source != nullptr)
                    {
                        const sig::source_signature_t* src = srcm.source;
                        if (src != nullptr)
                        {
                            taint_kind_t source_kind = srcm.kind == taint_kind_t::user_input
                                                       ? kind_from_source_name(nm)
                                                       : srcm.kind;
                            taint_tag_t tag = seed_tag(source_kind, m->ea);
                            int idx = src->taint_arg_index;
                            if (idx >= 0)
                            {
                                const mop_t* arg = call_arg_at(*m, idx);
                                if (arg != nullptr && arg->t == mop_l && arg->l != nullptr)
                                    taint_destination(*arg, ts, tag);
                            }
                            else if (m->d.t == mop_l && m->d.l != nullptr)
                            {
                                taint_destination(m->d, ts, tag);
                            }
                        }
                    }
                    if (is_alloc_name(nm))
                    {
                        if (m->d.t == mop_l && m->d.l != nullptr)
                        {
                            ts.tainted_lvars.erase(m->d.l->idx);
                            ts.tainted_fields.erase(m->d.l->idx);
                        }
                    }
                    continue;
                }
            }

            if (is_arith_op(m->opcode))
            {
                bool l_t = mop_is_tainted(m->l, ts);
                bool r_t = mop_is_tainted(m->r, ts);
                if (l_t || r_t)
                    taint_destination_from(m->d, l_t ? m->l : m->r, ts);
                continue;
            }
            if (is_move_op(m->opcode))
            {
                if (mop_is_tainted(m->l, ts))
                    taint_destination_from(m->d, m->l, ts);
                else
                    clear_destination_taint(m->d, ts);
                continue;
            }
            if (m->opcode == m_ldx)
            {
                propagate_struct_field_taint(mba, *m, ts);
                continue;
            }
            if (is_mcode_jcond(m->opcode))
            {
                qstring qs;
                m->print(&qs, SHINS_SHORT | SHINS_VALNUM);
                qstring clean;
                tag_remove(&clean, qs);
                if (clean.length() > 0)
                    conditions.emplace_back(clean.c_str());
            }
        }
    }

    return reached;
}

severity_t severity_from_vulnerability_label(const std::string& label)
{
    if (label == "buffer_overflow") return severity_t::high;
    if (label == "command_injection") return severity_t::high;
    if (label == "format_string") return severity_t::high;
    if (label == "integer_overflow") return severity_t::high;
    if (label == "use_after_free") return severity_t::high;
    if (label == "double_free") return severity_t::high;
    if (label == "path_traversal") return severity_t::medium;
    if (label == "uninitialized_use") return severity_t::medium;
    return severity_t::medium;
}

}

nlohmann::json to_json(const taint_path_t& p)
{
    nlohmann::json j;
    nlohmann::json origin;
    origin["source_ea"]      = ea_to_hex(p.origin.source_ea);
    origin["source_func_ea"] = ea_to_hex(p.origin.source_func_ea);
    origin["source_name"]    = p.origin.source_name;
    origin["kind"]           = taint_kind_str(p.origin.kind);
    j["origin"] = std::move(origin);

    j["sink_ea"]        = ea_to_hex(p.sink_ea);
    j["sink_func_ea"]   = ea_to_hex(p.sink_func_ea);
    j["sink_name"]      = p.sink_name;
    j["sink_arg_index"] = p.sink_arg_index;

    nlohmann::json steps = nlohmann::json::array();
    for (const auto& st : p.steps)
    {
        nlohmann::json sj;
        sj["ea"]          = ea_to_hex(st.ea);
        sj["func_ea"]     = ea_to_hex(st.func_ea);
        sj["func_name"]   = st.func_name;
        sj["description"] = st.description;
        sj["condition"]   = st.condition;
        steps.push_back(std::move(sj));
    }
    j["steps"] = std::move(steps);

    nlohmann::json conds = nlohmann::json::array();
    for (const auto& c : p.conditions)
        conds.push_back(c);
    j["conditions"] = std::move(conds);

    nlohmann::json validators = nlohmann::json::array();
    for (const auto& v : p.validator_chain)
        validators.push_back(v);
    j["validator_chain"] = std::move(validators);

    j["vulnerability_type"] = p.vulnerability_type;
    j["severity"]           = severity_str(p.severity);
    j["confidence"]         = confidence_str(p.confidence);
    return j;
}

TaintEngine::TaintEngine() {}
TaintEngine::~TaintEngine() {}

void TaintEngine::clear()
{
    m_summaries.clear();
    m_forward_reach.clear();
    m_backward_reach.clear();
    m_analyzed = false;
}

void TaintEngine::analyze_function(ea_t func_ea)
{
    func_summary_t sum;
    sum.func_ea = func_ea;
    compute_summary(func_ea, sum);
    m_summaries[func_ea] = std::move(sum);
}

void TaintEngine::compute_summary(ea_t func_ea, func_summary_t& sum)
{
    sum.func_ea = func_ea;
    sum.name    = func_name_for(func_ea);

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr || function_is_skippable(pfn))
        return;

    if (!ida_utils::is_safely_decompilable(pfn))
        return;

    auto handle = microcode::generate(func_ea, MMAT_LVARS);
    if (!handle.has_value() || !handle->mba)
        return;

    mba_t& mba = *handle->mba;
    sum.cyclomatic = compute_cyclomatic_from_mba(mba);

    intra_state_t st;
    run_intraprocedural_analysis(mba, st);

    sum.tainted_param_indices.insert(st.tainted_param_indices.begin(), st.tainted_param_indices.end());
    sum.tainted_out_param_indices.insert(st.tainted_out_param_indices.begin(), st.tainted_out_param_indices.end());
    sum.returns_tainted = st.returns_tainted;
    sum.sinks_reached = std::move(st.sinks_reached);
    sum.validators_called = std::move(st.validators_called);
    sum.allocs_called = std::move(st.allocs_called);
    sum.frees_called = std::move(st.frees_called);
    sum.input_sources_called = std::move(st.input_sources_called);
    sum.params_passed_to_sinks = std::move(st.params_passed_to_sinks);
    sum.params_validated = std::move(st.params_validated);
    sum.params_freed = std::move(st.params_freed);
    sum.returns_alloc = !sum.allocs_called.empty();
    sum.returns_free = !sum.frees_called.empty();
    // Slice C3 — per-parameter metadata populated by process_call_taint.
    sum.param_sink_uses        = std::move(st.param_sink_uses);
    sum.param_validators_seen  = std::move(st.param_validators_seen);
    sum.param_inferred_kinds   = std::move(st.param_inferred_kinds);
    for (const auto& kv : st.ts.tainted_fields)
        sum.tainted_fields[kv.first].insert(kv.second.begin(), kv.second.end());
    sum.analyzed = true;
}

std::vector<ea_t> TaintEngine::caller_eas(ea_t callee_ea) const
{
    std::vector<ea_t> out;
    if (callee_ea == BADADDR)
        return out;
    xrefblk_t xb;
    std::unordered_set<ea_t> seen;
    for (bool ok = xb.first_to(callee_ea, XREF_ALL); ok; ok = xb.next_to())
    {
        if (!xb.iscode)
            continue;
        if (xb.type != fl_CN && xb.type != fl_CF)
            continue;
        func_t* caller = get_func(xb.from);
        if (caller == nullptr)
            continue;
        if (seen.insert(caller->start_ea).second)
            out.push_back(caller->start_ea);
    }
    std::sort(out.begin(), out.end());
    return out;
}

void TaintEngine::analyze_all()
{
    m_summaries.clear();
    m_forward_reach.clear();
    m_backward_reach.clear();
    m_analyzed = false;

    std::vector<ea_t> functions;
    const std::size_t fq = get_func_qty();
    functions.reserve(fq);
    int analyzed_count = 0;
    for (std::size_t i = 0; i < fq && analyzed_count < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        functions.push_back(pfn->start_ea);
        ++analyzed_count;
    }

    TaintCallGraph cg;
    cg.build();

    std::vector<ea_t> ordered = cg.topological_order(functions);
    if (ordered.empty())
        ordered = functions;

    for (int iter = 0; iter < kMaxFixpointIterations; ++iter)
    {
        bool changed = false;
        for (ea_t fea : ordered)
        {
            func_summary_t prev;
            auto it = m_summaries.find(fea);
            if (it != m_summaries.end())
                prev = it->second;
            func_summary_t sum;
            sum.func_ea = fea;
            compute_summary(fea, sum);
            if (!prev.analyzed ||
                prev.tainted_param_indices != sum.tainted_param_indices ||
                prev.tainted_out_param_indices != sum.tainted_out_param_indices ||
                prev.returns_tainted != sum.returns_tainted ||
                prev.sinks_reached != sum.sinks_reached ||
                prev.input_sources_called != sum.input_sources_called ||
                prev.tainted_fields != sum.tainted_fields)
            {
                changed = true;
            }
            m_summaries[fea] = std::move(sum);
        }
        if (!changed)
            break;
    }

    m_analyzed = true;
    build_reachability_index(8);
}

const func_summary_t* TaintEngine::get_summary(ea_t func_ea) const
{
    auto it = m_summaries.find(func_ea);
    if (it == m_summaries.end())
        return nullptr;
    return &it->second;
}

std::vector<func_summary_t> TaintEngine::get_all_summaries() const
{
    std::vector<func_summary_t> out;
    out.reserve(m_summaries.size());
    for (const auto& kv : m_summaries)
        out.push_back(kv.second);
    return out;
}

std::vector<taint_path_t> TaintEngine::trace_paths(ea_t source_ea, ea_t sink_ea,
                                                   int max_paths, int max_depth)
{
    std::vector<taint_path_t> out;
    if (max_paths <= 0)
        max_paths = 1;
    if (max_paths > 64)
        max_paths = 64;
    if (max_depth <= 0)
        max_depth = 1;
    if (max_depth > 16)
        max_depth = 16;

    if (!m_analyzed)
        analyze_all();

    ea_t source_func_ea = containing_func_ea(source_ea);
    ea_t sink_func_ea   = containing_func_ea(sink_ea);
    if (source_func_ea == BADADDR || sink_func_ea == BADADDR)
        return out;

    if (source_func_ea == sink_func_ea)
    {
        auto handle = microcode::generate(source_func_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            return out;
        std::vector<std::string> conditions;
        int sink_arg_index = -1;
        std::string sink_name;
        std::string source_name;
        taint_kind_t kind = taint_kind_t::user_input;
        if (intraprocedural_taint_reaches(*handle->mba, source_ea, sink_ea,
                                          conditions, sink_arg_index, sink_name,
                                          source_name, kind))
        {
            taint_path_t p;
            p.origin.source_ea      = source_ea;
            p.origin.source_func_ea = source_func_ea;
            p.origin.source_name    = source_name.empty() ? func_name_for(source_func_ea) : source_name;
            p.origin.kind           = kind;
            p.sink_ea       = sink_ea;
            p.sink_func_ea  = sink_func_ea;
            p.sink_name     = sink_name.empty() ? func_name_for(sink_func_ea) : sink_name;
            p.sink_arg_index = sink_arg_index;
            taint_path_step_t s;
            s.ea          = sink_ea;
            s.func_ea     = source_func_ea;
            s.func_name   = func_name_for(source_func_ea);
            s.description = std::string("intraprocedural taint flow");
            s.condition.clear();
            p.steps.push_back(std::move(s));
            p.conditions = std::move(conditions);
            p.validator_chain = path_sensitive_sanitizer_gate(source_func_ea, source_ea, sink_ea);
            sink_match_t sm = find_sink_signature(p.sink_name);
            int cwe = sm.matched() ? sm.primary_cwe : 0;
            p.vulnerability_type = vulnerability_label_from_cwe(cwe);
            p.severity   = severity_from_vulnerability_label(p.vulnerability_type);
            p.confidence = confidence_t::likely;
            out.push_back(std::move(p));
        }
        return out;
    }

    TaintCallGraph cg;
    cg.build();

    struct frame_t
    {
        ea_t                              func_ea;
        std::vector<taint_path_step_t>    steps;
        std::vector<std::string>          conditions;
        std::set<ea_t>                    visited;
    };

    std::deque<frame_t> queue;
    frame_t start;
    start.func_ea = source_func_ea;
    start.visited.insert(source_func_ea);
    taint_path_step_t s0;
    s0.ea          = source_ea;
    s0.func_ea     = source_func_ea;
    s0.func_name   = func_name_for(source_func_ea);
    s0.description = std::string("input source observed");
    start.steps.push_back(std::move(s0));
    queue.push_back(std::move(start));

    std::string sink_name_for_path;
    sink_match_t sm0 = find_sink_signature(func_name_for(sink_func_ea));
    int sink_arg_index_for_path = -1;
    int sink_cwe = 0;
    if (sm0.matched())
    {
        sink_name_for_path = sm0.sink != nullptr
                             ? std::string(sm0.sink->name)
                             : sm0.category;
        sink_cwe = sm0.primary_cwe;
        sink_arg_index_for_path = sm0.len_arg_index >= 0 ? sm0.len_arg_index : 0;
    }

    std::string source_name_for_path = func_name_for(source_func_ea);
    taint_kind_t kind_for_path = kind_from_source_name(source_name_for_path);

    while (!queue.empty() && static_cast<int>(out.size()) < max_paths)
    {
        frame_t cur = std::move(queue.front());
        queue.pop_front();

        if (cur.func_ea == sink_func_ea)
        {
            taint_path_t p;
            p.origin.source_ea      = source_ea;
            p.origin.source_func_ea = source_func_ea;
            p.origin.source_name    = source_name_for_path;
            p.origin.kind           = kind_for_path;
            p.sink_ea       = sink_ea;
            p.sink_func_ea  = sink_func_ea;
            p.sink_name     = sink_name_for_path.empty() ? func_name_for(sink_func_ea) : sink_name_for_path;
            p.sink_arg_index = sink_arg_index_for_path;
            p.steps      = cur.steps;
            p.conditions = cur.conditions;
            p.vulnerability_type = vulnerability_label_from_cwe(sink_cwe);
            p.severity   = severity_from_vulnerability_label(p.vulnerability_type);
            const auto* sum = get_summary(cur.func_ea);
            if (sum != nullptr)
                p.validator_chain.assign(sum->validators_called.begin(), sum->validators_called.end());
            p.confidence = (sum != nullptr && !sum->validators_called.empty())
                            ? confidence_t::plausible : confidence_t::likely;
            out.push_back(std::move(p));
            continue;
        }

        if (static_cast<int>(cur.steps.size()) >= max_depth)
            continue;

        const auto& callees = cg.callees_of(cur.func_ea);
        for (ea_t next_ea : callees)
        {
            if (cur.visited.count(next_ea))
                continue;
            const auto* nsum = get_summary(next_ea);
            if (next_ea != sink_func_ea)
            {
                if (nsum == nullptr)
                    continue;
                if (nsum->tainted_param_indices.empty() &&
                    nsum->tainted_out_param_indices.empty() &&
                    nsum->sinks_reached.empty() &&
                    !nsum->returns_tainted)
                    continue;
            }
            std::vector<ea_t> call_eas = walk_call_to_in_func(cur.func_ea, next_ea);
            ea_t hop_ea = call_eas.empty() ? BADADDR : call_eas.front();
            frame_t nf = cur;
            nf.func_ea = next_ea;
            nf.visited.insert(next_ea);
            taint_path_step_t st;
            st.ea          = hop_ea;
            st.func_ea     = next_ea;
            st.func_name   = func_name_for(next_ea);
            st.description = std::string("call hop from ") + func_name_for(cur.func_ea) +
                              std::string(" to ") + st.func_name;
            nf.steps.push_back(std::move(st));
            queue.push_back(std::move(nf));
            if (static_cast<int>(queue.size()) > max_paths * 8)
                break;
        }
    }

    return out;
}

std::vector<taint_path_t> TaintEngine::trace_paths_from_source(ea_t source_ea,
                                                                int max_paths,
                                                                int max_depth)
{
    std::vector<taint_path_t> out;
    if (max_paths <= 0)
        max_paths = 1;
    if (max_paths > 64)
        max_paths = 64;
    if (!m_analyzed)
        analyze_all();

    std::vector<std::string> sink_names;
    sink_names.reserve(64);
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
        sink_names.emplace_back(s.name);
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        sink_names.emplace_back(s.name);
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
        sink_names.emplace_back(s.name);
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        sink_names.emplace_back(s.name);
    std::sort(sink_names.begin(), sink_names.end());
    sink_names.erase(std::unique(sink_names.begin(), sink_names.end()), sink_names.end());

    std::unordered_set<ea_t> sink_eas;
    for (const auto& nm : sink_names)
    {
        ea_t e = get_name_ea(BADADDR, nm.c_str());
        if (e != BADADDR)
            sink_eas.insert(e);
    }

    for (ea_t sink_ea : sink_eas)
    {
        if (static_cast<int>(out.size()) >= max_paths)
            break;
        auto found = trace_paths(source_ea, sink_ea, max_paths - static_cast<int>(out.size()),
                                 max_depth);
        for (auto& p : found)
        {
            if (static_cast<int>(out.size()) >= max_paths)
                break;
            out.push_back(std::move(p));
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_uaf_candidates(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode))
                    continue;
                std::string nm;
                ea_t ce = BADADDR;
                if (!resolve_callee_simple(*m, nm, ce))
                    continue;
                if (!is_free_name(nm) || is_realloc_name(nm))
                    continue;
                mop_t ptr;
                ptr.zero();
                if (!collect_first_pointer_arg(*m, ptr))
                    continue;
                ea_t free_ea = BADADDR;
                ea_t use_ea  = BADADDR;
                if (!microcode::is_freed_then_used(mba, ptr, free_ea, use_ea))
                    continue;
                if (free_ea == BADADDR || use_ea == BADADDR)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/uaf/" << std::hex << std::uppercase << static_cast<std::uint64_t>(use_ea);
                f.id = id.str();
                f.primary_ea = use_ea;
                f.related_eas.push_back(free_ea);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 416;
                c.name = cwe_name_for(416);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::likely;
                std::ostringstream tt;
                tt << "Use-after-free in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer freed at " << ea_to_hex(free_ea)
                    << " is dereferenced or passed to another sink at "
                    << ea_to_hex(use_ea) << " without an intervening reassignment.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["free_ea"] = ea_to_hex(free_ea);
                ev["use_ea"]  = ea_to_hex(use_ea);
                ev["func_ea"] = ea_to_hex(pfn->start_ea);
                ev["callee"]  = nm;
                ev["ptr"]     = microcode::mop_describe(ptr);
                f.evidence    = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_double_free_candidates(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode))
                    continue;
                std::string nm;
                ea_t ce = BADADDR;
                if (!resolve_callee_simple(*m, nm, ce))
                    continue;
                if (!is_free_name(nm) || is_realloc_name(nm))
                    continue;
                mop_t ptr;
                ptr.zero();
                if (!collect_first_pointer_arg(*m, ptr))
                    continue;
                ea_t free1 = BADADDR;
                ea_t free2 = BADADDR;
                if (!microcode::is_double_freed(mba, ptr, free1, free2))
                    continue;
                if (free1 == BADADDR || free2 == BADADDR)
                    continue;
                if (free1 != m->ea)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/double_free/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(free2);
                f.id = id.str();
                f.primary_ea = free2;
                f.related_eas.push_back(free1);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 415;
                c.name = cwe_name_for(415);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::likely;
                std::ostringstream tt;
                tt << "Double free in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer freed at " << ea_to_hex(free1)
                    << " is freed again at " << ea_to_hex(free2)
                    << " without an intervening reassignment.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["first_free_ea"]  = ea_to_hex(free1);
                ev["second_free_ea"] = ea_to_hex(free2);
                ev["func_ea"]        = ea_to_hex(pfn->start_ea);
                ev["callee"]         = nm;
                ev["ptr"]            = microcode::mop_describe(ptr);
                f.evidence           = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_use_after_realloc(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode))
                    continue;
                std::string nm;
                ea_t ce = BADADDR;
                if (!resolve_callee_simple(*m, nm, ce))
                    continue;
                if (!is_realloc_name(nm))
                    continue;
                mop_t input_ptr;
                input_ptr.zero();
                if (!collect_first_pointer_arg(*m, input_ptr))
                    continue;

                ea_t free_ea = BADADDR;
                ea_t use_ea  = BADADDR;
                if (!microcode::is_freed_then_used(mba, input_ptr, free_ea, use_ea))
                    continue;
                if (use_ea == BADADDR || use_ea == m->ea)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/use_after_realloc/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(use_ea);
                f.id = id.str();
                f.primary_ea = use_ea;
                f.related_eas.push_back(m->ea);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 416;
                c.name = cwe_name_for(416);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "Use after realloc in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Pointer reallocated at " << ea_to_hex(m->ea)
                    << " is dereferenced via the original handle at " << ea_to_hex(use_ea)
                    << " without checking whether realloc returned a new pointer.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["realloc_ea"] = ea_to_hex(m->ea);
                ev["use_ea"]     = ea_to_hex(use_ea);
                ev["func_ea"]    = ea_to_hex(pfn->start_ea);
                ev["callee"]     = nm;
                ev["ptr"]        = microcode::mop_describe(input_ptr);
                f.evidence       = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_uninit_use(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;

        std::unordered_set<int> param_lvars;
        for (size_t a = 0; a < mba.argidx.size(); ++a)
            param_lvars.insert(mba.argidx[a]);

        std::size_t per_func = 0;
        for (size_t v = 0; v < mba.vars.size() && per_func < kMaxFreedTrackingPerFunc; ++v)
        {
            int idx = static_cast<int>(v);
            if (param_lvars.count(idx))
                continue;
            const lvar_t& lv = mba.vars[v];
            int width = lv.width > 0 ? lv.width : 1;
            mop_t synth;
            synth._make_lvar(&mba, idx, 0);
            synth.size = width;
            ea_t read_ea = BADADDR;
            if (!microcode::has_uninit_read(mba, synth, read_ea))
                continue;
            if (read_ea == BADADDR)
                continue;

            vuln_finding_t f;
            std::ostringstream id;
            id << "vuln/uninit/" << std::hex << std::uppercase << static_cast<std::uint64_t>(read_ea);
            f.id = id.str();
            f.primary_ea = read_ea;
            f.related_eas.push_back(pfn->start_ea);
            cwe_t c;
            c.id = 457;
            c.name = cwe_name_for(457);
            f.cwes.push_back(c);
            f.severity   = severity_t::medium;
            f.confidence = confidence_t::plausible;
            std::ostringstream tt;
            std::string vname = lv.name.empty() ? std::string("v") + std::to_string(idx) : std::string(lv.name.c_str());
            tt << "Uninitialized read of " << vname << " in " << func_name_for(pfn->start_ea);
            f.title = tt.str();
            std::ostringstream rat;
            rat << "Local variable " << vname
                << " is read at " << ea_to_hex(read_ea)
                << " before any reaching definition.";
            f.rationale = rat.str();
            nlohmann::json ev;
            ev["read_ea"]  = ea_to_hex(read_ea);
            ev["func_ea"]  = ea_to_hex(pfn->start_ea);
            ev["lvar_idx"] = idx;
            ev["lvar_name"] = vname;
            f.evidence     = std::move(ev);
            out.push_back(std::move(f));
            ++per_func;
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
        if (static_cast<int>(out.size()) >= max_findings)
            break;
    }
    return out;
}

std::vector<vuln_finding_t> TaintEngine::find_integer_overflow_sites(int max_findings)
{
    std::vector<vuln_finding_t> out;
    if (max_findings <= 0)
        max_findings = 1;
    if (max_findings > 1024)
        max_findings = 1024;

    const std::size_t fq = get_func_qty();
    int scanned = 0;
    for (std::size_t i = 0; i < fq && static_cast<int>(out.size()) < max_findings &&
         scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        if (function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;

        intra_state_t st;
        run_intraprocedural_analysis(mba, st);

        std::size_t per_func = 0;
        for (int b = 0; b < mba.qty && per_func < kMaxFreedTrackingPerFunc; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_overflow_arith(m->opcode))
                    continue;
                if (m->d.t == mop_z)
                    continue;
                bool l_t = mop_is_tainted(m->l, st.ts);
                bool r_t = mop_is_tainted(m->r, st.ts);
                if (!l_t && !r_t)
                    continue;
                if (m->d.t != mop_l || m->d.l == nullptr)
                    continue;

                auto chain = microcode::def_use_chain(mba, m->d);
                bool flows_to_alloc_or_copy = false;
                ea_t reaching_sink_ea = BADADDR;
                std::string reaching_sink_name;

                for (ea_t use_ea : chain.uses)
                {
                    for (int bb = 0; bb < mba.qty && !flows_to_alloc_or_copy; ++bb)
                    {
                        const mblock_t* blk2 = mba.get_mblock(static_cast<uint>(bb));
                        if (blk2 == nullptr)
                            continue;
                        for (const minsn_t* mm = blk2->head; mm != nullptr; mm = mm->next)
                        {
                            if (mm->ea != use_ea)
                                continue;
                            if (!is_call_op(mm->opcode))
                                continue;
                            std::string callee_nm;
                            ea_t cce = BADADDR;
                            if (!microcode::resolve_call_target(*mm, cce, callee_nm))
                                continue;
                            if (!(is_alloc_name(callee_nm) || is_sink_name(callee_nm)))
                                continue;
                            flows_to_alloc_or_copy = true;
                            reaching_sink_ea = mm->ea;
                            reaching_sink_name = callee_nm;
                            break;
                        }
                    }
                    if (flows_to_alloc_or_copy)
                        break;
                }

                if (!flows_to_alloc_or_copy)
                    continue;

                vuln_finding_t f;
                std::ostringstream id;
                id << "vuln/integer_overflow/" << std::hex << std::uppercase
                   << static_cast<std::uint64_t>(m->ea);
                f.id = id.str();
                f.primary_ea = m->ea;
                f.related_eas.push_back(reaching_sink_ea);
                f.related_eas.push_back(pfn->start_ea);
                cwe_t c;
                c.id = 190;
                c.name = cwe_name_for(190);
                f.cwes.push_back(c);
                f.severity   = severity_t::high;
                f.confidence = confidence_t::plausible;
                std::ostringstream tt;
                tt << "Tainted integer arithmetic flowing into " << reaching_sink_name
                   << " in " << func_name_for(pfn->start_ea);
                f.title = tt.str();
                std::ostringstream rat;
                rat << "Arithmetic at " << ea_to_hex(m->ea)
                    << " mixes attacker-tainted operands and the result reaches "
                    << reaching_sink_name << " at " << ea_to_hex(reaching_sink_ea)
                    << " without an intervening overflow guard.";
                f.rationale = rat.str();
                nlohmann::json ev;
                ev["arith_ea"]   = ea_to_hex(m->ea);
                ev["sink_ea"]    = ea_to_hex(reaching_sink_ea);
                ev["sink_name"]  = reaching_sink_name;
                ev["func_ea"]    = ea_to_hex(pfn->start_ea);
                ev["l_tainted"]  = l_t;
                ev["r_tainted"]  = r_t;
                f.evidence       = std::move(ev);
                out.push_back(std::move(f));
                ++per_func;
                if (per_func >= kMaxFreedTrackingPerFunc)
                    break;
                if (static_cast<int>(out.size()) >= max_findings)
                    break;
            }
            if (static_cast<int>(out.size()) >= max_findings)
                break;
        }
    }
    return out;
}

TaintEngine& engine()
{
    static TaintEngine e;
    return e;
}

// =============================================================================
// Slice C4 — enumerate_input_callsites
// =============================================================================
std::vector<std::tuple<ea_t, ea_t, std::string, taint_kind_t>>
TaintEngine::enumerate_input_callsites(std::optional<taint_kind_t> only_kind) const
{
    std::vector<std::tuple<ea_t, ea_t, std::string, taint_kind_t>> out;
    std::set<std::pair<ea_t, taint_kind_t>> seen;

    struct row_t { const sig::source_signature_t* arr; size_t n; taint_kind_t kind; };
    const row_t tables[] = {
        { sig::INPUT_SOURCES,        std::size(sig::INPUT_SOURCES),        taint_kind_t::user_input    },
        { sig::RPC_SERVER_SINKS,     std::size(sig::RPC_SERVER_SINKS),     taint_kind_t::rpc_input     },
        { sig::COM_SERVER_SINKS,     std::size(sig::COM_SERVER_SINKS),     taint_kind_t::com_input     },
        { sig::ALPC_SOURCES,         std::size(sig::ALPC_SOURCES),         taint_kind_t::alpc_input    },
        { sig::NAMED_PIPE_SOURCES,   std::size(sig::NAMED_PIPE_SOURCES),   taint_kind_t::named_pipe_input },
        { sig::SOCKET_ACCEPT_SOURCES,std::size(sig::SOCKET_ACCEPT_SOURCES),taint_kind_t::socket_input  },
        { sig::HTTP_SERVER_SOURCES,  std::size(sig::HTTP_SERVER_SOURCES),  taint_kind_t::http_input    },
        { sig::WEBSOCKET_SOURCES,    std::size(sig::WEBSOCKET_SOURCES),    taint_kind_t::websocket_input },
        { sig::NDIS_WSK_SOURCES,     std::size(sig::NDIS_WSK_SOURCES),     taint_kind_t::ndis_wsk_input  },
        { sig::KERNEL_IRP_SOURCES,   std::size(sig::KERNEL_IRP_SOURCES),   taint_kind_t::kernel_irp_input },
    };

    for (const auto& row : tables)
    {
        if (only_kind.has_value() &&
            *only_kind != row.kind &&
            row.kind != taint_kind_t::user_input)
            continue;
        for (size_t i = 0; i < row.n; ++i)
        {
            const auto& src = row.arr[i];
            std::string nm(src.name);
            taint_kind_t actual_kind = row.kind == taint_kind_t::user_input
                                       ? kind_from_source_name(nm)
                                       : row.kind;
            if (only_kind.has_value() && *only_kind != actual_kind)
                continue;
            ea_t sym_ea = get_name_ea(BADADDR, nm.c_str());
            if (sym_ea == BADADDR) continue;
            xrefblk_t xb;
            for (bool ok = xb.first_to(sym_ea, XREF_ALL); ok; ok = xb.next_to())
            {
                if (!xb.iscode) continue;
                if (xb.type != fl_CN && xb.type != fl_CF) continue;
                func_t* container = get_func(xb.from);
                ea_t func_ea = container != nullptr ? container->start_ea : BADADDR;
                if (seen.insert(std::make_pair(xb.from, actual_kind)).second)
                    out.emplace_back(xb.from, func_ea, nm, actual_kind);
            }
        }
    }
    return out;
}

// =============================================================================
// Slice C5 — enumerate_sink_callsites
// =============================================================================
std::vector<std::tuple<ea_t, ea_t, std::string, std::string>>
TaintEngine::enumerate_sink_callsites() const
{
    std::vector<std::tuple<ea_t, ea_t, std::string, std::string>> out;
    std::set<ea_t> seen_call_eas;

    struct row_t { const sig::sink_signature_t* arr; size_t n; const char* category; };
    const row_t tables[] = {
        { sig::BUFFER_OVERFLOW_SINKS,    std::size(sig::BUFFER_OVERFLOW_SINKS),    "buffer_overflow" },
        { sig::COMMAND_INJECTION_SINKS,  std::size(sig::COMMAND_INJECTION_SINKS),  "command_injection" },
        { sig::PATH_TRAVERSAL_SINKS,     std::size(sig::PATH_TRAVERSAL_SINKS),     "path_traversal" },
        { sig::FORMAT_STRING_FUNCS,      std::size(sig::FORMAT_STRING_FUNCS),      "format_string" },
        { sig::SAFEARRAY_PARSER_SINKS,   std::size(sig::SAFEARRAY_PARSER_SINKS),   "safearray_parser" },
        { sig::DESERIALIZATION_SINKS,    std::size(sig::DESERIALIZATION_SINKS),    "deserialization" },
    };
    for (const auto& row : tables)
    {
        for (size_t i = 0; i < row.n; ++i)
        {
            std::string nm(row.arr[i].name);
            ea_t sym_ea = get_name_ea(BADADDR, nm.c_str());
            if (sym_ea == BADADDR) continue;
            xrefblk_t xb;
            for (bool ok = xb.first_to(sym_ea, XREF_ALL); ok; ok = xb.next_to())
            {
                if (!xb.iscode) continue;
                if (xb.type != fl_CN && xb.type != fl_CF) continue;
                func_t* container = get_func(xb.from);
                ea_t func_ea = container != nullptr ? container->start_ea : BADADDR;
                if (seen_call_eas.insert(xb.from).second)
                    out.emplace_back(xb.from, func_ea, nm, std::string(row.category));
            }
        }
    }
    int scanned = 0;
    const std::size_t fq = get_func_qty();
    for (std::size_t i = 0; i < fq && scanned < kMaxFunctionsToAnalyze; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr || function_is_skippable(pfn))
            continue;
        ++scanned;
        auto handle = microcode::generate(pfn->start_ea, MMAT_LVARS);
        if (!handle.has_value() || !handle->mba)
            continue;
        mba_t& mba = *handle->mba;
        for (int b = 0; b < mba.qty; ++b)
        {
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            for (minsn_t* m = blk->head; m != nullptr; m = m->next)
            {
                if (!is_call_op(m->opcode) || m->ea == BADADDR)
                    continue;
                funcrole_t role =
                    (m->d.t == mop_f && m->d.f != nullptr) ? m->d.f->role : ROLE_UNK;
                sink_match_t sm = sink_match_from_role(role);
                if (!sm.matched())
                    continue;
                if (seen_call_eas.insert(m->ea).second)
                    out.emplace_back(m->ea, pfn->start_ea, std::string(sink_role_name(role)), sm.category);
            }
        }
    }
    return out;
}

// =============================================================================
// Slice C6 — build_reachability_index (forward + backward)
// =============================================================================
const reach_record_t* TaintEngine::forward_reach_for(ea_t func_ea) const
{
    auto it = m_forward_reach.find(func_ea);
    return it == m_forward_reach.end() ? nullptr : &it->second;
}

const reach_record_t* TaintEngine::backward_reach_for(ea_t func_ea) const
{
    auto it = m_backward_reach.find(func_ea);
    return it == m_backward_reach.end() ? nullptr : &it->second;
}

void TaintEngine::build_reachability_index(int max_hops)
{
    if (max_hops <= 0) max_hops = 8;
    if (max_hops > 16) max_hops = 16;

    m_forward_reach.clear();
    m_backward_reach.clear();

    // 1) Build call graph (caller/callee) over analyzed functions, skipping
    //    FUNC_THUNK/FUNC_LIB.
    std::unordered_map<ea_t, std::vector<ea_t>> callees;
    std::unordered_map<ea_t, std::vector<ea_t>> callers;

    const std::size_t fq = get_func_qty();
    for (std::size_t i = 0; i < fq; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr) continue;
        if (function_is_skippable(pfn)) continue;
        xrefblk_t xb;
        for (bool ok = xb.first_to(pfn->start_ea, XREF_ALL); ok; ok = xb.next_to())
        {
            if (!xb.iscode) continue;
            if (xb.type != fl_CN && xb.type != fl_CF) continue;
            func_t* caller = get_func(xb.from);
            if (caller == nullptr) continue;
            if (function_is_skippable(caller)) continue;
            callees[caller->start_ea].push_back(pfn->start_ea);
            callers[pfn->start_ea].push_back(caller->start_ea);
        }
    }

    // 2) Seed forward_reach with sink callsites (C5).
    auto sinks = enumerate_sink_callsites();
    for (const auto& tup : sinks)
    {
        ea_t call_ea       = std::get<0>(tup);
        ea_t containing    = std::get<1>(tup);
        const std::string& nm  = std::get<2>(tup);
        const std::string& cat = std::get<3>(tup);
        if (containing == BADADDR) continue;
        auto& rec = m_forward_reach[containing];
        rec.sink_categories.insert(cat);
        if (rec.sink_callsites.size() < 32)
            rec.sink_callsites.emplace_back(call_ea, nm);
        else
            rec.capped = true;
        rec.min_hops_to_sink = 0;
    }

    for (auto& kv : m_forward_reach)
    {
        const func_summary_t* sum = get_summary(kv.first);
        if (sum == nullptr) continue;
        for (const auto& v : sum->validators_called)
            kv.second.dominant_validators.insert(v);
    }

    // 3) BFS backward across callers — propagate min_hops_to_sink + categories.
    std::deque<ea_t> bfs;
    for (auto& kv : m_forward_reach)
        bfs.push_back(kv.first);
    while (!bfs.empty())
    {
        ea_t cur = bfs.front();
        bfs.pop_front();
        reach_record_t cur_rec = m_forward_reach[cur];
        int next_hops = cur_rec.min_hops_to_sink + 1;
        if (next_hops > max_hops) continue;
        auto it = callers.find(cur);
        if (it == callers.end()) continue;
        for (ea_t parent : it->second)
        {
            auto& prec = m_forward_reach[parent];
            bool changed = false;
            if (next_hops < prec.min_hops_to_sink) {
                prec.min_hops_to_sink = next_hops;
                changed = true;
            }
            for (const auto& c : cur_rec.sink_categories)
                if (prec.sink_categories.insert(c).second) changed = true;
            for (const auto& v : cur_rec.dominant_validators)
                if (prec.dominant_validators.insert(v).second) changed = true;
            for (const auto& sc : cur_rec.sink_callsites)
            {
                if (prec.sink_callsites.size() >= 32) { prec.capped = true; break; }
                bool exists = false;
                for (const auto& have : prec.sink_callsites)
                {
                    if (have.first == sc.first)
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    prec.sink_callsites.push_back(sc);
                    changed = true;
                }
            }
            if (changed)
                bfs.push_back(parent);
        }
    }

    // 4) Seed backward_reach with input callsites (C4).
    auto inputs = enumerate_input_callsites();
    for (const auto& tup : inputs)
    {
        ea_t containing = std::get<1>(tup);
        ea_t call_ea = std::get<0>(tup);
        const std::string& name = std::get<2>(tup);
        taint_kind_t k  = std::get<3>(tup);
        if (containing == BADADDR) continue;
        auto& rec = m_backward_reach[containing];
        rec.input_kinds.insert(k);
        if (rec.input_callsites.size() < 32)
            rec.input_callsites.emplace_back(call_ea, name);
        else
            rec.capped = true;
        rec.min_hops_from_source = 0;
    }
    // BFS forward across callees.
    std::deque<ea_t> bfs2;
    for (auto& kv : m_backward_reach)
        bfs2.push_back(kv.first);
    while (!bfs2.empty())
    {
        ea_t cur = bfs2.front();
        bfs2.pop_front();
        reach_record_t cur_rec = m_backward_reach[cur];
        int next_hops = cur_rec.min_hops_from_source + 1;
        if (next_hops > max_hops) continue;
        auto it = callees.find(cur);
        if (it == callees.end()) continue;
        for (ea_t child : it->second)
        {
            auto& crec = m_backward_reach[child];
            bool changed = false;
            if (next_hops < crec.min_hops_from_source) {
                crec.min_hops_from_source = next_hops;
                changed = true;
            }
            for (auto k : cur_rec.input_kinds)
                if (crec.input_kinds.insert(k).second) changed = true;
            for (const auto& ic : cur_rec.input_callsites)
            {
                if (crec.input_callsites.size() >= 32) { crec.capped = true; break; }
                bool exists = false;
                for (const auto& have : crec.input_callsites)
                {
                    if (have.first == ic.first)
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    crec.input_callsites.push_back(ic);
                    changed = true;
                }
            }
            if (changed)
                bfs2.push_back(child);
        }
    }

    // 5) Dominant validators per forward_reach node from func_summary_t.
    for (auto& kv : m_forward_reach)
    {
        const func_summary_t* sum = get_summary(kv.first);
        if (sum == nullptr) continue;
        for (const auto& v : sum->validators_called)
            kv.second.dominant_validators.insert(v);
    }
}

// =============================================================================
// Slice C7 — path_sensitive_sanitizer_gate
// =============================================================================
std::vector<std::string>
TaintEngine::path_sensitive_sanitizer_gate(ea_t func_ea, ea_t source_ea, ea_t sink_ea) const
{
    std::vector<std::string> out;
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr) return out;
    auto handle = microcode::generate(func_ea, MMAT_LVARS);
    if (!handle.has_value() || !handle->mba) return out;
    mba_t& mba = *handle->mba;

    bool started = false;
    bool stopped = false;
    auto match_helper = [](const std::string& nm) -> bool {
        for (const auto& v : sig::LENGTH_VALIDATOR_HELPERS)
            if (name_matches_signature(nm, v)) return true;
        for (const auto& v : sig::AUTH_GATE_HELPERS)
            if (name_matches_signature(nm, v)) return true;
        return false;
    };

    for (int b = 0; b < mba.qty && !stopped; ++b)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
        if (blk == nullptr) continue;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (m->ea == source_ea) { started = true; continue; }
            if (m->ea == sink_ea)   { stopped = true; break; }
            if (!started) continue;
            if (!is_call_op(m->opcode)) continue;
            std::string nm; ea_t ce = BADADDR;
            if (!resolve_callee_simple(*m, nm, ce)) continue;
            if (match_helper(nm))
                out.push_back(nm);
        }
    }
    // Deduplicate preserving order.
    std::set<std::string> seen;
    std::vector<std::string> dedup;
    for (auto& s : out) if (seen.insert(s).second) dedup.push_back(std::move(s));
    return dedup;
}

// =============================================================================
// Slice C8 — trace_paths_reverse (BFS backward via callers).
// =============================================================================
std::vector<taint_path_t>
TaintEngine::trace_paths_reverse(ea_t sink_ea, int max_paths, int max_depth)
{
    std::vector<taint_path_t> out;
    if (max_paths <= 0) max_paths = 16;
    if (max_paths > 64) max_paths = 64;
    if (max_depth <= 0) max_depth = 10;
    if (max_depth > 16) max_depth = 16;
    if (!m_analyzed) analyze_all();
    if (m_forward_reach.empty() || m_backward_reach.empty())
        build_reachability_index(max_depth);

    ea_t sink_func_ea = containing_func_ea(sink_ea);
    if (sink_func_ea == BADADDR) return out;

    TaintCallGraph cg; cg.build();

    struct frame_t {
        ea_t func_ea;
        std::vector<taint_path_step_t> steps;
        std::set<ea_t> visited;
    };
    std::deque<frame_t> queue;
    frame_t start; start.func_ea = sink_func_ea; start.visited.insert(sink_func_ea);
    taint_path_step_t s0;
    s0.ea = sink_ea; s0.func_ea = sink_func_ea;
    s0.func_name = func_name_for(sink_func_ea);
    s0.description = std::string("sink callsite");
    start.steps.push_back(std::move(s0));
    queue.push_back(std::move(start));

    while (!queue.empty() && static_cast<int>(out.size()) < max_paths)
    {
        frame_t cur = std::move(queue.front()); queue.pop_front();
        // Source-detection: if current function has input_kinds, emit a path.
        const reach_record_t* br = backward_reach_for(cur.func_ea);
        if (br != nullptr && !br->input_kinds.empty())
        {
            taint_path_t p;
            p.origin.source_func_ea = cur.func_ea;
            p.origin.source_ea      = br->input_callsites.empty()
                                      ? cur.func_ea
                                      : br->input_callsites.front().first;
            p.origin.source_name    = br->input_callsites.empty()
                                      ? func_name_for(cur.func_ea)
                                      : br->input_callsites.front().second;
            p.origin.kind           = *br->input_kinds.begin();
            p.sink_ea       = sink_ea;
            p.sink_func_ea  = sink_func_ea;
            p.sink_name     = func_name_for(sink_func_ea);
            p.steps         = cur.steps;
            p.vulnerability_type = "tainted_sink";
            p.severity      = severity_t::medium;
            p.confidence    = confidence_t::plausible;
            const func_summary_t* sum = get_summary(cur.func_ea);
            if (sum != nullptr)
                p.validator_chain.assign(sum->validators_called.begin(), sum->validators_called.end());
            out.push_back(std::move(p));
            continue;
        }
        if (static_cast<int>(cur.steps.size()) >= max_depth) continue;
        const auto& cs = cg.callers_of(cur.func_ea);
        for (ea_t parent : cs)
        {
            if (cur.visited.count(parent)) continue;
            // Pruning via forward_reach: only walk parents that reach the sink.
            const reach_record_t* fr = forward_reach_for(parent);
            if (fr == nullptr) continue;
            frame_t nf = cur; nf.func_ea = parent; nf.visited.insert(parent);
            taint_path_step_t st;
            st.ea = BADADDR; st.func_ea = parent;
            st.func_name = func_name_for(parent);
            st.description = std::string("caller hop");
            nf.steps.push_back(std::move(st));
            queue.push_back(std::move(nf));
        }
    }
    return out;
}

// =============================================================================
// Slice C9 — trace_all_network_to_sinks
// =============================================================================
std::vector<taint_path_t>
TaintEngine::trace_all_network_to_sinks(bool require_unsanitized, int max_paths,
                                        int max_depth,
                                        std::optional<taint_kind_t> only_kind)
{
    std::vector<taint_path_t> out;
    if (max_paths <= 0) max_paths = 64;
    if (max_paths > 256) max_paths = 256;
    if (!m_analyzed) analyze_all();
    if (m_forward_reach.empty()) build_reachability_index(max_depth);

    auto inputs = enumerate_input_callsites(only_kind);
    struct scored_t { taint_path_t path; int score; };
    std::vector<scored_t> ranked;

    for (const auto& tup : inputs)
    {
        if (static_cast<int>(ranked.size()) >= max_paths * 2) break;
        ea_t src_call_ea = std::get<0>(tup);
        ea_t src_func    = std::get<1>(tup);
        const std::string& src_nm = std::get<2>(tup);
        taint_kind_t k   = std::get<3>(tup);
        if (src_func == BADADDR) continue;
        const reach_record_t* fr = forward_reach_for(src_func);
        if (fr == nullptr) continue;
        if (fr->sink_callsites.empty()) continue;

        for (const auto& sc : fr->sink_callsites)
        {
            std::vector<std::string> validators(fr->dominant_validators.begin(),
                                                fr->dominant_validators.end());
            ea_t sink_func = containing_func_ea(sc.first);
            if (sink_func == src_func)
            {
                std::vector<std::string> local =
                    path_sensitive_sanitizer_gate(src_func, src_call_ea, sc.first);
                validators.insert(validators.end(), local.begin(), local.end());
            }
            std::sort(validators.begin(), validators.end());
            validators.erase(std::unique(validators.begin(), validators.end()), validators.end());
            if (require_unsanitized && !validators.empty())
                continue;

            taint_path_t p;
            p.origin.source_ea      = src_call_ea;
            p.origin.source_func_ea = src_func;
            p.origin.source_name    = src_nm;
            p.origin.kind           = k;
            p.sink_ea       = sc.first;
            p.sink_func_ea  = sink_func;
            p.sink_name     = sc.second;
            p.vulnerability_type = "tainted_sink";
            p.severity   = severity_t::medium;
            p.confidence = validators.empty()
                            ? confidence_t::likely : confidence_t::plausible;
            p.validator_chain = std::move(validators);

            int validator_count = static_cast<int>(p.validator_chain.size());
            int path_length     = fr->min_hops_to_sink == INT_MAX
                                    ? 16 : fr->min_hops_to_sink;
            int kind_spec       = (k == taint_kind_t::user_input) ? 1 : 2;
            int score = -(path_length + validator_count * 2) + kind_spec * 10;
            ranked.push_back({ std::move(p), score });
        }
    }
    std::stable_sort(ranked.begin(), ranked.end(),
                     [](const scored_t& a, const scored_t& b) { return a.score > b.score; });
    for (auto& s : ranked)
    {
        if (static_cast<int>(out.size()) >= max_paths) break;
        out.push_back(std::move(s.path));
    }
    return out;
}

// =============================================================================
// Slice C10 — function_taint_brief
// =============================================================================
nlohmann::json TaintEngine::function_taint_brief(ea_t func_ea) const
{
    nlohmann::json j;
    j["func_ea"] = ea_to_hex(func_ea);
    j["func_name"] = func_name_for(func_ea);
    const func_summary_t* sum = get_summary(func_ea);
    if (sum == nullptr) {
        j["analyzed"] = false;
        return j;
    }
    j["analyzed"]    = sum->analyzed;
    j["cyclomatic"] = sum->cyclomatic;
    j["returns_tainted"] = sum->returns_tainted;

    nlohmann::json params = nlohmann::json::object();
    auto add_param = [&](int p_idx) {
        nlohmann::json pj;
        pj["index"] = p_idx;
        pj["tainted_in"]  = sum->tainted_param_indices.count(p_idx) > 0;
        pj["tainted_out"] = sum->tainted_out_param_indices.count(p_idx) > 0;
        pj["passed_to_sink"] = sum->params_passed_to_sinks.count(p_idx) > 0;
        pj["validated"]      = sum->params_validated.count(p_idx) > 0;
        pj["freed"]          = sum->params_freed.count(p_idx) > 0;
        nlohmann::json sink_uses = nlohmann::json::array();
        auto it = sum->param_sink_uses.find(p_idx);
        if (it != sum->param_sink_uses.end()) {
            for (const auto& tup : it->second) {
                nlohmann::json e;
                e["sink_name"] = std::get<0>(tup);
                e["category"]  = std::get<1>(tup);
                e["arg_idx"]   = std::get<2>(tup);
                sink_uses.push_back(std::move(e));
            }
        }
        pj["sink_uses"] = std::move(sink_uses);
        auto vit = sum->param_validators_seen.find(p_idx);
        nlohmann::json vs = nlohmann::json::array();
        if (vit != sum->param_validators_seen.end())
            for (auto& v : vit->second) vs.push_back(v);
        pj["validators_seen"] = std::move(vs);
        auto kit = sum->param_inferred_kinds.find(p_idx);
        nlohmann::json ks = nlohmann::json::array();
        if (kit != sum->param_inferred_kinds.end())
            for (auto k : kit->second) ks.push_back(taint_kind_str(k));
        pj["inferred_kinds"] = std::move(ks);
        params[std::to_string(p_idx)] = std::move(pj);
    };
    std::set<int> all_params;
    for (int p : sum->tainted_param_indices) all_params.insert(p);
    for (int p : sum->tainted_out_param_indices) all_params.insert(p);
    for (int p : sum->params_passed_to_sinks) all_params.insert(p);
    for (int p : sum->params_validated) all_params.insert(p);
    for (int p : sum->params_freed) all_params.insert(p);
    for (auto& kv : sum->param_sink_uses) all_params.insert(kv.first);
    for (auto& kv : sum->param_validators_seen) all_params.insert(kv.first);
    for (auto& kv : sum->param_inferred_kinds) all_params.insert(kv.first);
    for (int p : all_params) add_param(p);
    j["params"] = std::move(params);

    nlohmann::json sinks_arr = nlohmann::json::array();
    for (const auto& s : sum->sinks_reached) sinks_arr.push_back(s);
    j["sinks_reached"] = std::move(sinks_arr);
    nlohmann::json src_arr = nlohmann::json::array();
    for (const auto& s : sum->input_sources_called) src_arr.push_back(s);
    j["input_sources_called"] = std::move(src_arr);
    nlohmann::json v_arr = nlohmann::json::array();
    for (const auto& v : sum->validators_called) v_arr.push_back(v);
    j["validators_called"] = std::move(v_arr);

    std::unordered_map<int, int> lvar_to_param;
    auto handle = microcode::generate(func_ea, MMAT_LVARS);
    if (handle.has_value() && handle->mba)
    {
        const mba_t& mba = *handle->mba;
        for (size_t i = 0; i < mba.argidx.size(); ++i)
            lvar_to_param[mba.argidx[i]] = static_cast<int>(i);
    }

    nlohmann::json fields = nlohmann::json::array();
    for (const auto& kv : sum->tainted_fields)
    {
        nlohmann::json fj;
        fj["base_lvar_idx"] = kv.first;
        auto pit = lvar_to_param.find(kv.first);
        fj["param_index"] = pit == lvar_to_param.end() ? -1 : pit->second;
        nlohmann::json offsets = nlohmann::json::array();
        for (int off : kv.second)
            offsets.push_back(off);
        fj["field_offsets"] = std::move(offsets);
        fields.push_back(std::move(fj));
    }
    j["tainted_fields"] = std::move(fields);

    nlohmann::json input_callsites = nlohmann::json::array();
    for (const auto& row : enumerate_input_callsites())
    {
        if (std::get<1>(row) != func_ea)
            continue;
        nlohmann::json cj;
        cj["call_ea"] = ea_to_hex(std::get<0>(row));
        cj["name"] = std::get<2>(row);
        cj["kind"] = taint_kind_str(std::get<3>(row));
        input_callsites.push_back(std::move(cj));
    }
    j["input_callsites"] = std::move(input_callsites);

    nlohmann::json sink_callsites = nlohmann::json::array();
    for (const auto& row : enumerate_sink_callsites())
    {
        if (std::get<1>(row) != func_ea)
            continue;
        nlohmann::json cj;
        cj["call_ea"] = ea_to_hex(std::get<0>(row));
        cj["name"] = std::get<2>(row);
        cj["category"] = std::get<3>(row);
        sink_callsites.push_back(std::move(cj));
    }
    j["sink_callsites"] = std::move(sink_callsites);

    const reach_record_t* fr = forward_reach_for(func_ea);
    if (fr != nullptr) {
        nlohmann::json frj;
        nlohmann::json cats = nlohmann::json::array();
        for (auto& c : fr->sink_categories) cats.push_back(c);
        frj["sink_categories"] = std::move(cats);
        nlohmann::json scalls = nlohmann::json::array();
        for (const auto& sc : fr->sink_callsites) {
            nlohmann::json sj;
            sj["call_ea"] = ea_to_hex(sc.first);
            sj["name"] = sc.second;
            scalls.push_back(std::move(sj));
        }
        frj["sink_callsites"] = std::move(scalls);
        nlohmann::json dvs = nlohmann::json::array();
        for (const auto& v : fr->dominant_validators) dvs.push_back(v);
        frj["dominant_validators"] = std::move(dvs);
        frj["min_hops_to_sink"] = fr->min_hops_to_sink == INT_MAX ? -1 : fr->min_hops_to_sink;
        frj["capped"] = fr->capped;
        j["forward_reach"] = std::move(frj);
    }
    const reach_record_t* br = backward_reach_for(func_ea);
    if (br != nullptr) {
        nlohmann::json brj;
        nlohmann::json kinds = nlohmann::json::array();
        for (auto k : br->input_kinds) kinds.push_back(taint_kind_str(k));
        brj["input_kinds"] = std::move(kinds);
        nlohmann::json icalls = nlohmann::json::array();
        for (const auto& ic : br->input_callsites) {
            nlohmann::json ij;
            ij["call_ea"] = ea_to_hex(ic.first);
            ij["name"] = ic.second;
            icalls.push_back(std::move(ij));
        }
        brj["input_callsites"] = std::move(icalls);
        brj["min_hops_from_source"] = br->min_hops_from_source == INT_MAX ? -1 : br->min_hops_from_source;
        brj["capped"] = br->capped;
        j["backward_reach"] = std::move(brj);
    }
    return j;
}

// =============================================================================
// Slice C11 — persistent summary cache (netnode-backed)
// =============================================================================
namespace {

// Slice C11: encode taint_kind_t as int for JSON map keys.
nlohmann::json summary_to_json(const func_summary_t& s)
{
    nlohmann::json j;
    j["func_ea"] = static_cast<uint64_t>(s.func_ea);
    j["name"]    = s.name;
    j["analyzed"] = s.analyzed;
    j["cyclomatic"] = s.cyclomatic;
    j["returns_tainted"] = s.returns_tainted;
    j["returns_alloc"]   = s.returns_alloc;
    j["returns_free"]    = s.returns_free;
    auto pack_int_set = [](const std::set<int>& xs) { nlohmann::json a = nlohmann::json::array(); for (int x : xs) a.push_back(x); return a; };
    auto pack_str_set = [](const std::set<std::string>& xs) { nlohmann::json a = nlohmann::json::array(); for (auto& x : xs) a.push_back(x); return a; };
    auto pack_kind_set = [](const std::set<taint_kind_t>& xs) { nlohmann::json a = nlohmann::json::array(); for (auto x : xs) a.push_back(static_cast<int>(x)); return a; };
    j["tainted_param_indices"]     = pack_int_set(s.tainted_param_indices);
    j["tainted_out_param_indices"] = pack_int_set(s.tainted_out_param_indices);
    j["params_passed_to_sinks"]    = pack_int_set(s.params_passed_to_sinks);
    j["params_validated"]          = pack_int_set(s.params_validated);
    j["params_freed"]              = pack_int_set(s.params_freed);
    j["sinks_reached"]    = pack_str_set(s.sinks_reached);
    j["validators_called"]= pack_str_set(s.validators_called);
    j["allocs_called"]    = pack_str_set(s.allocs_called);
    j["frees_called"]     = pack_str_set(s.frees_called);
    j["input_sources_called"] = pack_str_set(s.input_sources_called);
    nlohmann::json sink_uses = nlohmann::json::object();
    for (const auto& kv : s.param_sink_uses) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& t : kv.second) {
            nlohmann::json row;
            row["sink_name"] = std::get<0>(t);
            row["category"] = std::get<1>(t);
            row["arg_idx"] = std::get<2>(t);
            arr.push_back(std::move(row));
        }
        sink_uses[std::to_string(kv.first)] = std::move(arr);
    }
    j["param_sink_uses"] = std::move(sink_uses);
    nlohmann::json validators = nlohmann::json::object();
    for (const auto& kv : s.param_validators_seen)
        validators[std::to_string(kv.first)] = pack_str_set(kv.second);
    j["param_validators_seen"] = std::move(validators);
    nlohmann::json kinds = nlohmann::json::object();
    for (const auto& kv : s.param_inferred_kinds)
        kinds[std::to_string(kv.first)] = pack_kind_set(kv.second);
    j["param_inferred_kinds"] = std::move(kinds);
    nlohmann::json fields = nlohmann::json::object();
    for (const auto& kv : s.tainted_fields)
        fields[std::to_string(kv.first)] = pack_int_set(kv.second);
    j["tainted_fields"] = std::move(fields);
    return j;
}
void summary_from_json(const nlohmann::json& j, func_summary_t& s)
{
    s.func_ea = static_cast<ea_t>(j.value("func_ea", static_cast<std::uint64_t>(BADADDR)));
    s.name    = j.value("name", std::string());
    s.analyzed = j.value("analyzed", false);
    s.cyclomatic = j.value("cyclomatic", 0);
    s.returns_tainted = j.value("returns_tainted", false);
    s.returns_alloc   = j.value("returns_alloc", false);
    s.returns_free    = j.value("returns_free", false);
    auto load_int_set = [&](const char* k, std::set<int>& dst) {
        if (j.contains(k) && j[k].is_array()) for (auto& v : j[k]) {
            if (v.is_number_integer())
            {
                const std::int64_t value = v.get<std::int64_t>();
                if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                    dst.insert(static_cast<int>(value));
            }
            else if (v.is_number_unsigned())
            {
                const std::uint64_t value = v.get<std::uint64_t>();
                if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                    dst.insert(static_cast<int>(value));
            }
        }
    };
    auto load_str_set = [&](const char* k, std::set<std::string>& dst) {
        if (j.contains(k) && j[k].is_array()) for (auto& v : j[k]) dst.insert(v.get<std::string>());
    };
    load_int_set("tainted_param_indices",     s.tainted_param_indices);
    load_int_set("tainted_out_param_indices", s.tainted_out_param_indices);
    load_int_set("params_passed_to_sinks",    s.params_passed_to_sinks);
    load_int_set("params_validated",          s.params_validated);
    load_int_set("params_freed",              s.params_freed);
    load_str_set("sinks_reached",     s.sinks_reached);
    load_str_set("validators_called", s.validators_called);
    load_str_set("allocs_called",     s.allocs_called);
    load_str_set("frees_called",      s.frees_called);
    load_str_set("input_sources_called", s.input_sources_called);
    auto parse_index = [](const std::string& k) -> int {
        try {
            return std::stoi(k);
        } catch (...) {
            return -1;
        }
    };
    if (j.contains("param_sink_uses") && j["param_sink_uses"].is_object()) {
        for (auto it = j["param_sink_uses"].begin(); it != j["param_sink_uses"].end(); ++it) {
            int idx = parse_index(it.key());
            if (idx < 0 || !it.value().is_array()) continue;
            for (const auto& row : it.value()) {
                if (!row.is_object()) continue;
                s.param_sink_uses[idx].emplace(
                    row.value("sink_name", std::string()),
                    row.value("category", std::string()),
                    row.value("arg_idx", -1));
            }
        }
    }
    if (j.contains("param_validators_seen") && j["param_validators_seen"].is_object()) {
        for (auto it = j["param_validators_seen"].begin(); it != j["param_validators_seen"].end(); ++it) {
            int idx = parse_index(it.key());
            if (idx < 0 || !it.value().is_array()) continue;
            for (const auto& v : it.value())
                s.param_validators_seen[idx].insert(v.get<std::string>());
        }
    }
    if (j.contains("param_inferred_kinds") && j["param_inferred_kinds"].is_object()) {
        for (auto it = j["param_inferred_kinds"].begin(); it != j["param_inferred_kinds"].end(); ++it) {
            int idx = parse_index(it.key());
            if (idx < 0 || !it.value().is_array()) continue;
            for (const auto& v : it.value())
            {
                if (v.is_number_integer())
                {
                    const std::int64_t value = v.get<std::int64_t>();
                    if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                        s.param_inferred_kinds[idx].insert(static_cast<taint_kind_t>(static_cast<int>(value)));
                }
                else if (v.is_number_unsigned())
                {
                    const std::uint64_t value = v.get<std::uint64_t>();
                    if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                        s.param_inferred_kinds[idx].insert(static_cast<taint_kind_t>(static_cast<int>(value)));
                }
            }
        }
    }
    if (j.contains("tainted_fields") && j["tainted_fields"].is_object()) {
        for (auto it = j["tainted_fields"].begin(); it != j["tainted_fields"].end(); ++it) {
            int idx = parse_index(it.key());
            if (idx < 0 || !it.value().is_array()) continue;
            for (const auto& v : it.value())
            {
                if (v.is_number_integer())
                {
                    const std::int64_t value = v.get<std::int64_t>();
                    if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                        s.tainted_fields[idx].insert(static_cast<int>(value));
                }
                else if (v.is_number_unsigned())
                {
                    const std::uint64_t value = v.get<std::uint64_t>();
                    if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                        s.tainted_fields[idx].insert(static_cast<int>(value));
                }
            }
        }
    }
}

nlohmann::json reach_record_to_json(const reach_record_t& r)
{
    nlohmann::json j;
    nlohmann::json input_kinds = nlohmann::json::array();
    for (auto k : r.input_kinds)
        input_kinds.push_back(static_cast<int>(k));
    j["input_kinds"] = std::move(input_kinds);
    nlohmann::json input_callsites = nlohmann::json::array();
    for (const auto& ic : r.input_callsites) {
        nlohmann::json row;
        row["ea"] = static_cast<std::uint64_t>(ic.first);
        row["name"] = ic.second;
        input_callsites.push_back(std::move(row));
    }
    j["input_callsites"] = std::move(input_callsites);
    nlohmann::json categories = nlohmann::json::array();
    for (const auto& c : r.sink_categories)
        categories.push_back(c);
    j["sink_categories"] = std::move(categories);
    nlohmann::json sink_callsites = nlohmann::json::array();
    for (const auto& sc : r.sink_callsites) {
        nlohmann::json row;
        row["ea"] = static_cast<std::uint64_t>(sc.first);
        row["name"] = sc.second;
        sink_callsites.push_back(std::move(row));
    }
    j["sink_callsites"] = std::move(sink_callsites);
    nlohmann::json validators = nlohmann::json::array();
    for (const auto& v : r.dominant_validators)
        validators.push_back(v);
    j["dominant_validators"] = std::move(validators);
    j["capped"] = r.capped;
    j["min_hops_to_sink"] = r.min_hops_to_sink;
    j["min_hops_from_source"] = r.min_hops_from_source;
    return j;
}

void reach_record_from_json(const nlohmann::json& j, reach_record_t& r)
{
    if (j.contains("input_kinds") && j["input_kinds"].is_array())
        for (const auto& v : j["input_kinds"])
        {
            if (v.is_number_integer())
            {
                const std::int64_t value = v.get<std::int64_t>();
                if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                    r.input_kinds.insert(static_cast<taint_kind_t>(static_cast<int>(value)));
            }
            else if (v.is_number_unsigned())
            {
                const std::uint64_t value = v.get<std::uint64_t>();
                if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                    r.input_kinds.insert(static_cast<taint_kind_t>(static_cast<int>(value)));
            }
        }
    if (j.contains("input_callsites") && j["input_callsites"].is_array())
        for (const auto& row : j["input_callsites"])
            if (row.is_object())
                r.input_callsites.emplace_back(
                    static_cast<ea_t>(row.value("ea", static_cast<std::uint64_t>(BADADDR))),
                    row.value("name", std::string()));
    if (j.contains("sink_categories") && j["sink_categories"].is_array())
        for (const auto& v : j["sink_categories"])
            r.sink_categories.insert(v.get<std::string>());
    if (j.contains("sink_callsites") && j["sink_callsites"].is_array())
        for (const auto& row : j["sink_callsites"])
            if (row.is_object())
                r.sink_callsites.emplace_back(
                    static_cast<ea_t>(row.value("ea", static_cast<std::uint64_t>(BADADDR))),
                    row.value("name", std::string()));
    if (j.contains("dominant_validators") && j["dominant_validators"].is_array())
        for (const auto& v : j["dominant_validators"])
            r.dominant_validators.insert(v.get<std::string>());
    r.capped = j.value("capped", false);
    r.min_hops_to_sink = j.value("min_hops_to_sink", INT_MAX);
    r.min_hops_from_source = j.value("min_hops_from_source", INT_MAX);
}

nlohmann::json reach_map_to_json(const std::unordered_map<ea_t, reach_record_t>& m)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& kv : m) {
        nlohmann::json row;
        row["func_ea"] = static_cast<std::uint64_t>(kv.first);
        row["record"] = reach_record_to_json(kv.second);
        arr.push_back(std::move(row));
    }
    return arr;
}

void reach_map_from_json(const nlohmann::json& j, std::unordered_map<ea_t, reach_record_t>& out)
{
    if (!j.is_array())
        return;
    for (const auto& row : j) {
        if (!row.is_object() || !row.contains("record"))
            continue;
        reach_record_t rec;
        reach_record_from_json(row["record"], rec);
        ea_t func_ea = static_cast<ea_t>(row.value("func_ea", static_cast<std::uint64_t>(BADADDR)));
        if (func_ea == BADADDR)
            continue;
        out[func_ea] = std::move(rec);
    }
}

std::string compute_binary_cache_key()
{
    uchar md5[16] = {0};
    if (!retrieve_input_file_md5(md5))
        return {};
    std::ostringstream ss;
    for (int i = 0; i < 16; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md5[i]);
    ss << ":" << sig::SIGNATURE_DATABASE_REVISION;
    return ss.str();
}

constexpr const char kTaintCacheNetnodeName[] = "$ AiDA.taint.cache";
constexpr uchar      kTaintCacheBlobTag       = 'T';
constexpr nodeidx_t  kTaintCacheBlobStart     = 0;
constexpr std::size_t kTaintCacheMaxBlobBytes = 1024u * 1024u;

} // namespace

bool TaintEngine::save_summaries_to_netnode() const
{
    std::string key = compute_binary_cache_key();
    if (key.empty()) return false;
    nlohmann::json doc;
    doc["key"] = key;
    nlohmann::json sums = nlohmann::json::array();
    for (const auto& kv : m_summaries)
        sums.push_back(summary_to_json(kv.second));
    doc["summaries"] = std::move(sums);
    doc["forward_reach"] = reach_map_to_json(m_forward_reach);
    doc["backward_reach"] = reach_map_to_json(m_backward_reach);
    std::vector<std::uint8_t> cbor = nlohmann::json::to_cbor(doc);
    if (cbor.empty()) return false;
    if (cbor.size() > kTaintCacheMaxBlobBytes) return false;
    netnode nn(kTaintCacheNetnodeName, 0, true);
    if (nn == BADNODE) return false;
    nn.delblob(kTaintCacheBlobStart, kTaintCacheBlobTag);
    if (!nn.setblob(cbor.data(), cbor.size(), kTaintCacheBlobStart, kTaintCacheBlobTag))
        return false;
    return true;
}

bool TaintEngine::load_summaries_from_netnode()
{
    std::string key = compute_binary_cache_key();
    if (key.empty()) return false;
    netnode nn(kTaintCacheNetnodeName, 0, false);
    if (nn == BADNODE) return false;
    size_t sz = 0;
    void* blob = nn.getblob(nullptr, &sz, kTaintCacheBlobStart, kTaintCacheBlobTag);
    if (blob == nullptr || sz == 0) {
        if (blob != nullptr) qfree(blob);
        return false;
    }
    const std::unique_ptr<void, decltype(&qfree)> blob_guard(blob, &qfree);
    std::vector<std::uint8_t> buf(static_cast<const std::uint8_t*>(blob_guard.get()),
                                  static_cast<const std::uint8_t*>(blob_guard.get()) + sz);
    nlohmann::json doc;
    try {
        doc = nlohmann::json::from_cbor(buf);
    } catch (...) {
        return false;
    }
    std::string have = doc.value("key", std::string());
    if (have != key) return false;
    m_summaries.clear();
    m_forward_reach.clear();
    m_backward_reach.clear();
    if (doc.contains("summaries") && doc["summaries"].is_array()) {
        for (const auto& sj : doc["summaries"]) {
            func_summary_t s;
            summary_from_json(sj, s);
            m_summaries[s.func_ea] = std::move(s);
        }
    }
    if (doc.contains("forward_reach"))
        reach_map_from_json(doc["forward_reach"], m_forward_reach);
    if (doc.contains("backward_reach"))
        reach_map_from_json(doc["backward_reach"], m_backward_reach);
    m_analyzed = !m_summaries.empty();
    return m_analyzed;
}

namespace tools
{

namespace
{

using nlohmann::json;
using agent_tools::tool_result_t;

std::mutex& engine_mutex()
{
    static std::mutex mtx;
    return mtx;
}

int extract_int_param(const json& params, const std::string& key, int default_value)
{
    if (!params.is_object())
        return default_value;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return default_value;
    try
    {
        if (it->is_number_integer())
        {
            const std::int64_t value = it->get<std::int64_t>();
            if (value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return default_value;
            return static_cast<int>(value);
        }
        if (it->is_number_unsigned())
        {
            const std::uint64_t value = it->get<std::uint64_t>();
            if (value > static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                return default_value;
            return static_cast<int>(value);
        }
        if (it->is_number())
        {
            const double value = it->get<double>();
            if (!std::isfinite(value) || value < (std::numeric_limits<int>::min)() || value > (std::numeric_limits<int>::max)())
                return default_value;
            return static_cast<int>(value);
        }
        if (it->is_string())
        {
            const std::string s = it->get<std::string>();
            if (s.empty())
                return default_value;
            return std::stoi(s);
        }
    }
    catch (...)
    {
        return default_value;
    }
    return default_value;
}

std::string extract_string_param(const json& params, const std::string& key,
                                 const std::string& default_value)
{
    if (!params.is_object())
        return default_value;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return default_value;
    if (it->is_string())
        return it->get<std::string>();
    return default_value;
}

json findings_to_json_array(const std::vector<vuln_finding_t>& findings)
{
    json arr = json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

ea_t resolve_address_or_name(const std::string& spec)
{
    if (spec.empty())
        return BADADDR;
    auto parsed = agent_tools::helpers::parse_address(spec);
    if (parsed.has_value())
        return *parsed;
    ea_t ea = get_name_ea(BADADDR, spec.c_str());
    return ea;
}

tool_result_t handle_trace_taint_path(const json& params)
{
    const std::string source_spec = extract_string_param(params, "source", std::string());
    const std::string sink_spec   = extract_string_param(params, "sink",   std::string());
    if (source_spec.empty() || sink_spec.empty())
        return tool_result_t::error(std::string("source and sink must be provided"));

    int max_paths = extract_int_param(params, "max_paths", 16);
    if (max_paths <= 0) max_paths = 16;
    if (max_paths > 64) max_paths = 64;

    int max_depth = extract_int_param(params, "max_depth", 10);
    if (max_depth <= 0) max_depth = 10;
    if (max_depth > 16) max_depth = 16;

    ea_t source_ea = resolve_address_or_name(source_spec);
    ea_t sink_ea   = resolve_address_or_name(sink_spec);
    if (source_ea == BADADDR)
        return tool_result_t::error(std::string("Could not resolve source: ") + source_spec);
    if (sink_ea == BADADDR)
        return tool_result_t::error(std::string("Could not resolve sink: ") + sink_spec);

    std::vector<taint_path_t> paths;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        paths = engine().trace_paths(source_ea, sink_ea, max_paths, max_depth);
    }

    json arr = json::array();
    for (const auto& p : paths)
        arr.push_back(to_json(p));

    json data;
    data["paths"] = std::move(arr);
    data["count"] = paths.size();
    data["source_ea"] = ea_to_hex(source_ea);
    data["sink_ea"]   = ea_to_hex(sink_ea);
    func_t* sf = get_func(source_ea);
    func_t* tf = get_func(sink_ea);
    data["source_func"] = sf != nullptr ? func_name_for(sf->start_ea) : std::string();
    data["sink_func"]   = tf != nullptr ? func_name_for(tf->start_ea) : std::string();
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << std::string("Taint path trace: ") << paths.size() << std::string(" path(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_uaf_candidates(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_uaf_candidates(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 416;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << std::string("Use-after-free scan: ") << findings.size() << std::string(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_double_free_candidates(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_double_free_candidates(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 415;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << std::string("Double-free scan: ") << findings.size() << std::string(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_use_after_realloc(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_use_after_realloc(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 416;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << std::string("Use-after-realloc scan: ") << findings.size() << std::string(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_uninit_use(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_uninit_use(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 457;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << std::string("Uninitialized-use scan: ") << findings.size() << std::string(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

tool_result_t handle_find_integer_overflow_sites(const json& params)
{
    int limit = extract_int_param(params, "limit", 64);
    if (limit <= 0) limit = 64;
    if (limit > 1024) limit = 1024;

    std::vector<vuln_finding_t> findings;
    {
        std::lock_guard<std::mutex> lk(engine_mutex());
        findings = engine().find_integer_overflow_sites(limit);
    }

    json data;
    data["count"]       = findings.size();
    data["findings"]    = findings_to_json_array(findings);
    data["primary_cwe"] = 190;
    sanitize_json_utf8_inplace(data);

    std::ostringstream msg;
    msg << std::string("Integer-overflow scan: ") << findings.size() << std::string(" finding(s)");
    return tool_result_t::ok(msg.str(), data);
}

}

void register_tier1_taint_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        std::string("trace_taint_path"),
        std::string("vuln"),
        std::string("Compute interprocedural taint paths from a known input source callsite (recv/"
               "ReadFile/scanf/getenv/RegQuery/...) to a known dangerous sink callsite "
               "(strcpy/memcpy/system/CreateProcess/sprintf/...). Walks the binary's call graph "
               "and applies per-function taint summaries (parameter taint, returns_tainted, "
               "sinks_reached, validators_called) at each hop. Returns up to max_paths distinct "
               "paths, each with the originating taint kind, the sink argument index, the "
               "caller chain (taint_path_step_t per call hop), accumulated branch conditions, a "
               "vulnerability classification derived from the sink CWE, and a severity / "
               "confidence assessment that downgrades to plausible when validators are present "
               "on the dominant route."),
        {
            {std::string("source"),    std::string("string"),
             std::string("Address (0x...) or symbol name of the input-source callsite."), true},
            {std::string("sink"),      std::string("string"),
             std::string("Address (0x...) or symbol name of the dangerous-sink callsite."), true},
            {std::string("max_paths"), std::string("number"),
             std::string("Maximum number of paths to enumerate (default 16, max 64)."), false},
            {std::string("max_depth"), std::string("number"),
             std::string("Maximum call-graph depth (default 10, max 16)."), false},
        },
        handle_trace_taint_path,
        true,
    });
}

void register_tier2_taint_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        std::string("find_uaf_candidates"),
        std::string("vuln_advanced"),
        std::string("Locate use-after-free candidates (CWE-416) by walking each function's microcode, "
               "tracking the freed pointer at every call to free/HeapFree/RtlFreeHeap/ExFreePool/"
               "operator delete and detecting subsequent dereferences (m_ldx/m_stx) or sink-arg "
               "uses without an intervening reassignment of the same pointer. Skips realloc-style "
               "calls because those have a separate engine."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_uaf_candidates,
        true,
    });

    registry.register_tool({
        std::string("find_double_free_candidates"),
        std::string("vuln_advanced"),
        std::string("Locate double-free candidates (CWE-415) by walking each function's microcode and "
               "flagging two distinct free-style calls applied to the same pointer without an "
               "intervening reassignment. Free signatures cover free/HeapFree/RtlFreeHeap/"
               "ExFreePool/ExFreePoolWithTag/operator delete and the corresponding mangled "
               "MSVC operator-delete symbols."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_double_free_candidates,
        true,
    });

    registry.register_tool({
        std::string("find_use_after_realloc"),
        std::string("vuln_advanced"),
        std::string("Locate use-after-realloc candidates (CWE-416) by walking each function's "
               "microcode for realloc/HeapReAlloc calls, capturing the input pointer, and "
               "checking whether that original handle is dereferenced after the realloc without "
               "an early-return check on the new pointer. Reports the realloc EA, the offending "
               "use EA, and the function context."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_use_after_realloc,
        true,
    });

    registry.register_tool({
        std::string("find_uninit_use"),
        std::string("vuln_advanced"),
        std::string("Locate uninitialized-variable reads (CWE-457) by walking each function's "
               "microcode for non-parameter local variables (mba.vars excluding mba.argidx) "
               "where any use precedes any reaching definition. Reports the variable name (or "
               "synthetic v<idx> for unnamed slots), the read EA, and the function context."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_uninit_use,
        true,
    });

    registry.register_tool({
        std::string("find_integer_overflow_sites"),
        std::string("vuln_advanced"),
        std::string("Locate integer-overflow sites (CWE-190) by running intraprocedural taint analysis, "
               "scanning each m_add/m_sub/m_mul whose operands are tainted by an input source, "
               "tracing the result through the def-use chain, and emitting a finding when the "
               "result reaches an allocation-size or memcpy-length sink (malloc/calloc/realloc/"
               "HeapAlloc/ExAllocatePool*/memcpy/memmove/snprintf/...) without an intervening "
               "overflow guard."),
        {
            {std::string("limit"), std::string("number"),
             std::string("Maximum number of findings to return (default 64, max 1024)."), false},
        },
        handle_find_integer_overflow_sites,
        true,
    });
}

}

}
}
}
