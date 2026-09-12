#include "../aida_pro.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cmath>
#include <deque>
#include <functional>
#include <iomanip>
#include <limits>
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
#include <entry.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <xref.hpp>

#include "../agent_tools.hpp"
#include "../analysis_db.hpp"
#include "../ida_utils.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace callsites
{

namespace
{

using json = nlohmann::json;

constexpr int CACHE_SCHEMA_REVISION = 1;

struct name_index_t
{
    std::unordered_map<std::string, std::vector<ea_t>> by_name;
};

struct callee_match_t
{
    ea_t        callee_ea  = BADADDR;
    std::string canonical_name;
};

inline std::string strip_known_prefixes(const std::string& raw)
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
    if (!out.empty() && out.front() == '_')
    {
        bool only_alnum_underscore = true;
        for (char c : out)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$' || c == '@' || c == '?'))
            {
                only_alnum_underscore = false;
                break;
            }
        }
        if (only_alnum_underscore && out.size() > 1)
            out.erase(0, 1);
    }
    auto at_pos = out.find('@');
    if (at_pos != std::string::npos)
        out.erase(at_pos);
    return out;
}

inline void add_name_for_ea(name_index_t& idx, const std::string& name, ea_t ea)
{
    if (name.empty() || ea == BADADDR)
        return;
    idx.by_name[name].push_back(ea);
    const std::string stripped = strip_known_prefixes(name);
    if (stripped != name && !stripped.empty())
        idx.by_name[stripped].push_back(ea);
}

struct import_collect_ctx_t
{
    name_index_t* idx = nullptr;
};

int idaapi import_enum_collect_cb(ea_t ea, const char* name, uval_t ord, void* param)
{
    (void)ord;
    if (param == nullptr || name == nullptr || ea == BADADDR)
        return 1;
    auto* ctx = static_cast<import_collect_ctx_t*>(param);
    if (ctx->idx == nullptr)
        return 1;
    std::string str_name(name);
    if (str_name.empty())
        return 1;
    add_name_for_ea(*ctx->idx, str_name, ea);
    qstring real;
    if (get_name(&real, ea) > 0 && !real.empty())
    {
        std::string r = real.c_str();
        if (r != str_name)
            add_name_for_ea(*ctx->idx, r, ea);
    }
    return 1;
}

inline name_index_t build_name_index()
{
    name_index_t idx;

    const uint mod_count = get_import_module_qty();
    for (uint i = 0; i < mod_count; ++i)
    {
        import_collect_ctx_t ctx;
        ctx.idx = &idx;
        enum_import_names(static_cast<int>(i), import_enum_collect_cb, &ctx);
    }

    const std::size_t entry_qty = get_entry_qty();
    for (std::size_t i = 0; i < entry_qty; ++i)
    {
        const uval_t ord = get_entry_ordinal(i);
        const ea_t ea = get_entry(ord);
        if (ea == BADADDR)
            continue;
        qstring nm;
        if (get_entry_name(&nm, ord) > 0 && !nm.empty())
            add_name_for_ea(idx, nm.c_str(), ea);
        qstring real;
        if (get_name(&real, ea) > 0 && !real.empty())
        {
            std::string r = real.c_str();
            add_name_for_ea(idx, r, ea);
        }
    }

    const std::size_t func_qty = get_func_qty();
    for (std::size_t i = 0; i < func_qty; ++i)
    {
        func_t* pfn = getn_func(i);
        if (pfn == nullptr)
            continue;
        qstring nm;
        if (get_func_name(&nm, pfn->start_ea) > 0 && !nm.empty())
            add_name_for_ea(idx, nm.c_str(), pfn->start_ea);
        qstring vname;
        if (get_name(&vname, pfn->start_ea) > 0 && !vname.empty())
        {
            std::string v = vname.c_str();
            add_name_for_ea(idx, v, pfn->start_ea);
        }

        if ((pfn->flags & FUNC_THUNK) != 0)
        {
            ea_t fptr = BADADDR;
            const ea_t target = calc_thunk_func_target(pfn, &fptr);
            if (target != BADADDR && target != pfn->start_ea)
            {
                qstring tnm;
                if (get_func_name(&tnm, target) > 0 && !tnm.empty())
                {
                    std::string t = tnm.c_str();
                    if (!t.empty())
                        idx.by_name[t].push_back(pfn->start_ea);
                }
                qstring tnm2;
                if (get_name(&tnm2, target) > 0 && !tnm2.empty())
                {
                    std::string t2 = tnm2.c_str();
                    if (!t2.empty())
                        idx.by_name[t2].push_back(pfn->start_ea);
                    const std::string stripped_t2 = strip_known_prefixes(t2);
                    if (!stripped_t2.empty() && stripped_t2 != t2)
                        idx.by_name[stripped_t2].push_back(pfn->start_ea);
                }
            }
            if (fptr != BADADDR)
            {
                qstring fnm;
                if (get_name(&fnm, fptr) > 0 && !fnm.empty())
                {
                    std::string f = fnm.c_str();
                    if (!f.empty())
                        idx.by_name[f].push_back(pfn->start_ea);
                    const std::string stripped_f = strip_known_prefixes(f);
                    if (!stripped_f.empty() && stripped_f != f)
                        idx.by_name[stripped_f].push_back(pfn->start_ea);
                }
            }
        }
    }

    for (auto& kv : idx.by_name)
    {
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());
    }
    return idx;
}

const name_index_t& cached_name_index()
{
    static std::mutex                          mtx;
    static std::optional<name_index_t>         cache;
    static std::string                         cached_hash;
    std::lock_guard<std::mutex> lk(mtx);
    const std::string current_hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (!cache.has_value() || current_hash != cached_hash)
    {
        cache = build_name_index();
        cached_hash = current_hash;
    }
    return *cache;
}

inline std::vector<callee_match_t> resolve_callee_eas(const std::vector<std::string>& names)
{
    const name_index_t& idx = cached_name_index();
    std::vector<callee_match_t> out;
    std::unordered_set<ea_t> seen;
    for (const auto& nm : names)
    {
        if (nm.empty())
            continue;
        auto it = idx.by_name.find(nm);
        if (it != idx.by_name.end())
        {
            for (ea_t ea : it->second)
            {
                if (seen.insert(ea).second)
                {
                    callee_match_t m;
                    m.callee_ea = ea;
                    m.canonical_name = nm;
                    out.push_back(std::move(m));
                }
            }
        }
        const ea_t direct = get_name_ea(BADADDR, nm.c_str());
        if (direct != BADADDR && seen.insert(direct).second)
        {
            callee_match_t m;
            m.callee_ea = direct;
            m.canonical_name = nm;
            out.push_back(std::move(m));
        }
    }
    return out;
}

inline std::string escape_for_summary(const std::string& s, std::size_t max_len = 64)
{
    std::ostringstream out;
    std::size_t emitted = 0;
    for (std::size_t i = 0; i < s.size() && emitted < max_len; ++i)
    {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '\\' || c == '"')
        {
            out << '\\' << static_cast<char>(c);
            emitted += 2;
        }
        else if (c == '\n')
        {
            out << "\\n";
            emitted += 2;
        }
        else if (c == '\r')
        {
            out << "\\r";
            emitted += 2;
        }
        else if (c == '\t')
        {
            out << "\\t";
            emitted += 2;
        }
        else if (c < 0x20 || c == 0x7F)
        {
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
            emitted += 4;
        }
        else
        {
            out << static_cast<char>(c);
            emitted += 1;
        }
    }
    if (s.size() > max_len)
        out << "...";
    return out.str();
}

inline bool ea_is_in_readonly_segment(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    segment_t* seg = getseg(ea);
    if (seg == nullptr)
        return false;
    if (seg->perm != 0 && (seg->perm & SEGPERM_WRITE) == 0)
        return true;
    qstring name;
    if (get_segm_name(&name, seg, 0) > 0 && !name.empty())
    {
        std::string n = name.c_str();
        std::transform(n.begin(), n.end(), n.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (n.find("rdata") != std::string::npos ||
            n.find("rodata") != std::string::npos ||
            n.find(".text") != std::string::npos ||
            n.find("const") != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

inline bool obj_is_string_constant(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    flags64_t fl = get_flags(ea);
    if (is_strlit(fl))
        return true;
    return false;
}

inline std::string format_obj_summary(ea_t ea)
{
    std::ostringstream out;
    qstring nm;
    if (get_name(&nm, ea) > 0 && !nm.empty())
    {
        out << "&" << nm.c_str();
        return out.str();
    }
    out << "&0x" << std::hex << std::uppercase << static_cast<uint64_t>(ea);
    return out.str();
}

inline std::string read_string_literal(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return std::string();
    qstring s;
    if (get_strlit_contents(&s, ea, -1, STRTYPE_C) > 0)
        return std::string(s.c_str());
    if (get_strlit_contents(&s, ea, -1, STRTYPE_C_16) > 0)
        return std::string(s.c_str());
    return std::string();
}

inline std::string fallback_expr_summary(const cfunc_t* cf, const cexpr_t* expr)
{
    if (cf == nullptr || expr == nullptr)
        return std::string();
    qstring out;
    expr->print1(&out, cf);
    tag_remove(&out);
    std::string s = out.c_str();
    if (s.size() > 96)
    {
        s.resize(93);
        s.append("...");
    }
    return s;
}

inline std::string lvar_name_for(const cfunc_t* cf, const var_ref_t& v)
{
    if (cf == nullptr)
        return std::string();
    cfunc_t* mut = const_cast<cfunc_t*>(cf);
    lvars_t* lv = mut->get_lvars();
    if (lv == nullptr)
        return std::string();
    if (v.idx < 0 || static_cast<std::size_t>(v.idx) >= lv->size())
        return std::string();
    const lvar_t& l = (*lv)[v.idx];
    if (!l.name.empty())
        return std::string(l.name.c_str());
    return std::string();
}

inline std::string summarize_arg(const cfunc_t* cf, const carg_t& arg, bool& out_is_literal)
{
    out_is_literal = false;
    const cexpr_t* expr = static_cast<const cexpr_t*>(&arg);
    const cexpr_t* inner = expr;
    while (inner != nullptr && (inner->op == cot_cast || inner->op == cot_ref) && inner->x != nullptr)
        inner = inner->x;
    if (inner == nullptr)
        inner = expr;

    if (inner->op == cot_str && inner->string != nullptr)
    {
        out_is_literal = true;
        std::string raw(inner->string);
        std::ostringstream ss;
        ss << "\"" << escape_for_summary(raw, 64) << "\"";
        return ss.str();
    }
    if (inner->op == cot_num)
    {
        out_is_literal = true;
        std::ostringstream ss;
        ss << "#0x" << std::hex << std::uppercase << static_cast<uint64_t>(inner->numval());
        return ss.str();
    }
    if (inner->op == cot_obj)
    {
        if (obj_is_string_constant(inner->obj_ea))
        {
            out_is_literal = true;
            std::string raw = read_string_literal(inner->obj_ea);
            if (!raw.empty())
            {
                std::ostringstream ss;
                ss << "\"" << escape_for_summary(raw, 64) << "\"";
                return ss.str();
            }
        }
        if (ea_is_in_readonly_segment(inner->obj_ea))
            out_is_literal = true;
        return format_obj_summary(inner->obj_ea);
    }
    if (inner->op == cot_var)
    {
        std::ostringstream ss;
        ss << "v" << inner->v.idx;
        const std::string lvname = lvar_name_for(cf, inner->v);
        if (!lvname.empty())
            ss << "(" << lvname << ")";
        return ss.str();
    }
    return fallback_expr_summary(cf, expr);
}

struct call_visitor_t : public ctree_visitor_t
{
    cfunc_t*                        cfunc = nullptr;
    std::function<void(cexpr_t*)>   on_call;

    call_visitor_t(cfunc_t* cf, std::function<void(cexpr_t*)> cb)
        : ctree_visitor_t(CV_FAST), cfunc(cf), on_call(std::move(cb)) {}

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr != nullptr && expr->op == cot_call && on_call)
            on_call(expr);
        return 0;
    }
};

struct decompile_cache_t
{
    std::unordered_map<ea_t, cfuncptr_t> entries;
    std::unordered_set<ea_t>             failed;

    cfunc_t* fetch(ea_t func_ea)
    {
        if (func_ea == BADADDR)
            return nullptr;
        auto it = entries.find(func_ea);
        if (it != entries.end())
            return it->second.operator->();
        if (failed.count(func_ea))
            return nullptr;
        if (!init_hexrays_plugin())
        {
            failed.insert(func_ea);
            return nullptr;
        }
        func_t* pfn = get_func(func_ea);
        if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
        {
            failed.insert(func_ea);
            return nullptr;
        }
        try
        {
            cfuncptr_t cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
            if (!cf)
            {
                failed.insert(func_ea);
                return nullptr;
            }
            cfunc_t* raw = cf.operator->();
            entries.emplace(func_ea, std::move(cf));
            return raw;
        }
        catch (const vd_failure_t&)
        {
            failed.insert(func_ea);
            return nullptr;
        }
        catch (...)
        {
            failed.insert(func_ea);
            return nullptr;
        }
    }
};

inline ea_t resolve_call_target_ea(const cexpr_t* call_expr)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->x == nullptr)
        return BADADDR;
    const cexpr_t* x = call_expr->x;
    while (x != nullptr && (x->op == cot_cast || x->op == cot_ref) && x->x != nullptr)
        x = x->x;
    if (x == nullptr)
        return BADADDR;
    if (x->op == cot_obj)
        return x->obj_ea;
    return BADADDR;
}

inline void fill_callsite_args(const cfunc_t* cf, const cexpr_t* call_expr, callsite_t& out)
{
    if (cf == nullptr || call_expr == nullptr || call_expr->a == nullptr)
        return;
    const carglist_t& args = *call_expr->a;
    out.arg_summaries.reserve(args.size());
    out.arg_is_literal.reserve(args.size());
    for (std::size_t i = 0; i < args.size(); ++i)
    {
        bool is_lit = false;
        std::string summary = summarize_arg(cf, args[i], is_lit);
        out.arg_summaries.push_back(std::move(summary));
        out.arg_is_literal.push_back(is_lit);
    }
}

inline std::vector<callsite_t> collect_calls_to_targets(const std::vector<callee_match_t>& callees)
{
    std::vector<callsite_t> result;
    if (callees.empty())
        return result;

    std::unordered_map<ea_t, std::string> ea_to_name;
    ea_to_name.reserve(callees.size());
    for (const auto& m : callees)
        ea_to_name.emplace(m.callee_ea, m.canonical_name);

    std::unordered_map<ea_t, std::vector<ea_t>> caller_to_calls;
    struct pair_hash_t
    {
        std::size_t operator()(const std::pair<ea_t, ea_t>& p) const noexcept
        {
            const std::uint64_t a = static_cast<std::uint64_t>(p.first);
            const std::uint64_t b = static_cast<std::uint64_t>(p.second);
            std::uint64_t h = a ^ (b + 0x9E3779B97F4A7C15ull + (a << 6) + (a >> 2));
            return static_cast<std::size_t>(h);
        }
    };
    std::unordered_map<std::pair<ea_t, ea_t>, std::string, pair_hash_t> call_to_name;
    std::unordered_set<std::pair<ea_t, ea_t>, pair_hash_t>              seen_pairs;

    for (const auto& m : callees)
    {
        xrefblk_t xb;
        for (bool ok = xb.first_to(m.callee_ea, XREF_ALL); ok; ok = xb.next_to())
        {
            if (!xb.iscode)
                continue;
            if (xb.type != fl_CN && xb.type != fl_CF)
                continue;
            func_t* caller = get_func(xb.from);
            if (caller == nullptr)
                continue;
            std::pair<ea_t, ea_t> key(caller->start_ea, xb.from);
            if (!seen_pairs.insert(key).second)
                continue;
            caller_to_calls[caller->start_ea].push_back(xb.from);
            call_to_name[key] = m.canonical_name;
        }
    }

    decompile_cache_t cache;

    for (auto& kv : caller_to_calls)
    {
        ea_t caller_ea = kv.first;
        std::sort(kv.second.begin(), kv.second.end());
        kv.second.erase(std::unique(kv.second.begin(), kv.second.end()), kv.second.end());

        cfunc_t* cf = cache.fetch(caller_ea);
        std::unordered_map<ea_t, cexpr_t*> call_map;
        if (cf != nullptr)
        {
            call_visitor_t visitor(cf, [&](cexpr_t* e) {
                if (e == nullptr)
                    return;
                if (e->ea != BADADDR)
                    call_map[e->ea] = e;
            });
            visitor.apply_to(&cf->body, nullptr);
        }

        for (ea_t call_ea : kv.second)
        {
            callsite_t cs;
            cs.call_ea = call_ea;
            cs.func_ea = caller_ea;
            auto name_it = call_to_name.find(std::pair<ea_t, ea_t>(caller_ea, call_ea));
            if (name_it != call_to_name.end())
                cs.callee_name = name_it->second;

            if (cf != nullptr)
            {
                auto cm = call_map.find(call_ea);
                if (cm != call_map.end())
                {
                    fill_callsite_args(cf, cm->second, cs);
                }
                else
                {
                    cexpr_t* found = nullptr;
                    call_visitor_t enclosing(cf, [&](cexpr_t* e) {
                        if (found != nullptr)
                            return;
                        if (e == nullptr)
                            return;
                        const ea_t target_ea = resolve_call_target_ea(e);
                        if (target_ea == BADADDR)
                            return;
                        if (ea_to_name.count(target_ea) == 0)
                            return;
                        if (e->ea == call_ea)
                            found = e;
                    });
                    enclosing.apply_to(&cf->body, nullptr);
                    if (found != nullptr)
                        fill_callsite_args(cf, found, cs);
                }
            }

            result.push_back(std::move(cs));
        }
    }

    std::sort(result.begin(), result.end(),
              [](const callsite_t& a, const callsite_t& b) {
                  if (a.func_ea != b.func_ea)
                      return a.func_ea < b.func_ea;
                  return a.call_ea < b.call_ea;
              });

    return result;
}

}

std::vector<callsite_t> all_calls_to(const std::vector<std::string>& target_names)
{
    if (target_names.empty())
        return {};
    auto callees = resolve_callee_eas(target_names);
    if (callees.empty())
        return {};
    return collect_calls_to_targets(callees);
}

std::vector<callsite_t> input_source_callsites()
{
    std::vector<std::string> names;
    names.reserve(sizeof(sig::INPUT_SOURCES) / sizeof(sig::INPUT_SOURCES[0]));
    for (const auto& s : sig::INPUT_SOURCES)
        names.emplace_back(s.name);
    return all_calls_to(names);
}

bool is_call_arg_literal(const cfunc_t& cf, ea_t call_ea, int arg_idx)
{
    if (call_ea == BADADDR || arg_idx < 0)
        return false;

    cfunc_t* mut = const_cast<cfunc_t*>(&cf);
    cexpr_t* found = nullptr;

    call_visitor_t visitor(mut, [&](cexpr_t* e) {
        if (found != nullptr)
            return;
        if (e == nullptr)
            return;
        if (e->ea == call_ea)
        {
            found = e;
        }
    });
    visitor.apply_to(&mut->body, nullptr);

    if (found == nullptr || found->a == nullptr)
        return false;
    if (static_cast<std::size_t>(arg_idx) >= found->a->size())
        return false;

    const carg_t& arg = (*found->a)[arg_idx];
    const cexpr_t* expr = static_cast<const cexpr_t*>(&arg);
    while (expr != nullptr && (expr->op == cot_cast || expr->op == cot_ref) && expr->x != nullptr)
        expr = expr->x;
    if (expr == nullptr)
        return false;

    if (expr->op == cot_str)
        return true;
    if (expr->op == cot_num)
        return true;
    if (expr->op == cot_obj)
    {
        if (obj_is_string_constant(expr->obj_ea))
            return true;
        if (ea_is_in_readonly_segment(expr->obj_ea))
            return true;
        return false;
    }
    return false;
}

namespace
{

inline std::string ascii_lower_copy(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

inline bool name_matches_signature_local(const std::string& callee, std::string_view sig)
{
    if (callee.empty() || sig.empty())
        return false;
    const std::string c = ascii_lower_copy(callee);
    const std::string stripped = ascii_lower_copy(strip_known_prefixes(callee));
    const std::string s(sig);
    const std::string sl = ascii_lower_copy(s);
    if (c == sl || stripped == sl)
        return true;
    if (c.size() > sl.size() && c.compare(c.size() - sl.size(), sl.size(), sl) == 0)
        return true;
    if (stripped.size() > sl.size() && stripped.compare(stripped.size() - sl.size(), sl.size(), sl) == 0)
        return true;
    return false;
}

inline bool ea_in_code_segment_local(ea_t ea)
{
    if (ea == BADADDR || !is_loaded(ea))
        return false;
    segment_t* seg = getseg(ea);
    return seg != nullptr && seg->type == SEG_CODE;
}

inline std::string function_name_for_local(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return std::string();
    qstring nm;
    if (get_func_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    if (get_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << static_cast<std::uint64_t>(func_ea);
    return ss.str();
}

inline std::string target_name_for_call(const cexpr_t* call_expr)
{
    if (call_expr == nullptr || call_expr->op != cot_call || call_expr->x == nullptr)
        return std::string();
    const cexpr_t* x = call_expr->x;
    while (x != nullptr && (x->op == cot_cast || x->op == cot_ref) && x->x != nullptr)
        x = x->x;
    if (x == nullptr)
        return std::string();
    if (x->op == cot_helper && x->helper != nullptr)
        return std::string(x->helper);
    if (x->op == cot_obj && x->obj_ea != BADADDR)
    {
        qstring nm;
        if (get_func_name(&nm, x->obj_ea) > 0 && !nm.empty())
            return std::string(nm.c_str());
        if (get_name(&nm, x->obj_ea) > 0 && !nm.empty())
            return std::string(nm.c_str());
    }
    return std::string();
}

struct func_call_index_cache_t
{
    std::string hash;
    std::unordered_map<ea_t, std::vector<call_index_entry_t>> entries;
};

func_call_index_cache_t& call_index_cache()
{
    static func_call_index_cache_t c;
    return c;
}

std::vector<call_index_entry_t> build_function_call_index(ea_t func_ea)
{
    std::vector<call_index_entry_t> out;
    if (func_ea == BADADDR)
        return out;
    if (!init_hexrays_plugin())
        return out;
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;
    func_ea = pfn->start_ea;
    if (!ida_utils::is_safely_decompilable(pfn))
        return out;
    cfuncptr_t cf(nullptr);
    try
    {
        cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
    }
    catch (const vd_failure_t&)
    {
        cf.reset();
    }
    catch (...)
    {
        cf.reset();
    }
    if (!cf)
        return out;
    call_visitor_t visitor(cf.operator->(), [&](cexpr_t* e) {
        if (e == nullptr || e->op != cot_call)
            return;
        call_index_entry_t ci;
        ci.func_ea = func_ea;
        ci.call_ea = e->ea;
        ci.callee_ea = resolve_call_target_ea(e);
        ci.callee_name = target_name_for_call(e);
        if (ci.callee_name.empty() && ci.callee_ea != BADADDR)
            ci.callee_name = function_name_for_local(ci.callee_ea);
        callsite_t tmp;
        fill_callsite_args(cf.operator->(), e, tmp);
        ci.arg_is_literal = std::move(tmp.arg_is_literal);
        out.push_back(std::move(ci));
    });
    visitor.apply_to(&cf->body, nullptr);
    std::sort(out.begin(), out.end(), [](const call_index_entry_t& a, const call_index_entry_t& b) {
        return a.call_ea < b.call_ea;
    });
    return out;
}

inline void reset_call_index_if_needed()
{
    func_call_index_cache_t& c = call_index_cache();
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (c.hash != hash)
    {
        c.hash = hash;
        c.entries.clear();
    }
}

template <typename ArrayT>
void append_source_names(std::vector<std::string>& out, const ArrayT& arr)
{
    for (const auto& s : arr)
        out.emplace_back(s.name);
}

template <typename ArrayT>
void append_sink_names(std::vector<std::string>& out, const ArrayT& arr)
{
    for (const auto& s : arr)
        out.emplace_back(s.name);
}

inline std::vector<std::string> names_for_source_category(const std::string& category)
{
    std::vector<std::string> names;
    const std::string cat = ascii_lower_copy(category.empty() ? std::string("all") : category);
    if (cat == "all" || cat == "network" || cat == "socket")
        append_source_names(names, sig::SOCKET_ACCEPT_SOURCES);
    if (cat == "all" || cat == "network" || cat == "http")
        append_source_names(names, sig::HTTP_SERVER_SOURCES);
    if (cat == "all" || cat == "network" || cat == "websocket")
        append_source_names(names, sig::WEBSOCKET_SOURCES);
    if (cat == "all" || cat == "rpc")
        append_source_names(names, sig::RPC_SERVER_SINKS);
    if (cat == "all" || cat == "com")
        append_source_names(names, sig::COM_SERVER_SINKS);
    if (cat == "all" || cat == "alpc")
        append_source_names(names, sig::ALPC_SOURCES);
    if (cat == "all" || cat == "pipe" || cat == "named_pipe")
        append_source_names(names, sig::NAMED_PIPE_SOURCES);
    if (cat == "all" || cat == "ndis" || cat == "wsk")
        append_source_names(names, sig::NDIS_WSK_SOURCES);
    if (cat == "all" || cat == "kernel" || cat == "kernel_irp")
        append_source_names(names, sig::KERNEL_IRP_SOURCES);
    if (cat == "all" || cat == "classic_input" || cat == "input")
        append_source_names(names, sig::INPUT_SOURCES);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

inline std::vector<std::string> names_for_sink_category(const std::string& category)
{
    std::vector<std::string> names;
    const std::string cat = ascii_lower_copy(category.empty() ? std::string("all") : category);
    if (cat == "all" || cat == "buffer_overflow" || cat == "memory")
        append_sink_names(names, sig::BUFFER_OVERFLOW_SINKS);
    if (cat == "all" || cat == "command_injection")
        append_sink_names(names, sig::COMMAND_INJECTION_SINKS);
    if (cat == "all" || cat == "path_traversal")
        append_sink_names(names, sig::PATH_TRAVERSAL_SINKS);
    if (cat == "all" || cat == "format_string")
        append_sink_names(names, sig::FORMAT_STRING_FUNCS);
    if (cat == "all" || cat == "safearray")
        append_sink_names(names, sig::SAFEARRAY_PARSER_SINKS);
    if (cat == "all" || cat == "deserialization")
        append_sink_names(names, sig::DESERIALIZATION_SINKS);
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

inline bool call_name_in_array(const std::string& name, const std::vector<std::string>& names)
{
    for (const auto& n : names)
    {
        if (name_matches_signature_local(name, n))
            return true;
    }
    return false;
}

struct len_compare_visitor_t : public ctree_visitor_t
{
    cfunc_t* cf = nullptr;
    int count = 0;
    explicit len_compare_visitor_t(cfunc_t* f) : ctree_visitor_t(CV_FAST), cf(f) {}
    bool expr_has_len_name(cexpr_t* e)
    {
        if (e == nullptr || cf == nullptr)
            return false;
        if (e->op == cot_var)
        {
            lvars_t* lv = cf->get_lvars();
            if (lv != nullptr && e->v.idx >= 0 && static_cast<std::size_t>(e->v.idx) < lv->size())
            {
                std::string nm = ascii_lower_copy((*lv)[e->v.idx].name.c_str());
                return nm.find("len") != std::string::npos ||
                       nm.find("size") != std::string::npos ||
                       nm.find("count") != std::string::npos ||
                       nm.find("cb") != std::string::npos ||
                       nm.find("cch") != std::string::npos;
            }
        }
        if (e->x != nullptr && expr_has_len_name(e->x))
            return true;
        if (e->y != nullptr && expr_has_len_name(e->y))
            return true;
        return false;
    }
    int idaapi visit_expr(cexpr_t* e) override
    {
        if (e == nullptr)
            return 0;
        if (e->op == cot_sle || e->op == cot_sge || e->op == cot_slt || e->op == cot_sgt ||
            e->op == cot_ule || e->op == cot_uge || e->op == cot_ult || e->op == cot_ugt)
        {
            if (expr_has_len_name(e->x) || expr_has_len_name(e->y))
                ++count;
        }
        return 0;
    }
};

inline json callsite_json_with_name(const callsite_t& cs)
{
    json j = to_json(cs);
    j["caller_name"] = function_name_for_local(cs.func_ea);
    return j;
}

inline json validator_summary_to_json(const validator_summary_t& s)
{
    json j;
    j["func_ea"] = static_cast<std::uint64_t>(s.func_ea);
    j["func_name"] = function_name_for_local(s.func_ea);
    j["length_size_comparisons"] = s.length_size_comparisons;
    j["validators_seen"] = s.validators_seen;
    j["auth_gates_seen"] = s.auth_gates_seen;
    j["integer_math_seen"] = s.integer_math_seen;
    j["validator_call_eas"] = json::array();
    for (ea_t e : s.validator_call_eas)
        j["validator_call_eas"].push_back(static_cast<std::uint64_t>(e));
    j["auth_gate_call_eas"] = json::array();
    for (ea_t e : s.auth_gate_call_eas)
        j["auth_gate_call_eas"].push_back(static_cast<std::uint64_t>(e));
    j["integer_math_call_eas"] = json::array();
    for (ea_t e : s.integer_math_call_eas)
        j["integer_math_call_eas"].push_back(static_cast<std::uint64_t>(e));
    return j;
}

inline bool summary_has_validator(const validator_summary_t& s)
{
    return !s.validators_seen.empty() || s.length_size_comparisons > 0 || !s.integer_math_seen.empty();
}

inline bool summary_has_auth(const validator_summary_t& s)
{
    return !s.auth_gates_seen.empty();
}

inline std::uint64_t fnv1a64(const std::string& s)
{
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s)
    {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

inline std::string binary_cache_token()
{
    std::ostringstream ss;
    ss << aida_db::AnalysisDB::instance().get_binary_hash()
       << "|sig=" << sig::SIGNATURE_DATABASE_REVISION
       << "|schema=" << CACHE_SCHEMA_REVISION;
    return ss.str();
}

std::optional<json> finding_cache_lookup(const std::string& type, const std::string& key)
{
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (hash.empty())
        return std::nullopt;
    const ea_t key_ea = static_cast<ea_t>(fnv1a64(binary_cache_token() + "|" + key));
    auto entries = aida_db::AnalysisDB::instance().get_analysis(hash, key_ea);
    for (const auto& e : entries)
    {
        if (e.analysis_type == type && !e.result.empty())
        {
            try
            {
                return json::parse(e.result);
            }
            catch (...)
            {
                return std::nullopt;
            }
        }
    }
    return std::nullopt;
}

void finding_cache_store(const std::string& type, const std::string& key, const json& value)
{
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (hash.empty())
        return;
    aida_db::analysis_entry_t entry;
    entry.address = static_cast<ea_t>(fnv1a64(binary_cache_token() + "|" + key));
    entry.function_name.clear();
    entry.analysis_type = type;
    entry.result = value.dump();
    entry.model_name = "static";
    entry.timestamp_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    aida_db::AnalysisDB::instance().add_analysis(hash, entry);
}

inline std::vector<ea_t> unique_func_eas_from_calls(const std::vector<callsite_t>& calls)
{
    std::vector<ea_t> funcs;
    for (const auto& cs : calls)
    {
        if (cs.func_ea != BADADDR)
            funcs.push_back(cs.func_ea);
    }
    std::sort(funcs.begin(), funcs.end());
    funcs.erase(std::unique(funcs.begin(), funcs.end()), funcs.end());
    return funcs;
}

}

std::vector<callsite_t> all_calls_to_public_wrapper(const std::vector<std::string>& target_names,
                                                    std::size_t limit,
                                                    std::vector<std::string>* unresolved_names,
                                                    bool* capped)
{
    if (capped != nullptr)
        *capped = false;
    if (unresolved_names != nullptr)
        unresolved_names->clear();
    if (target_names.empty())
        return {};
    std::vector<std::string> names;
    names.reserve(target_names.size());
    std::unordered_set<std::string> seen_names;
    const name_index_t& idx = cached_name_index();
    for (const auto& raw : target_names)
    {
        if (raw.empty())
            continue;
        if (!seen_names.insert(raw).second)
            continue;
        names.push_back(raw);
        if (unresolved_names != nullptr && idx.by_name.find(raw) == idx.by_name.end() &&
            get_name_ea(BADADDR, raw.c_str()) == BADADDR)
        {
            unresolved_names->push_back(raw);
        }
    }
    std::vector<callsite_t> calls = all_calls_to(names);
    if (limit > 0 && calls.size() > limit)
    {
        calls.resize(limit);
        if (capped != nullptr)
            *capped = true;
    }
    return calls;
}

std::vector<call_index_entry_t> per_function_call_index(ea_t func_ea)
{
    if (func_ea == BADADDR)
        return {};
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return {};
    func_ea = pfn->start_ea;
    reset_call_index_if_needed();
    func_call_index_cache_t& c = call_index_cache();
    auto it = c.entries.find(func_ea);
    if (it != c.entries.end())
        return it->second;
    std::vector<call_index_entry_t> built = build_function_call_index(func_ea);
    c.entries.emplace(func_ea, built);
    return built;
}

validator_summary_t summarize_validators_in_function(ea_t func_ea)
{
    validator_summary_t out;
    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return out;
    out.func_ea = pfn->start_ea;
    std::set<std::string> vals;
    std::set<std::string> auths;
    std::set<std::string> maths;
    for (const auto& ci : per_function_call_index(out.func_ea))
    {
        for (auto v : sig::LENGTH_VALIDATOR_HELPERS)
        {
            if (name_matches_signature_local(ci.callee_name, v))
            {
                vals.insert(std::string(v));
                out.validator_call_eas.push_back(ci.call_ea);
            }
        }
        for (auto v : sig::AUTH_GATE_HELPERS)
        {
            if (name_matches_signature_local(ci.callee_name, v))
            {
                auths.insert(std::string(v));
                out.auth_gate_call_eas.push_back(ci.call_ea);
            }
        }
        for (auto v : sig::INTEGER_MATH_HELPERS)
        {
            if (name_matches_signature_local(ci.callee_name, v))
            {
                maths.insert(std::string(v));
                out.integer_math_call_eas.push_back(ci.call_ea);
            }
        }
    }
    out.validators_seen.assign(vals.begin(), vals.end());
    out.auth_gates_seen.assign(auths.begin(), auths.end());
    out.integer_math_seen.assign(maths.begin(), maths.end());
    cfuncptr_t cf(nullptr);
    if (init_hexrays_plugin() && ida_utils::is_safely_decompilable(pfn))
    {
        try
        {
            cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
        }
        catch (...)
        {
            cf.reset();
        }
    }
    if (cf)
    {
        len_compare_visitor_t v(cf.operator->());
        v.apply_to(&cf->body, nullptr);
        out.length_size_comparisons = v.count;
    }
    return out;
}

nlohmann::json reverse_slice_sink_to_sources(ea_t sink_call_ea,
                                             int max_depth,
                                             const std::string& source_category,
                                             int max_paths,
                                             bool require_no_validator,
                                             bool require_pre_auth)
{
    if (max_depth <= 0)
        max_depth = 6;
    if (max_depth > 12)
        max_depth = 12;
    if (max_paths <= 0)
        max_paths = 8;
    if (max_paths > 32)
        max_paths = 32;
    json data;
    data["sink_call_ea"] = static_cast<std::uint64_t>(sink_call_ea);
    data["paths"] = json::array();
    data["more_paths_truncated"] = false;
    func_t* sink_func = get_func(sink_call_ea);
    if (sink_func == nullptr)
        return data;
    std::vector<std::string> source_names = names_for_source_category(source_category);
    std::vector<callsite_t> sources = all_calls_to(source_names);
    std::unordered_set<ea_t> source_funcs;
    for (const auto& cs : sources)
        source_funcs.insert(cs.func_ea);
    std::deque<std::pair<ea_t, std::vector<ea_t>>> q;
    std::unordered_set<ea_t> visited;
    q.push_back({sink_func->start_ea, {sink_func->start_ea}});
    visited.insert(sink_func->start_ea);
    while (!q.empty())
    {
        auto cur = q.front();
        q.pop_front();
        ea_t fea = cur.first;
        int depth = static_cast<int>(cur.second.size()) - 1;
        validator_summary_t sum = summarize_validators_in_function(fea);
        if (source_funcs.count(fea) != 0)
        {
            bool passes_validator = summary_has_validator(sum);
            bool passes_auth = summary_has_auth(sum);
            for (ea_t hop : cur.second)
            {
                if (hop == fea)
                    continue;
                validator_summary_t hs = summarize_validators_in_function(hop);
                passes_validator = passes_validator || summary_has_validator(hs);
                passes_auth = passes_auth || summary_has_auth(hs);
            }
            if ((!require_no_validator || !passes_validator) &&
                (!require_pre_auth || !passes_auth))
            {
                json p;
                p["functions"] = json::array();
                for (ea_t hop : cur.second)
                    p["functions"].push_back(static_cast<std::uint64_t>(hop));
                p["call_eas"] = json::array({static_cast<std::uint64_t>(sink_call_ea)});
                p["validators_seen"] = json::array();
                p["auth_gates_seen"] = json::array();
                for (ea_t hop : cur.second)
                {
                    validator_summary_t hs = summarize_validators_in_function(hop);
                    for (const auto& v : hs.validators_seen)
                        p["validators_seen"].push_back(v);
                    for (const auto& v : hs.integer_math_seen)
                        p["validators_seen"].push_back(v);
                    for (const auto& v : hs.auth_gates_seen)
                        p["auth_gates_seen"].push_back(v);
                }
                p["passes_validator"] = passes_validator;
                p["passes_auth_gate"] = passes_auth;
                data["paths"].push_back(std::move(p));
                if (static_cast<int>(data["paths"].size()) >= max_paths)
                {
                    data["more_paths_truncated"] = true;
                    break;
                }
            }
        }
        if (depth >= max_depth)
            continue;
        xrefblk_t xb;
        for (bool ok = xb.first_to(fea, XREF_ALL); ok; ok = xb.next_to())
        {
            if (!xb.iscode || (xb.type != fl_CN && xb.type != fl_CF))
                continue;
            func_t* caller = get_func(xb.from);
            if (caller == nullptr)
                continue;
            if (!visited.insert(caller->start_ea).second)
                continue;
            std::vector<ea_t> next = cur.second;
            next.push_back(caller->start_ea);
            q.push_back({caller->start_ea, std::move(next)});
        }
    }
    data["count"] = data["paths"].size();
    return data;
}

nlohmann::json forward_reachability_source_to_sinks(ea_t source_func_ea,
                                                    int max_depth,
                                                    const std::string& sink_category,
                                                    int max_hits,
                                                    bool require_no_validator)
{
    if (max_depth <= 0)
        max_depth = 6;
    if (max_depth > 12)
        max_depth = 12;
    if (max_hits <= 0)
        max_hits = 64;
    if (max_hits > 512)
        max_hits = 512;
    json data;
    data["source_func_ea"] = static_cast<std::uint64_t>(source_func_ea);
    data["hits"] = json::array();
    data["truncated"] = false;
    func_t* start = get_func(source_func_ea);
    if (start == nullptr)
        return data;
    source_func_ea = start->start_ea;
    std::vector<std::string> sink_names = names_for_sink_category(sink_category);
    std::vector<callsite_t> sinks = all_calls_to(sink_names);
    std::unordered_map<ea_t, std::vector<callsite_t>> sinks_by_func;
    for (const auto& cs : sinks)
        sinks_by_func[cs.func_ea].push_back(cs);
    std::deque<std::pair<ea_t, int>> q;
    std::unordered_set<ea_t> visited;
    q.push_back({source_func_ea, 0});
    visited.insert(source_func_ea);
    while (!q.empty())
    {
        auto [cur, depth] = q.front();
        q.pop_front();
        validator_summary_t sum = summarize_validators_in_function(cur);
        auto hit_it = sinks_by_func.find(cur);
        if (hit_it != sinks_by_func.end())
        {
            bool has_val = summary_has_validator(sum);
            if (!require_no_validator || !has_val)
            {
                for (const auto& cs : hit_it->second)
                {
                    json h = callsite_json_with_name(cs);
                    h["depth"] = depth;
                    h["validator_summary"] = validator_summary_to_json(sum);
                    h["passes_validator"] = has_val;
                    data["hits"].push_back(std::move(h));
                    if (static_cast<int>(data["hits"].size()) >= max_hits)
                    {
                        data["truncated"] = true;
                        data["count"] = data["hits"].size();
                        return data;
                    }
                }
            }
        }
        if (depth >= max_depth)
            continue;
        func_t* pfn = get_func(cur);
        if (pfn == nullptr)
            continue;
        func_item_iterator_t fii(pfn);
        for (bool ok = fii.first(); ok; ok = fii.next_head())
        {
            ea_t item = fii.current();
            xrefblk_t xb;
            for (bool ix = xb.first_from(item, XREF_ALL); ix; ix = xb.next_from())
            {
                if (!xb.iscode || (xb.type != fl_CN && xb.type != fl_CF))
                    continue;
                func_t* callee = get_func(xb.to);
                if (callee == nullptr)
                    continue;
                if (!visited.insert(callee->start_ea).second)
                    continue;
                q.push_back({callee->start_ea, depth + 1});
            }
        }
    }
    data["count"] = data["hits"].size();
    return data;
}

nlohmann::json protocol_attack_surface_report()
{
    const std::string cache_key = "protocol_attack_surface_report";
    if (auto cached = finding_cache_lookup("vuln_protocol_surface_v1", cache_key); cached.has_value())
    {
        (*cached)["cached"] = true;
        return *cached;
    }
    struct family_t { const char* name; std::vector<std::string> names; };
    std::vector<family_t> fams;
    fams.push_back({"rpc", names_for_source_category("rpc")});
    fams.push_back({"com", names_for_source_category("com")});
    fams.push_back({"alpc", names_for_source_category("alpc")});
    fams.push_back({"pipe", names_for_source_category("pipe")});
    fams.push_back({"socket", names_for_source_category("socket")});
    fams.push_back({"http", names_for_source_category("http")});
    fams.push_back({"websocket", names_for_source_category("websocket")});
    fams.push_back({"ndis", names_for_source_category("ndis")});
    fams.push_back({"kernel_irp", names_for_source_category("kernel_irp")});
    json data;
    data["binary_kind"] = "user";
    if (aida::vuln::kernel_engine::is_kernel_driver())
        data["binary_kind"] = "kernel_driver";
    data["families"] = json::object();
    for (const auto& fam : fams)
    {
        json ingress = json::array();
        std::vector<callsite_t> calls = all_calls_to(fam.names);
        std::unordered_map<ea_t, std::vector<callsite_t>> by_func;
        for (const auto& cs : calls)
            by_func[cs.func_ea].push_back(cs);
        for (const auto& kv : by_func)
        {
            json e;
            e["func_ea"] = static_cast<std::uint64_t>(kv.first);
            e["name"] = function_name_for_local(kv.first);
            e["callsites"] = kv.second.size();
            e["role"] = aida::vuln::surface_engine::classify_function_role(kv.first);
            json fw = forward_reachability_source_to_sinks(kv.first, 4, "all", 32, false);
            e["downstream_sinks"] = fw.value("count", static_cast<std::size_t>(0));
            e["callsite_eas"] = json::array();
            for (const auto& cs : kv.second)
                e["callsite_eas"].push_back(static_cast<std::uint64_t>(cs.call_ea));
            ingress.push_back(std::move(e));
        }
        data["families"][fam.name]["ingress"] = std::move(ingress);
    }
    data["cached"] = false;
    finding_cache_store("vuln_protocol_surface_v1", cache_key, data);
    return data;
}

nlohmann::json find_pre_auth_paths(const std::string& source_category,
                                   const std::string& sink_category,
                                   int max_depth,
                                   int max_paths,
                                   bool require_no_validator)
{
    const std::string key = "preauth|" + source_category + "|" + sink_category + "|" +
                            std::to_string(max_depth) + "|" + std::to_string(max_paths) +
                            "|" + (require_no_validator ? "1" : "0");
    if (auto cached = finding_cache_lookup("vuln_preauth_paths_v1", key); cached.has_value())
    {
        (*cached)["cached"] = true;
        return *cached;
    }
    if (max_paths <= 0)
        max_paths = 32;
    if (max_paths > 128)
        max_paths = 128;
    json data;
    data["paths"] = json::array();
    data["source_category"] = source_category;
    data["sink_category"] = sink_category;
    data["truncated"] = false;
    std::vector<callsite_t> sources = all_calls_to(names_for_source_category(source_category));
    std::vector<ea_t> funcs = unique_func_eas_from_calls(sources);
    for (ea_t fea : funcs)
    {
        json fwd = forward_reachability_source_to_sinks(fea, max_depth, sink_category, max_paths, require_no_validator);
        for (const auto& hit : fwd["hits"])
        {
            bool passes_auth = false;
            if (hit.contains("validator_summary") && hit["validator_summary"].is_object())
                passes_auth = !hit["validator_summary"].value("auth_gates_seen", json::array()).empty();
            if (passes_auth)
                continue;
            data["paths"].push_back(hit);
            if (static_cast<int>(data["paths"].size()) >= max_paths)
            {
                data["truncated"] = true;
                break;
            }
        }
        if (data["truncated"].get<bool>())
            break;
    }
    data["count"] = data["paths"].size();
    data["cached"] = false;
    finding_cache_store("vuln_preauth_paths_v1", key, data);
    return data;
}

nlohmann::json find_dispatch_tables(int min_entries,
                                    int max_entries,
                                    bool include_vtables)
{
    if (min_entries <= 0)
        min_entries = 4;
    if (min_entries > 1024)
        min_entries = 1024;
    if (max_entries <= 0)
        max_entries = 256;
    if (max_entries > 4096)
        max_entries = 4096;
    if (max_entries < min_entries)
        max_entries = min_entries;
    const std::string key = "dispatch|" + std::to_string(min_entries) + "|" +
                            std::to_string(max_entries) + "|" + (include_vtables ? "1" : "0");
    if (auto cached = finding_cache_lookup("vuln_dispatch_tables_v1", key); cached.has_value())
    {
        (*cached)["cached"] = true;
        return *cached;
    }
    const bool is64 = inf_is_64bit();
    const ea_t step = is64 ? 8 : 4;
    json tables = json::array();
    const int qty = get_segm_qty();
    for (int i = 0; i < qty; ++i)
    {
        segment_t* seg = getnseg(i);
        if (seg == nullptr || seg->start_ea >= seg->end_ea)
            continue;
        if (seg->type == SEG_CODE)
            continue;
        if (seg->perm != 0 && (seg->perm & SEGPERM_WRITE) != 0)
            continue;
        for (ea_t ea = seg->start_ea; ea + step <= seg->end_ea;)
        {
            std::vector<ea_t> slots;
            ea_t cur = ea;
            while (cur + step <= seg->end_ea && static_cast<int>(slots.size()) < max_entries)
            {
                if (!is_loaded(cur))
                    break;
                ea_t target = is64 ? static_cast<ea_t>(get_qword(cur))
                                   : static_cast<ea_t>(get_dword(cur));
                if (target == 0 || !ea_in_code_segment_local(target))
                    break;
                func_t* tf = get_func(target);
                if (tf == nullptr || tf->start_ea != target)
                    break;
                slots.push_back(target);
                cur += step;
            }
            if (static_cast<int>(slots.size()) >= min_entries)
            {
                qstring nm;
                std::string near_name;
                if (get_name(&nm, ea) > 0 && !nm.empty())
                    near_name = nm.c_str();
                bool likely_vtable = near_name.find("vft") != std::string::npos ||
                                     near_name.find("vtable") != std::string::npos ||
                                     near_name.find("RTTI") != std::string::npos;
                if (include_vtables || !likely_vtable)
                {
                    json t;
                    t["table_ea"] = static_cast<std::uint64_t>(ea);
                    t["entry_count"] = slots.size();
                    t["pointer_size"] = static_cast<int>(step);
                    t["near_name"] = near_name;
                    t["likely_vtable"] = likely_vtable;
                    t["entries"] = json::array();
                    for (ea_t s : slots)
                    {
                        json e;
                        e["ea"] = static_cast<std::uint64_t>(s);
                        e["name"] = function_name_for_local(s);
                        t["entries"].push_back(std::move(e));
                    }
                    tables.push_back(std::move(t));
                }
                ea = cur;
            }
            else
            {
                ea += step;
            }
        }
    }
    json data;
    data["count"] = tables.size();
    data["tables"] = std::move(tables);
    data["pointer_size"] = static_cast<int>(step);
    data["cached"] = false;
    finding_cache_store("vuln_dispatch_tables_v1", key, data);
    return data;
}

namespace
{

struct parser_shape_visitor_t : public ctree_visitor_t
{
    cfunc_t* cf = nullptr;
    int loops = 0;
    int switches = 0;
    int max_cases = 0;
    int idx_nonliteral = 0;
    int byte_ops = 0;
    int copy_calls_in_loop = 0;
    int loop_depth = 0;
    explicit parser_shape_visitor_t(cfunc_t* f) : ctree_visitor_t(CV_PARENTS), cf(f) {}
    int idaapi visit_insn(cinsn_t* ins) override
    {
        if (ins == nullptr)
            return 0;
        if (ins->op == cit_for || ins->op == cit_while || ins->op == cit_do)
        {
            ++loops;
            ++loop_depth;
        }
        else if (ins->op == cit_switch && ins->cswitch != nullptr)
        {
            ++switches;
            int cases = 0;
            for (std::size_t i = 0; i < ins->cswitch->cases.size(); ++i)
                cases += static_cast<int>(ins->cswitch->cases[i].values.size());
            if (cases > max_cases)
                max_cases = cases;
        }
        return 0;
    }
    int idaapi leave_insn(cinsn_t* ins) override
    {
        if (ins != nullptr && (ins->op == cit_for || ins->op == cit_while || ins->op == cit_do) && loop_depth > 0)
            --loop_depth;
        return 0;
    }
    int idaapi visit_expr(cexpr_t* e) override
    {
        if (e == nullptr)
            return 0;
        if (e->op == cot_idx && e->y != nullptr)
        {
            const cexpr_t* idx = e->y;
            while (idx != nullptr && (idx->op == cot_cast || idx->op == cot_ref) && idx->x != nullptr)
                idx = idx->x;
            if (idx != nullptr && idx->op != cot_num)
                ++idx_nonliteral;
        }
        if (e->op == cot_band || e->op == cot_bor || e->op == cot_xor ||
            e->op == cot_shl || e->op == cot_sshr || e->op == cot_ushr)
            ++byte_ops;
        if (loop_depth > 0 && e->op == cot_call)
        {
            std::string nm = target_name_for_call(e);
            if (name_matches_signature_local(nm, "memcpy") ||
                name_matches_signature_local(nm, "memmove") ||
                name_matches_signature_local(nm, "RtlCopyMemory") ||
                name_matches_signature_local(nm, "RtlMoveMemory"))
            {
                ++copy_calls_in_loop;
            }
        }
        return 0;
    }
};

struct arith_expr_visitor_t : public ctree_visitor_t
{
    bool has_arith = false;
    arith_expr_visitor_t() : ctree_visitor_t(CV_FAST) {}
    int idaapi visit_expr(cexpr_t* e) override
    {
        if (e != nullptr && (e->op == cot_add || e->op == cot_mul || e->op == cot_shl))
            has_arith = true;
        return has_arith ? 1 : 0;
    }
};

bool expr_contains_arith(cexpr_t* e)
{
    if (e == nullptr)
        return false;
    arith_expr_visitor_t v;
    v.apply_to_exprs(e, nullptr);
    return v.has_arith;
}

}

nlohmann::json find_parser_shaped_functions(int top_k, bool only_reachable_from_network)
{
    if (top_k <= 0)
        top_k = 50;
    if (top_k > 512)
        top_k = 512;
    const std::string key = "parser|" + std::to_string(top_k) + "|" +
                            (only_reachable_from_network ? "1" : "0");
    if (auto cached = finding_cache_lookup("vuln_parser_shape_v1", key); cached.has_value())
    {
        (*cached)["cached"] = true;
        return *cached;
    }
    std::unordered_set<ea_t> reachable;
    if (only_reachable_from_network)
    {
        for (ea_t e : aida::vuln::surface_engine::attacker_reachable_functions())
            reachable.insert(e);
    }
    json rows = json::array();
    std::vector<std::pair<int, json>> scored;
    if (init_hexrays_plugin())
    {
        const std::size_t fq = get_func_qty();
        for (std::size_t i = 0; i < fq; ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr)
                continue;
            if (only_reachable_from_network && reachable.count(pfn->start_ea) == 0)
                continue;
            if (!ida_utils::is_safely_decompilable(pfn))
                continue;
            cfuncptr_t cf(nullptr);
            try
            {
                cf = decompile_func(pfn, nullptr, DECOMP_NO_WAIT);
            }
            catch (...)
            {
                cf.reset();
            }
            if (!cf)
                continue;
            parser_shape_visitor_t v(cf.operator->());
            v.apply_to(&cf->body, nullptr);
            int score = v.loops * 3 + v.idx_nonliteral * 4 + v.copy_calls_in_loop * 5 +
                        v.switches * 2 + (v.max_cases >= 4 ? v.max_cases : 0) + v.byte_ops;
            if (score <= 0)
                continue;
            json r;
            r["func_ea"] = static_cast<std::uint64_t>(pfn->start_ea);
            r["func_name"] = function_name_for_local(pfn->start_ea);
            r["score"] = score;
            r["loops"] = v.loops;
            r["switches"] = v.switches;
            r["max_cases"] = v.max_cases;
            r["idx_nonliteral"] = v.idx_nonliteral;
            r["copy_calls_in_loop"] = v.copy_calls_in_loop;
            r["byte_ops"] = v.byte_ops;
            scored.push_back({score, std::move(r)});
        }
    }
    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
        return a.first > b.first;
    });
    for (std::size_t i = 0; i < scored.size() && static_cast<int>(i) < top_k; ++i)
        rows.push_back(std::move(scored[i].second));
    json data;
    data["count"] = rows.size();
    data["functions"] = std::move(rows);
    data["only_reachable_from_network"] = only_reachable_from_network;
    data["cached"] = false;
    finding_cache_store("vuln_parser_shape_v1", key, data);
    return data;
}

nlohmann::json find_safearray_misuse(int limit)
{
    if (limit <= 0)
        limit = 64;
    if (limit > 1024)
        limit = 1024;
    std::vector<std::string> names;
    append_sink_names(names, sig::SAFEARRAY_PARSER_SINKS);
    std::vector<callsite_t> calls = all_calls_to(names);
    json findings = json::array();
    for (const auto& cs : calls)
    {
        if (static_cast<int>(findings.size()) >= limit)
            break;
        validator_summary_t sum = summarize_validators_in_function(cs.func_ea);
        bool has_safe_math = !sum.integer_math_seen.empty();
        if (has_safe_math)
            continue;
        json f;
        f["call_ea"] = static_cast<std::uint64_t>(cs.call_ea);
        f["func_ea"] = static_cast<std::uint64_t>(cs.func_ea);
        f["func_name"] = function_name_for_local(cs.func_ea);
        f["callee"] = cs.callee_name;
        f["cwe"] = 129;
        f["confidence"] = "plausible";
        f["rationale"] = "SAFEARRAY parser call occurs in a function with no recognized checked multiply or bounds helper";
        findings.push_back(std::move(f));
    }
    json data;
    data["count"] = findings.size();
    data["findings"] = std::move(findings);
    data["limit"] = limit;
    return data;
}

nlohmann::json find_int_overflow_alloc_from_input(int limit)
{
    if (limit <= 0)
        limit = 64;
    if (limit > 1024)
        limit = 1024;
    std::vector<std::string> allocs;
    for (auto a : sig::ALLOC_FUNCS)
        allocs.emplace_back(a);
    std::vector<callsite_t> calls = all_calls_to(allocs);
    std::unordered_set<ea_t> input_funcs;
    for (const auto& cs : input_source_callsites())
        input_funcs.insert(cs.func_ea);
    json findings = json::array();
    decompile_cache_t cache;
    for (const auto& cs : calls)
    {
        if (static_cast<int>(findings.size()) >= limit)
            break;
        cfunc_t* cf = cache.fetch(cs.func_ea);
        if (cf == nullptr)
            continue;
        cexpr_t* found = nullptr;
        call_visitor_t vis(cf, [&](cexpr_t* e) {
            if (found != nullptr || e == nullptr || e->ea != cs.call_ea || e->a == nullptr)
                return;
            found = e;
        });
        vis.apply_to(&cf->body, nullptr);
        if (found == nullptr || found->a == nullptr || found->a->empty())
            continue;
        bool arith = false;
        for (std::size_t i = 0; i < found->a->size(); ++i)
        {
            cexpr_t* arg = static_cast<cexpr_t*>(&(*found->a)[i]);
            if (expr_contains_arith(arg))
            {
                arith = true;
                break;
            }
        }
        if (!arith)
            continue;
        validator_summary_t sum = summarize_validators_in_function(cs.func_ea);
        if (!sum.integer_math_seen.empty())
            continue;
        bool near_input = input_funcs.count(cs.func_ea) != 0;
        json f;
        f["call_ea"] = static_cast<std::uint64_t>(cs.call_ea);
        f["func_ea"] = static_cast<std::uint64_t>(cs.func_ea);
        f["func_name"] = function_name_for_local(cs.func_ea);
        f["callee"] = cs.callee_name;
        f["cwe"] = 190;
        f["near_input_source"] = near_input;
        f["confidence"] = near_input ? "likely" : "plausible";
        f["rationale"] = "Allocation size argument contains add/mul/shift arithmetic and no recognized checked integer helper in the function";
        findings.push_back(std::move(f));
    }
    json data;
    data["count"] = findings.size();
    data["findings"] = std::move(findings);
    data["limit"] = limit;
    return data;
}

namespace tools
{

namespace
{

inline int extract_int_param(const json& params, const std::string& key, int default_value)
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

inline std::string extract_string_param(const json& params, const std::string& key,
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

inline bool extract_bool_param(const json& params, const std::string& key, bool default_value)
{
    if (!params.is_object())
        return default_value;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return default_value;
    if (it->is_boolean())
        return it->get<bool>();
    if (it->is_number_integer())
        return it->get<std::int64_t>() != 0;
    if (it->is_number_unsigned())
        return it->get<std::uint64_t>() != 0;
    if (it->is_string())
    {
        const std::string v = ascii_lower_copy(it->get<std::string>());
        if (v == "true" || v == "1" || v == "yes")
            return true;
        if (v == "false" || v == "0" || v == "no")
            return false;
    }
    return default_value;
}

inline std::vector<std::string> extract_names_param(const json& params, const std::string& key)
{
    std::vector<std::string> names;
    if (!params.is_object())
        return names;
    auto it = params.find(key);
    if (it == params.end() || it->is_null())
        return names;
    if (it->is_string())
    {
        names.push_back(it->get<std::string>());
        return names;
    }
    if (it->is_array())
    {
        for (const auto& v : *it)
        {
            if (v.is_string())
                names.push_back(v.get<std::string>());
        }
    }
    return names;
}

inline const char* cwe_name(int id)
{
    switch (id)
    {
    case 22:  return "Path Traversal";
    case 78:  return "OS Command Injection";
    case 120: return "Buffer Copy without Checking Size of Input";
    case 134: return "Use of Externally-Controlled Format String";
    case 242: return "Use of Inherently Dangerous Function";
    case 327: return "Use of a Broken or Risky Cryptographic Algorithm";
    case 328: return "Use of Weak Hash";
    case 770: return "Allocation of Resources Without Limits or Throttling";
    case 798: return "Use of Hard-coded Credentials";
    default:  return "Unknown CWE";
    }
}

inline severity_t default_severity_for_category(const std::string& category)
{
    if (category == "buffer_overflow")  return severity_t::high;
    if (category == "format_string")    return severity_t::high;
    if (category == "command_injection") return severity_t::high;
    if (category == "path_traversal")   return severity_t::medium;
    return severity_t::info;
}

inline std::string make_finding_id(const std::string& category, ea_t call_ea)
{
    std::ostringstream ss;
    ss << "vuln/" << category << "/" << std::hex << std::uppercase
       << static_cast<uint64_t>(call_ea);
    return ss.str();
}

inline json findings_to_json(const std::vector<vuln_finding_t>& findings)
{
    json arr = json::array();
    for (const auto& f : findings)
        arr.push_back(to_json(f));
    return arr;
}

inline std::string sink_set_signature(const std::vector<std::string>& names)
{
    std::ostringstream ss;
    ss << "rev=" << CACHE_SCHEMA_REVISION << ";n=";
    for (const auto& n : names)
        ss << n << "|";
    return ss.str();
}

inline ea_t cache_key_address(const std::string& signature)
{
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : signature)
    {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    return static_cast<ea_t>(h);
}

inline std::optional<json> cache_lookup(const std::string& analysis_type, ea_t key_ea)
{
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (hash.empty())
        return std::nullopt;
    auto entries = aida_db::AnalysisDB::instance().get_analysis(hash, key_ea);
    for (const auto& e : entries)
    {
        if (e.analysis_type == analysis_type && !e.result.empty())
        {
            try
            {
                return json::parse(e.result);
            }
            catch (...)
            {
                return std::nullopt;
            }
        }
    }
    return std::nullopt;
}

inline void cache_store(const std::string& analysis_type, ea_t key_ea, const json& payload)
{
    const std::string hash = aida_db::AnalysisDB::instance().get_binary_hash();
    if (hash.empty())
        return;
    aida_db::analysis_entry_t entry;
    entry.address       = key_ea;
    entry.function_name.clear();
    entry.analysis_type = analysis_type;
    entry.result        = payload.dump();
    entry.model_name    = "static";
    entry.timestamp_ms  = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
    aida_db::AnalysisDB::instance().add_analysis(hash, entry);
}

struct sink_with_category_t
{
    const sig::sink_signature_t* sink     = nullptr;
    std::string                  category;
};

inline std::vector<sink_with_category_t> resolve_buffer_overflow_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::BUFFER_OVERFLOW_SINKS)
        out.push_back({&s, "buffer_overflow"});
    return out;
}

inline std::vector<sink_with_category_t> resolve_command_injection_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::COMMAND_INJECTION_SINKS)
        out.push_back({&s, "command_injection"});
    return out;
}

inline std::vector<sink_with_category_t> resolve_path_traversal_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::PATH_TRAVERSAL_SINKS)
        out.push_back({&s, "path_traversal"});
    return out;
}

inline std::vector<sink_with_category_t> resolve_format_string_sinks()
{
    std::vector<sink_with_category_t> out;
    for (const auto& s : sig::FORMAT_STRING_FUNCS)
        out.push_back({&s, "format_string"});
    return out;
}

inline std::vector<sink_with_category_t> filter_sinks(const std::string& category)
{
    if (category == "buffer_overflow")
        return resolve_buffer_overflow_sinks();
    if (category == "command_injection")
        return resolve_command_injection_sinks();
    if (category == "path_traversal")
        return resolve_path_traversal_sinks();
    if (category == "format_string")
        return resolve_format_string_sinks();
    std::vector<sink_with_category_t> out;
    auto a = resolve_buffer_overflow_sinks();
    auto b = resolve_command_injection_sinks();
    auto c = resolve_path_traversal_sinks();
    auto d = resolve_format_string_sinks();
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    out.insert(out.end(), c.begin(), c.end());
    out.insert(out.end(), d.begin(), d.end());
    return out;
}

inline confidence_t derive_sink_confidence(const sig::sink_signature_t& sink, const callsite_t& cs)
{
    if (sink.len_arg_index >= 0 &&
        static_cast<std::size_t>(sink.len_arg_index) < cs.arg_is_literal.size() &&
        cs.arg_is_literal[sink.len_arg_index])
    {
        return confidence_t::plausible;
    }
    if (!cs.arg_is_literal.empty() && !cs.arg_is_literal[0])
        return confidence_t::likely;
    return confidence_t::plausible;
}

inline severity_t derive_sink_severity(const sig::sink_signature_t& sink,
                                       const callsite_t& cs,
                                       const std::string& category)
{
    severity_t base = default_severity_for_category(category);
    if (sink.len_arg_index >= 0 &&
        static_cast<std::size_t>(sink.len_arg_index) < cs.arg_is_literal.size() &&
        cs.arg_is_literal[sink.len_arg_index])
    {
        if (base == severity_t::high)
            return severity_t::medium;
        if (base == severity_t::medium)
            return severity_t::low;
    }
    return base;
}

inline json callsite_evidence(const callsite_t& cs)
{
    json ev;
    ev["call_ea"]    = static_cast<uint64_t>(cs.call_ea);
    ev["func_ea"]    = static_cast<uint64_t>(cs.func_ea);
    ev["callee"]     = cs.callee_name;
    ev["callsite"]   = to_json(cs);
    return ev;
}

inline std::string func_name_for(ea_t func_ea)
{
    qstring nm;
    if (get_func_name(&nm, func_ea) > 0 && !nm.empty())
        return std::string(nm.c_str());
    qstring vn;
    if (get_name(&vn, func_ea) > 0 && !vn.empty())
        return std::string(vn.c_str());
    std::ostringstream ss;
    ss << "sub_" << std::hex << std::uppercase << static_cast<uint64_t>(func_ea);
    return ss.str();
}

}

agent_tools::tool_result_t handle_find_vulnerable_sinks(const json& params)
{
    const std::string category = extract_string_param(params, "category", "all");
    const int limit_raw        = extract_int_param(params, "limit", 256);
    int limit = limit_raw;
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    if (category != "all" && category != "buffer_overflow" && category != "command_injection" &&
        category != "path_traversal" && category != "format_string")
    {
        return agent_tools::tool_result_t::error(
            std::string("category must be one of: all, buffer_overflow, command_injection, "
                   "path_traversal, format_string"));
    }

    auto sinks = filter_sinks(category);
    if (sinks.empty())
        return agent_tools::tool_result_t::error(std::string("No sinks resolved for category"));

    std::vector<std::string> names;
    names.reserve(sinks.size());
    for (const auto& s : sinks)
        names.emplace_back(std::string(s.sink->name));

    const std::string analysis_type = "vuln_callsites_v1";
    const std::string sig_str       = sink_set_signature(names);
    const ea_t        cache_key     = cache_key_address(sig_str + "|cat=" + category);

    if (auto cached = cache_lookup(analysis_type, cache_key); cached.has_value() &&
        cached->is_object() && cached->contains("findings"))
    {
        json data = *cached;
        if (data.contains("findings") && data["findings"].is_array() &&
            data["findings"].size() > static_cast<std::size_t>(limit))
        {
            json trimmed = json::array();
            for (std::size_t i = 0; i < static_cast<std::size_t>(limit) &&
                 i < data["findings"].size(); ++i)
                trimmed.push_back(data["findings"][i]);
            data["findings"] = std::move(trimmed);
        }
        data["cached"] = true;
        const std::size_t count = data.value("count", static_cast<std::size_t>(0));
        std::ostringstream msg;
        msg << std::string("Vulnerable-sink scan (cached): ") << count << std::string(" finding(s)");
        return agent_tools::tool_result_t::ok(msg.str(), data);
    }

    std::vector<vuln_finding_t> findings;
    findings.reserve(64);
    std::unordered_map<std::string, std::size_t> by_category;
    by_category["buffer_overflow"]   = 0;
    by_category["command_injection"] = 0;
    by_category["path_traversal"]    = 0;
    by_category["format_string"]     = 0;

    for (const auto& sk : sinks)
    {
        if (findings.size() >= static_cast<std::size_t>(limit))
            break;
        const std::string sink_name(sk.sink->name);
        std::vector<callsite_t> calls = all_calls_to({sink_name});
        if (calls.empty())
            continue;
        for (const auto& cs : calls)
        {
            if (findings.size() >= static_cast<std::size_t>(limit))
                break;
            vuln_finding_t f;
            f.id         = make_finding_id(sk.category, cs.call_ea);
            f.primary_ea = cs.call_ea;
            f.related_eas.push_back(cs.func_ea);
            cwe_t cwe;
            cwe.id   = sk.sink->primary_cwe;
            cwe.name = cwe_name(sk.sink->primary_cwe);
            f.cwes.push_back(cwe);
            f.severity   = derive_sink_severity(*sk.sink, cs, sk.category);
            f.confidence = derive_sink_confidence(*sk.sink, cs);

            std::ostringstream title;
            title << "Dangerous call to " << sink_name << " in " << func_name_for(cs.func_ea);
            f.title = title.str();

            std::ostringstream rat;
            rat << "Call to " << sink_name << " (CWE-" << sk.sink->primary_cwe << ", "
                << cwe.name << ") at "
                << agent_tools::helpers::format_address(cs.call_ea)
                << " inside " << func_name_for(cs.func_ea);
            if (sk.sink->len_arg_index >= 0 &&
                static_cast<std::size_t>(sk.sink->len_arg_index) < cs.arg_summaries.size())
            {
                rat << "; length argument [" << sk.sink->len_arg_index << "] = "
                    << cs.arg_summaries[sk.sink->len_arg_index];
                if (sk.sink->len_arg_index < static_cast<int>(cs.arg_is_literal.size()) &&
                    cs.arg_is_literal[sk.sink->len_arg_index])
                {
                    rat << " (literal)";
                }
                else
                {
                    rat << " (non-literal, may be attacker-controlled)";
                }
            }
            f.rationale = rat.str();
            f.evidence  = callsite_evidence(cs);
            f.evidence["category"] = sk.category;
            findings.push_back(std::move(f));
            by_category[sk.category] += 1;
        }
    }

    json data;
    data["count"]    = findings.size();
    data["limit"]    = limit;
    data["category"] = category;
    data["findings"] = findings_to_json(findings);
    json bc = json::object();
    for (const auto& kv : by_category)
        bc[kv.first] = kv.second;
    data["by_category"] = std::move(bc);
    data["cached"]      = false;

    cache_store(analysis_type, cache_key, data);

    std::ostringstream msg;
    msg << std::string("Vulnerable-sink scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_input_sources(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    std::vector<callsite_t> calls = input_source_callsites();

    std::unordered_map<std::string, std::size_t> by_source;
    json arr = json::array();
    int emitted = 0;
    for (const auto& cs : calls)
    {
        if (emitted >= limit)
            break;
        json entry = to_json(cs);
        entry["caller_name"] = func_name_for(cs.func_ea);
        arr.push_back(std::move(entry));
        by_source[cs.callee_name] += 1;
        ++emitted;
    }

    json data;
    data["count"]      = arr.size();
    data["limit"]      = limit;
    data["callsites"]  = std::move(arr);
    data["total_unique_calls"] = calls.size();
    json bs = json::object();
    for (const auto& kv : by_source)
        bs[kv.first] = kv.second;
    data["by_source"] = std::move(bs);

    std::ostringstream msg;
    msg << std::string("Input-source enumeration: ") << data["count"].get<std::size_t>()
        << std::string(" callsite(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_format_string_bugs(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    if (!init_hexrays_plugin())
        return agent_tools::tool_result_t::error(std::string("Hex-Rays not available"));

    std::vector<vuln_finding_t> findings;
    decompile_cache_t cache;

    for (const auto& fs : sig::FORMAT_STRING_FUNCS)
    {
        if (findings.size() >= static_cast<std::size_t>(limit))
            break;
        const std::string sink_name(fs.name);
        std::vector<callsite_t> calls = all_calls_to({sink_name});
        for (const auto& cs : calls)
        {
            if (findings.size() >= static_cast<std::size_t>(limit))
                break;
            cfunc_t* cf = cache.fetch(cs.func_ea);
            if (cf == nullptr)
                continue;
            const bool literal = is_call_arg_literal(*cf, cs.call_ea, fs.format_arg_index);
            if (literal)
                continue;

            vuln_finding_t f;
            f.id         = make_finding_id("format_string", cs.call_ea);
            f.primary_ea = cs.call_ea;
            f.related_eas.push_back(cs.func_ea);
            cwe_t cwe;
            cwe.id   = fs.primary_cwe;
            cwe.name = cwe_name(fs.primary_cwe);
            f.cwes.push_back(cwe);
            f.severity   = severity_t::high;
            f.confidence = confidence_t::likely;

            std::ostringstream title;
            title << "Non-literal format string passed to " << sink_name
                  << " in " << func_name_for(cs.func_ea);
            f.title = title.str();

            std::ostringstream rat;
            rat << "Call to " << sink_name << " at "
                << agent_tools::helpers::format_address(cs.call_ea)
                << " uses a non-literal value as the format-string argument (index "
                << fs.format_arg_index << "). When that value is attacker-controlled this "
                << "yields an arbitrary read/write primitive (CWE-134).";
            f.rationale = rat.str();
            f.evidence  = callsite_evidence(cs);
            f.evidence["format_arg_index"] = fs.format_arg_index;
            if (static_cast<std::size_t>(fs.format_arg_index) < cs.arg_summaries.size())
                f.evidence["format_arg_summary"] = cs.arg_summaries[fs.format_arg_index];
            f.evidence["category"] = "format_string";

            findings.push_back(std::move(f));
        }
    }

    json data;
    data["count"]    = findings.size();
    data["limit"]    = limit;
    data["findings"] = findings_to_json(findings);
    data["primary_cwe"] = 134;

    std::ostringstream msg;
    msg << std::string("Format-string-bug scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

inline std::vector<vuln_finding_t> scan_dangerous_sinks(const std::vector<sink_with_category_t>& sinks,
                                                       const std::string& category_label,
                                                       severity_t default_severity,
                                                       std::size_t limit)
{
    std::vector<vuln_finding_t> findings;
    findings.reserve(64);

    for (const auto& sk : sinks)
    {
        if (findings.size() >= limit)
            break;
        const std::string sink_name(sk.sink->name);
        const int arg_idx = sk.sink->sensitive_arg_index;
        std::vector<callsite_t> calls = all_calls_to({sink_name});
        for (const auto& cs : calls)
        {
            if (findings.size() >= limit)
                break;
            vuln_finding_t f;
            f.id         = make_finding_id(category_label, cs.call_ea);
            f.primary_ea = cs.call_ea;
            f.related_eas.push_back(cs.func_ea);
            cwe_t cwe;
            cwe.id   = sk.sink->primary_cwe;
            cwe.name = cwe_name(sk.sink->primary_cwe);
            f.cwes.push_back(cwe);
            f.severity   = default_severity;
            f.confidence = confidence_t::plausible;

            bool sensitive_is_literal = false;
            std::string sensitive_summary;
            if (arg_idx >= 0 && static_cast<std::size_t>(arg_idx) < cs.arg_is_literal.size())
            {
                sensitive_is_literal = cs.arg_is_literal[arg_idx];
                if (static_cast<std::size_t>(arg_idx) < cs.arg_summaries.size())
                    sensitive_summary = cs.arg_summaries[arg_idx];
                if (!sensitive_is_literal)
                    f.confidence = confidence_t::likely;
                else
                    f.severity = severity_t::low;
            }

            std::ostringstream title;
            title << "Call to " << sink_name << " in " << func_name_for(cs.func_ea);
            f.title = title.str();

            std::ostringstream rat;
            rat << "Call to " << sink_name << " (CWE-" << sk.sink->primary_cwe << ", "
                << cwe.name << ") at "
                << agent_tools::helpers::format_address(cs.call_ea)
                << " inside " << func_name_for(cs.func_ea);
            if (arg_idx >= 0)
            {
                rat << "; sensitive argument [" << arg_idx << "] = " << sensitive_summary;
                rat << (sensitive_is_literal ? " (literal)" : " (non-literal, may be attacker-controlled)");
            }
            else if (arg_idx == sig::STRUCT_INDIRECT)
            {
                rat << "; sensitive payload is carried through a structure pointer";
            }
            f.rationale = rat.str();
            f.evidence  = callsite_evidence(cs);
            f.evidence["category"] = category_label;
            f.evidence["sensitive_arg_index"] = arg_idx;
            f.evidence["sensitive_arg_is_literal"] = sensitive_is_literal;

            findings.push_back(std::move(f));
        }
    }

    return findings;
}

agent_tools::tool_result_t handle_find_command_injection_sites(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    auto sinks = resolve_command_injection_sinks();
    auto findings = scan_dangerous_sinks(sinks, "command_injection",
                                         severity_t::high,
                                         static_cast<std::size_t>(limit));

    json data;
    data["count"]       = findings.size();
    data["limit"]       = limit;
    data["findings"]    = findings_to_json(findings);
    data["primary_cwe"] = 78;

    std::ostringstream msg;
    msg << std::string("Command-injection scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_path_traversal_sites(const json& params)
{
    int limit = extract_int_param(params, "limit", 256);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be a positive integer"));
    if (limit > 4096)
        limit = 4096;

    auto sinks = resolve_path_traversal_sinks();
    auto findings = scan_dangerous_sinks(sinks, "path_traversal",
                                         severity_t::medium,
                                         static_cast<std::size_t>(limit));

    json data;
    data["count"]       = findings.size();
    data["limit"]       = limit;
    data["findings"]    = findings_to_json(findings);
    data["primary_cwe"] = 22;

    std::ostringstream msg;
    msg << std::string("Path-traversal scan: ") << findings.size() << std::string(" finding(s)");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_find_calls_to(const json& params)
{
    std::vector<std::string> names = extract_names_param(params, "names");
    if (names.empty())
        names = extract_names_param(params, "name");
    if (names.empty())
        return agent_tools::tool_result_t::error(std::string("names must contain at least one symbol"), "bad_param");
    if (names.size() > 256)
        return agent_tools::tool_result_t::error(std::string("find_calls_to accepts at most 256 names"), "bad_param");
    int limit = extract_int_param(params, "limit", 4096);
    if (limit <= 0)
        return agent_tools::tool_result_t::error(std::string("limit must be positive"), "bad_param");
    if (limit > 16384)
        limit = 16384;
    std::vector<std::string> unresolved;
    bool capped = false;
    std::vector<callsite_t> calls = all_calls_to_public_wrapper(names, static_cast<std::size_t>(limit),
                                                                &unresolved, &capped);
    json arr = json::array();
    for (const auto& cs : calls)
        arr.push_back(callsite_json_with_name(cs));
    json data;
    data["callsites"] = std::move(arr);
    data["unresolved_names"] = unresolved;
    data["count"] = calls.size();
    data["capped"] = capped;
    return agent_tools::tool_result_t::ok(std::string("Callsites found: ") + std::to_string(calls.size()), data);
}

agent_tools::tool_result_t handle_summarize_validators_in_function(const json& params)
{
    const std::string addr_s = extract_string_param(params, "address", "");
    auto parsed = agent_tools::helpers::parse_address(addr_s);
    if (!parsed.has_value())
        return agent_tools::tool_result_t::error(std::string("address is required"), "bad_param");
    func_t* pfn = get_func(*parsed);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(std::string("address does not lie inside a function"), "no_function_at_addr");
    validator_summary_t s = summarize_validators_in_function(pfn->start_ea);
    return agent_tools::tool_result_t::ok(std::string("Validator summary"), validator_summary_to_json(s));
}

agent_tools::tool_result_t handle_reverse_slice_sink_to_sources(const json& params)
{
    const std::string sink_s = extract_string_param(params, "sink_call_ea", "");
    auto parsed = agent_tools::helpers::parse_address(sink_s);
    if (!parsed.has_value())
        return agent_tools::tool_result_t::error(std::string("sink_call_ea is required"), "bad_param");
    json data = reverse_slice_sink_to_sources(*parsed,
        extract_int_param(params, "max_depth", 6),
        extract_string_param(params, "source_category", "network"),
        extract_int_param(params, "max_paths", 8),
        extract_bool_param(params, "require_no_validator", false),
        extract_bool_param(params, "require_pre_auth", false));
    return agent_tools::tool_result_t::ok(std::string("Reverse slice paths: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_forward_reachability_source_to_sinks(const json& params)
{
    const std::string src_s = extract_string_param(params, "source_func_ea", "");
    auto parsed = agent_tools::helpers::parse_address(src_s);
    if (!parsed.has_value())
        return agent_tools::tool_result_t::error(std::string("source_func_ea is required"), "bad_param");
    func_t* pfn = get_func(*parsed);
    if (pfn == nullptr)
        return agent_tools::tool_result_t::error(std::string("source_func_ea does not lie inside a function"), "no_function_at_addr");
    json data = forward_reachability_source_to_sinks(pfn->start_ea,
        extract_int_param(params, "max_depth", 6),
        extract_string_param(params, "sink_category", "all"),
        extract_int_param(params, "max_hits", 64),
        extract_bool_param(params, "require_no_validator", false));
    return agent_tools::tool_result_t::ok(std::string("Forward sink reachability: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_protocol_attack_surface_report(const json&)
{
    json data = protocol_attack_surface_report();
    return agent_tools::tool_result_t::ok(std::string("Protocol attack surface report"), data);
}

agent_tools::tool_result_t handle_find_pre_auth_paths(const json& params)
{
    json data = find_pre_auth_paths(
        extract_string_param(params, "source_category", "network"),
        extract_string_param(params, "sink_category", "all"),
        extract_int_param(params, "max_depth", 6),
        extract_int_param(params, "max_paths", 32),
        extract_bool_param(params, "require_no_validator", true));
    return agent_tools::tool_result_t::ok(std::string("Pre-auth paths: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_find_dispatch_tables(const json& params)
{
    json data = find_dispatch_tables(
        extract_int_param(params, "min_entries", 4),
        extract_int_param(params, "max_entries", 256),
        extract_bool_param(params, "include_vtables", true));
    return agent_tools::tool_result_t::ok(std::string("Dispatch tables: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_find_parser_shaped_functions(const json& params)
{
    json data = find_parser_shaped_functions(
        extract_int_param(params, "top_k", 50),
        extract_bool_param(params, "only_reachable_from_network", true));
    return agent_tools::tool_result_t::ok(std::string("Parser-shaped functions: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_find_safearray_misuse(const json& params)
{
    json data = find_safearray_misuse(extract_int_param(params, "limit", 64));
    return agent_tools::tool_result_t::ok(std::string("SAFEARRAY misuse candidates: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

agent_tools::tool_result_t handle_find_int_overflow_alloc_from_input(const json& params)
{
    json data = find_int_overflow_alloc_from_input(extract_int_param(params, "limit", 64));
    return agent_tools::tool_result_t::ok(std::string("Integer-overflow allocation candidates: ") +
                                          std::to_string(data.value("count", static_cast<std::size_t>(0))), data);
}

void register_tier1_callsite_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();
    auto register_taint_required = [&](agent_tools::tool_definition_t def) {
        def.required_indices = {std::string("taint_engine")};
        registry.register_tool(def);
    };
    auto register_nondeterministic = [&](agent_tools::tool_definition_t def) {
        def.deterministic = false;
        registry.register_tool(def);
    };

    {
        agent_tools::tool_param_t category_param;
        category_param.name        = std::string("category");
        category_param.type        = std::string("string");
        category_param.description = std::string("Sink category to enumerate. One of: all, "
                                            "buffer_overflow, command_injection, path_traversal, "
                                            "format_string. Defaults to all.");
        category_param.required    = false;
        category_param.enum_values = {
            std::string("all"),
            std::string("buffer_overflow"),
            std::string("command_injection"),
            std::string("path_traversal"),
            std::string("format_string"),
        };
        agent_tools::tool_param_t limit_param;
        limit_param.name        = std::string("limit");
        limit_param.type        = std::string("number");
        limit_param.description = std::string("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            std::string("find_vulnerable_sinks"),
            std::string("vuln"),
            std::string("Enumerate calls to known dangerous sink functions across the binary. "
                   "Categories cover buffer overflow (strcpy/memcpy/sprintf/...), command injection "
                   "(system/exec*/CreateProcess/ShellExecute/...), path traversal (fopen/CreateFile/...), "
                   "and format-string sinks (printf/sprintf/...). Each finding records the caller, "
                   "callsite EA, summarized arguments, CWE, severity, and confidence."),
            { category_param, limit_param },
            handle_find_vulnerable_sinks,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = std::string("limit");
        limit_param.type        = std::string("number");
        limit_param.description = std::string("Maximum number of callsites to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            std::string("find_input_sources"),
            std::string("vuln"),
            std::string("Enumerate callsites for known input-source functions (recv/recvfrom, ReadFile, "
                   "fread/fgets, scanf-family, getenv, GetCommandLine, RegQueryValueEx, "
                   "WinHttpReadData, etc.). These are the canonical taint origins for downstream "
                   "taint analysis."),
            { limit_param },
            handle_find_input_sources,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = std::string("limit");
        limit_param.type        = std::string("number");
        limit_param.description = std::string("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            std::string("find_format_string_bugs"),
            std::string("vuln"),
            std::string("Locate format-string vulnerabilities (CWE-134) by decompiling each caller of a "
                   "printf-family sink and confirming that the format-string argument at the "
                   "documented position is NOT a literal. Findings are emitted with severity=high "
                   "and confidence=likely."),
            { limit_param },
            handle_find_format_string_bugs,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = std::string("limit");
        limit_param.type        = std::string("number");
        limit_param.description = std::string("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            std::string("find_command_injection_sites"),
            std::string("vuln"),
            std::string("Locate command-execution callsites (system/_wsystem/popen/exec*/CreateProcess*/"
                   "ShellExecute*/WinExec) and classify whether the command-line / file argument at "
                   "the documented position is a literal or a non-literal (likely attacker-influenced) "
                   "value. CWE-78."),
            { limit_param },
            handle_find_command_injection_sites,
            true,
        });
    }

    {
        agent_tools::tool_param_t limit_param;
        limit_param.name        = std::string("limit");
        limit_param.type        = std::string("number");
        limit_param.description = std::string("Maximum number of findings to return (default 256, max 4096).");
        limit_param.required    = false;

        registry.register_tool({
            std::string("find_path_traversal_sites"),
            std::string("vuln"),
            std::string("Locate filesystem-API callsites (fopen/_wfopen/open/CreateFile*/Move/Copy/Delete) "
                   "and classify whether the path argument at the documented position is a literal "
                   "or a non-literal (likely attacker-influenced) value. CWE-22."),
            { limit_param },
            handle_find_path_traversal_sites,
            true,
        });
    }

    registry.register_tool({
        std::string("find_calls_to"),
        std::string("vuln"),
        std::string("Resolve up to 256 target names through the cached import/export/function name index and return every code callsite xref with caller, callee, and summarized literal arguments."),
        {
            {std::string("names"), std::string("array"), std::string("Target function/import names. Hard cap: 256."), true},
            {std::string("limit"), std::string("number"), std::string("Maximum callsites to return (default 4096, max 16384)."), false},
        },
        handle_find_calls_to,
        true,
    });

    registry.register_tool({
        std::string("summarize_validators_in_function"),
        std::string("vuln"),
        std::string("Summarize length validators, integer checked-math helpers, auth gates, and len/size/count comparisons in one function."),
        {
            {std::string("address"), std::string("string"), std::string("Address inside the function to summarize."), true},
        },
        handle_summarize_validators_in_function,
        true,
    });

    register_taint_required({
        std::string("reverse_slice_sink_to_sources"),
        std::string("vuln_advanced"),
        std::string("Reverse BFS from a sink callsite through caller xrefs to protocol/input sources, annotating validators and auth gates seen along each path."),
        {
            {std::string("sink_call_ea"), std::string("string"), std::string("Sink callsite address."), true},
            {std::string("max_depth"), std::string("number"), std::string("Maximum caller depth (default 6, max 12)."), false},
            {std::string("source_category"), std::string("string"), std::string("Source family: network, rpc, com, alpc, pipe, socket, http, websocket, ndis, kernel_irp, input, all."), false},
            {std::string("max_paths"), std::string("number"), std::string("Maximum paths (default 8, max 32)."), false},
            {std::string("require_no_validator"), std::string("boolean"), std::string("Only return paths with no validator evidence."), false},
            {std::string("require_pre_auth"), std::string("boolean"), std::string("Only return paths with no auth-gate evidence."), false},
        },
        handle_reverse_slice_sink_to_sources,
        true,
    });

    registry.register_tool({
        std::string("forward_reachability_source_to_sinks"),
        std::string("vuln_advanced"),
        std::string("Forward BFS from a source function to dangerous sinks, returning sink hits and per-function validator annotations."),
        {
            {std::string("source_func_ea"), std::string("string"), std::string("Source function address."), true},
            {std::string("max_depth"), std::string("number"), std::string("Maximum callee depth (default 6, max 12)."), false},
            {std::string("sink_category"), std::string("string"), std::string("Sink family: all, buffer_overflow, command_injection, path_traversal, format_string, safearray, deserialization."), false},
            {std::string("max_hits"), std::string("number"), std::string("Maximum sink hits (default 64, max 512)."), false},
            {std::string("require_no_validator"), std::string("boolean"), std::string("Only include sink functions with no validator evidence."), false},
        },
        handle_forward_reachability_source_to_sinks,
        true,
    });

    register_nondeterministic({
        std::string("protocol_attack_surface_report"),
        std::string("vuln_advanced"),
        std::string("Survey RPC, COM, ALPC, named pipe, socket, HTTP, WebSocket, NDIS/WSK, and kernel IRP ingress callsites, grouped by handler function with downstream sink counts."),
        {},
        handle_protocol_attack_surface_report,
        true,
    });

    register_taint_required({
        std::string("find_pre_auth_paths"),
        std::string("vuln_advanced"),
        std::string("Fan out from protocol/input ingress functions to sinks and return paths that do not pass an auth-gate; optionally require no validator evidence."),
        {
            {std::string("source_category"), std::string("string"), std::string("Source family (default network)."), false},
            {std::string("sink_category"), std::string("string"), std::string("Sink family (default all)."), false},
            {std::string("max_depth"), std::string("number"), std::string("Maximum depth (default 6)."), false},
            {std::string("max_paths"), std::string("number"), std::string("Maximum paths (default 32)."), false},
            {std::string("require_no_validator"), std::string("boolean"), std::string("Only return no-validator paths (default true)."), false},
        },
        handle_find_pre_auth_paths,
        true,
    });

    registry.register_tool({
        std::string("find_dispatch_tables"),
        std::string("vuln"),
        std::string("Structurally scan read-only segments for pointer-sized arrays whose entries all resolve to function starts in code segments. Uses 8-byte slots for 64-bit IDBs and 4-byte slots for 32-bit IDBs."),
        {
            {std::string("min_entries"), std::string("number"), std::string("Minimum consecutive function pointers (default 4)."), false},
            {std::string("max_entries"), std::string("number"), std::string("Maximum entries per table (default 256)."), false},
            {std::string("include_vtables"), std::string("boolean"), std::string("Include likely vtable-shaped arrays (default true)."), false},
        },
        handle_find_dispatch_tables,
        true,
    });

    registry.register_tool({
        std::string("find_parser_shaped_functions"),
        std::string("vuln_advanced"),
        std::string("Rank functions by parser-shaped control flow: loops, switch dispatch, non-literal indexing, copy calls inside loops, and byte operations."),
        {
            {std::string("top_k"), std::string("number"), std::string("Maximum ranked functions (default 50)."), false},
            {std::string("only_reachable_from_network"), std::string("boolean"), std::string("Filter to attacker-reachable functions (default true)."), false},
        },
        handle_find_parser_shaped_functions,
        true,
    });

    registry.register_tool({
        std::string("find_safearray_misuse"),
        std::string("vuln_advanced"),
        std::string("Find SAFEARRAY parser calls in functions lacking recognized checked integer math or bounds helpers."),
        {
            {std::string("limit"), std::string("number"), std::string("Maximum findings (default 64)."), false},
        },
        handle_find_safearray_misuse,
        true,
    });

    registry.register_tool({
        std::string("find_int_overflow_alloc_from_input"),
        std::string("vuln_advanced"),
        std::string("Find allocation calls whose size arguments contain add/mul/shift arithmetic without checked integer helpers, prioritizing input-source functions."),
        {
            {std::string("limit"), std::string("number"), std::string("Maximum findings (default 64)."), false},
        },
        handle_find_int_overflow_alloc_from_input,
        true,
    });
}

}

}
}
}
