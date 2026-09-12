#include "../aida_pro.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <bytes.hpp>
#include <funcs.hpp>
#include <hexrays.hpp>
#include <ida.hpp>
#include <name.hpp>

#include "../agent_tools.hpp"
#include "../ida_utils.hpp"
#include "microcode_engine.hpp"
#include "symbolic_engine.hpp"
#include "smt_solver.hpp"
#include "vuln_common.hpp"
#include "vuln_signatures.hpp"
#include "vuln_tools.hpp"

namespace aida
{
namespace vuln
{
namespace microcode
{

namespace
{

constexpr int kMaxMopJsonDepth = 4;

std::string ea_to_hex(ea_t ea)
{
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

const char* opcode_to_mnemonic(mcode_t op)
{
    switch (op)
    {
    case m_nop:    return "nop";
    case m_stx:    return "stx";
    case m_ldx:    return "ldx";
    case m_ldc:    return "ldc";
    case m_mov:    return "mov";
    case m_neg:    return "neg";
    case m_lnot:   return "lnot";
    case m_bnot:   return "bnot";
    case m_xds:    return "xds";
    case m_xdu:    return "xdu";
    case m_low:    return "low";
    case m_high:   return "high";
    case m_add:    return "add";
    case m_sub:    return "sub";
    case m_mul:    return "mul";
    case m_udiv:   return "udiv";
    case m_sdiv:   return "sdiv";
    case m_umod:   return "umod";
    case m_smod:   return "smod";
    case m_or:     return "or";
    case m_and:    return "and";
    case m_xor:    return "xor";
    case m_shl:    return "shl";
    case m_shr:    return "shr";
    case m_sar:    return "sar";
    case m_cfadd:  return "cfadd";
    case m_ofadd:  return "ofadd";
    case m_cfshl:  return "cfshl";
    case m_cfshr:  return "cfshr";
    case m_sets:   return "sets";
    case m_seto:   return "seto";
    case m_setp:   return "setp";
    case m_setnz:  return "setnz";
    case m_setz:   return "setz";
    case m_setae:  return "setae";
    case m_setb:   return "setb";
    case m_seta:   return "seta";
    case m_setbe:  return "setbe";
    case m_setg:   return "setg";
    case m_setge:  return "setge";
    case m_setl:   return "setl";
    case m_setle:  return "setle";
    case m_jcnd:   return "jcnd";
    case m_jnz:    return "jnz";
    case m_jz:     return "jz";
    case m_jae:    return "jae";
    case m_jb:     return "jb";
    case m_ja:     return "ja";
    case m_jbe:    return "jbe";
    case m_jg:     return "jg";
    case m_jge:    return "jge";
    case m_jl:     return "jl";
    case m_jle:    return "jle";
    case m_jtbl:   return "jtbl";
    case m_ijmp:   return "ijmp";
    case m_goto:   return "goto";
    case m_call:   return "call";
    case m_icall:  return "icall";
    case m_ret:    return "ret";
    case m_push:   return "push";
    case m_pop:    return "pop";
    case m_und:    return "und";
    case m_ext:    return "ext";
    case m_f2i:    return "f2i";
    case m_f2u:    return "f2u";
    case m_i2f:    return "i2f";
    case m_u2f:    return "u2f";
    case m_f2f:    return "f2f";
    case m_fneg:   return "fneg";
    case m_fadd:   return "fadd";
    case m_fsub:   return "fsub";
    case m_fmul:   return "fmul";
    case m_fdiv:   return "fdiv";
    default:       return "?";
    }
}

const char* block_type_to_str(mblock_type_t t)
{
    switch (t)
    {
    case BLT_NONE:  return "none";
    case BLT_STOP:  return "stop";
    case BLT_0WAY:  return "0way";
    case BLT_1WAY:  return "1way";
    case BLT_2WAY:  return "2way";
    case BLT_NWAY:  return "nway";
    case BLT_XTRN:  return "xtrn";
    default:        return "unknown";
    }
}

std::string render_minsn_text(const minsn_t& ins)
{
    qstring qs;
    ins.print(&qs, SHINS_SHORT | SHINS_VALNUM);
    qstring clean;
    tag_remove(&clean, qs);
    return std::string(clean.c_str());
}

std::string render_mop_text(const mop_t& op)
{
    qstring qs;
    op.print(&qs, SHINS_SHORT | SHINS_VALNUM);
    qstring clean;
    tag_remove(&clean, qs);
    return std::string(clean.c_str());
}

std::string lvar_name_for(const mop_t& op)
{
    if (op.t != mop_l || op.l == nullptr || op.l->mba == nullptr)
        return std::string();
    int idx = op.l->idx;
    if (idx < 0 || static_cast<size_t>(idx) >= op.l->mba->vars.size())
        return std::string();
    const lvar_t& v = op.l->mba->vars[idx];
    if (v.name.empty())
        return std::string();
    return std::string(v.name.c_str());
}

std::string global_name_for(ea_t ea)
{
    qstring qn;
    if (get_name(&qn, ea) > 0 && !qn.empty())
        return std::string(qn.c_str());
    return std::string();
}

bool reg_groups_overlap(mreg_t a_reg, int a_size, mreg_t b_reg, int b_size)
{
    if (a_size <= 0)
        a_size = 1;
    if (b_size <= 0)
        b_size = 1;
    sval_t a_lo = static_cast<sval_t>(a_reg);
    sval_t a_hi = a_lo + static_cast<sval_t>(a_size);
    sval_t b_lo = static_cast<sval_t>(b_reg);
    sval_t b_hi = b_lo + static_cast<sval_t>(b_size);
    return a_lo < b_hi && b_lo < a_hi;
}

bool stk_ranges_overlap(sval_t a_off, int a_size, sval_t b_off, int b_size)
{
    if (a_size <= 0)
        a_size = 1;
    if (b_size <= 0)
        b_size = 1;
    sval_t a_hi = a_off + static_cast<sval_t>(a_size);
    sval_t b_hi = b_off + static_cast<sval_t>(b_size);
    return a_off < b_hi && b_off < a_hi;
}

nlohmann::json mop_to_json_depth(const mop_t& op, int depth);

nlohmann::json minsn_to_json_depth(const minsn_t& ins, int depth)
{
    nlohmann::json j;
    j["ea"]        = ea_to_hex(ins.ea);
    j["opcode"]    = opcode_to_mnemonic(ins.opcode);
    j["opcode_id"] = static_cast<int>(ins.opcode);
    j["iprops"]    = static_cast<std::int64_t>(ins.iprops);
    j["text"]      = render_minsn_text(ins);

    if (depth < kMaxMopJsonDepth)
    {
        j["l"] = mop_to_json_depth(ins.l, depth + 1);
        j["r"] = mop_to_json_depth(ins.r, depth + 1);
        j["d"] = mop_to_json_depth(ins.d, depth + 1);
    }
    else
    {
        j["l"] = nlohmann::json{{"type", "elided"}};
        j["r"] = nlohmann::json{{"type", "elided"}};
        j["d"] = nlohmann::json{{"type", "elided"}};
    }
    return j;
}

nlohmann::json mop_to_json_depth(const mop_t& op, int depth)
{
    nlohmann::json j;
    j["valnum"] = static_cast<int>(op.valnum);
    j["oprops"] = static_cast<int>(op.oprops);
    j["size"]   = op.size;
    j["text"]   = render_mop_text(op);

    switch (op.t)
    {
    case mop_z:
        j["type"] = "none";
        break;
    case mop_r:
        j["type"] = "reg";
        j["r"]    = static_cast<int>(op.r);
        break;
    case mop_n:
        j["type"]  = "num";
        j["value"] = (op.nnn != nullptr) ? static_cast<std::uint64_t>(op.nnn->value) : 0;
        break;
    case mop_str:
        j["type"]  = "str";
        j["value"] = (op.cstr != nullptr) ? std::string(op.cstr) : std::string();
        break;
    case mop_d:
        j["type"] = "insn";
        if (op.d != nullptr && depth < kMaxMopJsonDepth)
            j["sub"] = minsn_to_json_depth(*op.d, depth + 1);
        else
            j["sub"] = nlohmann::json{{"type", "elided"}};
        break;
    case mop_S:
        j["type"] = "stkvar";
        j["off"]  = (op.s != nullptr) ? static_cast<std::int64_t>(op.s->off) : 0;
        break;
    case mop_v:
        j["type"] = "gvar";
        j["ea"]   = ea_to_hex(op.g);
        j["name"] = global_name_for(op.g);
        break;
    case mop_b:
        j["type"]   = "blkref";
        j["blknum"] = op.b;
        break;
    case mop_f:
    {
        j["type"] = "callinfo";
        if (op.f != nullptr)
        {
            j["callee"] = ea_to_hex(op.f->callee);
            nlohmann::json args = nlohmann::json::array();
            const mcallargs_t& list = op.f->args;
            for (size_t i = 0; i < list.size(); ++i)
            {
                const mcallarg_t& a = list[i];
                nlohmann::json arg_j;
                arg_j["arg_index"] = static_cast<int>(i);
                arg_j["arg_name"]  = std::string(a.name.c_str());
                arg_j["init_ea"]   = ea_to_hex(a.ea);
                if (depth + 1 < kMaxMopJsonDepth)
                    arg_j["value"] = mop_to_json_depth(static_cast<const mop_t&>(a), depth + 1);
                else
                    arg_j["value"] = nlohmann::json{{"type", "elided"}};
                args.push_back(std::move(arg_j));
            }
            j["args"] = std::move(args);
        }
        else
        {
            j["callee"] = ea_to_hex(BADADDR);
            j["args"]   = nlohmann::json::array();
        }
        break;
    }
    case mop_l:
    {
        j["type"] = "lvar";
        if (op.l != nullptr)
        {
            j["idx"]  = op.l->idx;
            j["off"]  = static_cast<std::int64_t>(op.l->off);
            j["name"] = lvar_name_for(op);
        }
        else
        {
            j["idx"]  = -1;
            j["off"]  = 0;
            j["name"] = std::string();
        }
        break;
    }
    case mop_a:
        j["type"] = "addr";
        if (op.a != nullptr && depth + 1 < kMaxMopJsonDepth)
            j["sub"] = mop_to_json_depth(static_cast<const mop_t&>(*op.a), depth + 1);
        else
            j["sub"] = nlohmann::json{{"type", "elided"}};
        break;
    case mop_h:
        j["type"] = "helper";
        j["name"] = (op.helper != nullptr) ? std::string(op.helper) : std::string();
        break;
    case mop_c:
        j["type"] = "cases";
        break;
    case mop_fn:
        j["type"] = "fpnum";
        break;
    case mop_p:
        j["type"] = "pair";
        break;
    case mop_sc:
        j["type"] = "scattered";
        if (op.scif != nullptr)
            j["name"] = std::string(op.scif->name.c_str());
        else
            j["name"] = std::string();
        break;
    default:
        j["type"]    = "unknown";
        j["type_id"] = static_cast<int>(op.t);
        break;
    }
    return j;
}

bool mop_collect_args_aliases(const mop_t& callinfo, const mop_t& tracked)
{
    if (callinfo.t != mop_f || callinfo.f == nullptr)
        return false;
    const mcallargs_t& args = callinfo.f->args;
    for (size_t i = 0; i < args.size(); ++i)
    {
        const mcallarg_t& a = args[i];
        if (mop_aliases(static_cast<const mop_t&>(a), tracked))
            return true;
    }
    return false;
}

void collect_constraint_strings(const minsn_t& ins, std::vector<std::string>& out)
{
    if (!is_mcode_jcond(ins.opcode) && !is_mcode_set(ins.opcode))
        return;
    out.push_back(render_minsn_text(ins));
}

bool insn_uses_tracked(const minsn_t& ins, const mop_t& tracked, bool& uses_in_args)
{
    uses_in_args = false;
    if (mop_aliases(ins.l, tracked))
        return true;
    if (mop_aliases(ins.r, tracked))
        return true;
    if (mop_aliases(ins.d, tracked))
        return true;
    if (mop_collect_args_aliases(ins.l, tracked) ||
        mop_collect_args_aliases(ins.r, tracked) ||
        mop_collect_args_aliases(ins.d, tracked))
    {
        uses_in_args = true;
        return true;
    }
    return false;
}

bool insn_defines_tracked(const minsn_t& ins, const mop_t& tracked)
{
    switch (ins.opcode)
    {
    case m_stx:
    case m_jcnd:
    case m_jnz:
    case m_jz:
    case m_jae:
    case m_jb:
    case m_ja:
    case m_jbe:
    case m_jg:
    case m_jge:
    case m_jl:
    case m_jle:
    case m_jtbl:
    case m_ijmp:
    case m_goto:
    case m_ret:
    case m_push:
    case m_nop:
    case m_und:
        return false;
    default:
        break;
    }
    return mop_aliases(ins.d, tracked);
}

bool resolve_callee_name(const minsn_t& ins, std::string& callee_name)
{
    ea_t ea = BADADDR;
    return resolve_call_target(ins, ea, callee_name);
}

bool callee_in_list(const std::string& callee_name, const std::vector<std::string>& names)
{
    if (callee_name.empty())
        return false;
    const std::string lower = ascii_lower(callee_name);
    for (const auto& n : names)
    {
        const std::string nl = ascii_lower(n);
        if (lower == nl)
            return true;
        if (!nl.empty() && lower.size() > nl.size() &&
            lower.compare(lower.size() - nl.size(), nl.size(), nl) == 0)
            return true;
        if (!nl.empty() && lower.find(nl) != std::string::npos)
            return true;
    }
    return false;
}

bool callee_in_signature_list(const std::string& callee_name, const std::string_view* list, size_t count)
{
    if (callee_name.empty())
        return false;
    const std::string lower = ascii_lower(callee_name);
    for (size_t i = 0; i < count; ++i)
    {
        std::string nl = ascii_lower(std::string(list[i]));
        if (nl.empty())
            continue;
        if (lower == nl)
            return true;
        if (lower.size() > nl.size() &&
            lower.compare(lower.size() - nl.size(), nl.size(), nl) == 0)
            return true;
        if (lower.find(nl) != std::string::npos)
            return true;
    }
    return false;
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

void traverse_topinsns(mba_t& mba, std::function<bool(int, minsn_t&)> visitor)
{
    struct visitor_t : public minsn_visitor_t
    {
        std::function<bool(int, minsn_t&)> cb;
        visitor_t(mba_t* m, std::function<bool(int, minsn_t&)> f)
            : minsn_visitor_t(m), cb(std::move(f))
        {
        }
        int idaapi visit_minsn() override
        {
            if (curins == nullptr)
                return 0;
            int serial = blk != nullptr ? blk->serial : -1;
            return cb(serial, *curins) ? 0 : 1;
        }
    };
    visitor_t v(&mba, std::move(visitor));
    mba.for_all_insns(v);
}

void traverse_topinsns_const(const mba_t& mba, std::function<bool(int, const minsn_t&)> visitor)
{
    mba_t& mutable_mba = const_cast<mba_t&>(mba);
    traverse_topinsns(mutable_mba, [&](int block_serial, minsn_t& ins) -> bool {
        return visitor(block_serial, ins);
    });
}

std::string mlist_to_string(const mlist_t& list)
{
    qstring qs;
    list.print(&qs);
    return qs.empty() ? std::string() : std::string(qs.c_str());
}

bool mlist_for_operand(const mblock_t& blk, const mop_t& op, bool def_not_use, maymust_t mm, mlist_t& out)
{
    out.clear();
    if (op.t == mop_z)
        return false;
    if (def_not_use)
        blk.append_def_list(&out, op, mm);
    else
        blk.append_use_list(&out, op, mm);
    return !out.empty();
}

bool block_ends_with_noret_call(const mblock_t& blk)
{
    const minsn_t* tail = blk.tail;
    if (tail == nullptr || !is_mcode_call(tail->opcode))
        return false;
    ea_t callee_ea = BADADDR;
    std::string callee_name;
    if (!resolve_call_target(*tail, callee_ea, callee_name) || callee_ea == BADADDR)
        return false;
    return !func_does_return(callee_ea);
}

nlohmann::json chain_to_json(const chain_t& ch)
{
    nlohmann::json j;
    qstring qs;
    ch.print(&qs);
    j["text"] = qs.empty() ? std::string() : std::string(qs.c_str());
    j["width"] = ch.width;
    j["varnum"] = ch.varnum;
    j["is_reg"] = ch.is_reg();
    j["is_stkoff"] = ch.is_stkoff();
    j["is_term"] = ch.is_term();
    j["is_pass_through"] = ch.is_passreg();
    nlohmann::json blocks = nlohmann::json::array();
    for (size_t i = 0; i < ch.size(); ++i)
        blocks.push_back(ch[i]);
    j["blocks"] = std::move(blocks);
    return j;
}

gctype_t parse_gctype(const std::string& s)
{
    const std::string lower = ascii_lower(s);
    if (lower == "asr")
        return GC_ASR;
    if (lower == "xdsu")
        return GC_XDSU;
    return GC_REGS_AND_STKVARS;
}

maymust_t parse_maymust(const std::string& s)
{
    return ascii_lower(s) == "must" ? MUST_ACCESS : MAY_ACCESS;
}

bool parse_bool_param(const nlohmann::json& params, const char* key, bool def)
{
    if (!params.contains(key))
        return def;
    const auto& v = params.at(key);
    if (v.is_boolean())
        return v.get<bool>();
    if (v.is_number_integer())
        return v.get<std::int64_t>() != 0;
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>() != 0;
    if (v.is_string())
    {
        const std::string lower = ascii_lower(v.get<std::string>());
        return lower == "1" || lower == "true" || lower == "yes";
    }
    return def;
}

template <typename T, size_t N>
bool source_name_in(const std::string& lower_name, const T (&items)[N], int& arg_index)
{
    for (const auto& item : items)
    {
        const std::string needle = ascii_lower(std::string(item.name));
        if (!needle.empty() && lower_name.find(needle) != std::string::npos)
        {
            arg_index = item.taint_arg_index;
            return true;
        }
    }
    return false;
}

template <size_t N>
bool sink_name_in(const std::string& lower_name,
                  const sig::sink_signature_t (&items)[N],
                  int& cwe,
                  int& len_arg,
                  int& sensitive_arg)
{
    for (const auto& item : items)
    {
        const std::string needle = ascii_lower(std::string(item.name));
        if (!needle.empty() && lower_name.find(needle) != std::string::npos)
        {
            cwe = item.primary_cwe;
            len_arg = item.len_arg_index;
            sensitive_arg = item.sensitive_arg_index;
            return true;
        }
    }
    return false;
}

template <size_t N>
bool helper_name_in(const std::string& lower_name, const std::string_view (&items)[N])
{
    for (const auto& item : items)
    {
        const std::string needle = ascii_lower(std::string(item));
        if (!needle.empty() && lower_name.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

void collect_numeric_mops(const mop_t& op, std::vector<uint64_t>& out, int depth = 0)
{
    if (depth > kMaxMopJsonDepth || op.t == mop_z)
        return;
    if (op.t == mop_n && op.nnn != nullptr)
    {
        out.push_back(static_cast<uint64_t>(op.nnn->value));
        return;
    }
    if (op.t == mop_d && op.d != nullptr)
    {
        collect_numeric_mops(op.d->l, out, depth + 1);
        collect_numeric_mops(op.d->r, out, depth + 1);
        collect_numeric_mops(op.d->d, out, depth + 1);
        return;
    }
    if (op.t == mop_f && op.f != nullptr)
    {
        for (size_t i = 0; i < op.f->args.size(); ++i)
            collect_numeric_mops(static_cast<const mop_t&>(op.f->args[i]), out, depth + 1);
        return;
    }
    if (op.t == mop_a && op.a != nullptr)
        collect_numeric_mops(static_cast<const mop_t&>(*op.a), out, depth + 1);
    if (op.t == mop_p && op.pair != nullptr)
    {
        collect_numeric_mops(op.pair->lop, out, depth + 1);
        collect_numeric_mops(op.pair->hop, out, depth + 1);
    }
}

std::unordered_map<std::string, nlohmann::json>& microcode_session_constraints()
{
    static std::unordered_map<std::string, nlohmann::json> constraints;
    return constraints;
}

std::mutex& microcode_session_constraints_mutex()
{
    static std::mutex m;
    return m;
}

}

void mba_deleter_t::operator()(mba_t* mba) const noexcept
{
    if (mba != nullptr)
        delete mba;
}

mba_maturity_t parse_maturity(const std::string& s)
{
    const std::string lower = ascii_lower(s);
    if (lower == "generated")        return MMAT_GENERATED;
    if (lower == "preoptimized")     return MMAT_PREOPTIMIZED;
    if (lower == "locopt")           return MMAT_LOCOPT;
    if (lower == "calls")            return MMAT_CALLS;
    if (lower == "glbopt1")          return MMAT_GLBOPT1;
    if (lower == "glbopt2")          return MMAT_GLBOPT2;
    if (lower == "glbopt3")          return MMAT_GLBOPT3;
    if (lower == "lvars")            return MMAT_LVARS;
    return MMAT_LVARS;
}

const char* maturity_str(mba_maturity_t mat)
{
    switch (mat)
    {
    case MMAT_ZERO:         return "zero";
    case MMAT_GENERATED:    return "generated";
    case MMAT_PREOPTIMIZED: return "preoptimized";
    case MMAT_LOCOPT:       return "locopt";
    case MMAT_CALLS:        return "calls";
    case MMAT_GLBOPT1:      return "glbopt1";
    case MMAT_GLBOPT2:      return "glbopt2";
    case MMAT_GLBOPT3:      return "glbopt3";
    case MMAT_LVARS:        return "lvars";
    }
    return "unknown";
}

std::optional<mba_handle_t> generate(ea_t func_ea, mba_maturity_t mat)
{
    if (!init_hexrays_plugin())
        return std::nullopt;

    func_t* pfn = get_func(func_ea);
    if (pfn == nullptr)
        return std::nullopt;

    if (!ida_utils::is_safely_decompilable(pfn))
        return std::nullopt;

    mba_handle_t handle;
    handle.maturity = mat;
    handle.func_ea  = pfn->start_ea;

    try
    {
        hexrays_failure_t hf;
        mba_ranges_t mbr(pfn);
        mba_t* mba = gen_microcode(mbr, &hf, nullptr, DECOMP_NO_WAIT | DECOMP_WARNINGS, mat);
        if (mba == nullptr)
            return std::nullopt;
        handle.mba.reset(mba);
        return handle;
    }
    catch (const vd_failure_t&)
    {
        return std::nullopt;
    }
    catch (...)
    {
        return std::nullopt;
    }
}

std::vector<mba_handle_t> generate_at_maturities(ea_t func_ea, const std::vector<mba_maturity_t>& mats)
{
    std::vector<mba_handle_t> out;
    out.reserve(mats.size());
    std::set<mba_maturity_t> seen;
    for (mba_maturity_t mat : mats)
    {
        if (!seen.insert(mat).second)
            continue;
        auto handle = generate(func_ea, mat);
        if (handle.has_value() && handle->mba != nullptr)
            out.push_back(std::move(*handle));
    }
    return out;
}

void iter_with_visitors(mba_t& mba,
                        const std::function<bool(int, minsn_t&)>& insn_visitor,
                        const std::function<bool(int, mop_t&, bool)>& mop_visitor)
{
    if (insn_visitor)
        traverse_topinsns(mba, insn_visitor);
    if (!mop_visitor)
        return;

    struct visitor_t : public mop_visitor_t
    {
        std::function<bool(int, mop_t&, bool)> cb;
        visitor_t(mba_t* m, std::function<bool(int, mop_t&, bool)> f)
            : mop_visitor_t(m), cb(std::move(f))
        {
        }
        int idaapi visit_mop(mop_t* op, const tinfo_t*, bool is_target) override
        {
            if (op == nullptr)
                return 0;
            int serial = blk != nullptr ? blk->serial : -1;
            return cb(serial, *op, is_target) ? 0 : 1;
        }
    };
    visitor_t v(&mba, mop_visitor);
    mba.for_all_ops(v);
}

std::pair<mlist_t, mlist_t> build_use_def_lists(mblock_t& blk,
                                                const minsn_t& ins,
                                                maymust_t mm)
{
    return {blk.build_use_list(ins, mm), blk.build_def_list(ins, mm)};
}

nlohmann::json minsn_to_json(const minsn_t& ins)
{
    return minsn_to_json_depth(ins, 0);
}

nlohmann::json mop_to_json(const mop_t& op)
{
    return mop_to_json_depth(op, 0);
}

nlohmann::json dump_mba(const mba_t& mba, size_t inst_offset, size_t inst_limit)
{
    nlohmann::json result;
    result["func_ea"]      = ea_to_hex(mba.entry_ea);
    result["maturity"]     = maturity_str(mba.maturity);
    result["block_count"]  = mba.qty;

    size_t total = 0;
    for (int i = 0; i < mba.qty; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
            ++total;
    }
    result["total_instructions"] = total;
    result["offset"]             = inst_offset;
    result["limit"]              = inst_limit;

    nlohmann::json blocks = nlohmann::json::array();
    size_t emitted    = 0;
    size_t seen       = 0;
    bool   truncated  = false;
    bool   limit_hit  = false;

    for (int i = 0; i < mba.qty && !limit_hit; ++i)
    {
        const mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;

        nlohmann::json blk_j;
        blk_j["serial"] = blk->serial;
        blk_j["type"]   = block_type_to_str(blk->type);
        blk_j["start"]  = ea_to_hex(blk->start);
        blk_j["end"]    = ea_to_hex(blk->end);

        nlohmann::json preds = nlohmann::json::array();
        for (size_t p = 0; p < blk->predset.size(); ++p)
            preds.push_back(blk->predset[p]);
        blk_j["predecessors"] = std::move(preds);

        nlohmann::json succs = nlohmann::json::array();
        for (size_t s = 0; s < blk->succset.size(); ++s)
            succs.push_back(blk->succset[s]);
        blk_j["successors"] = std::move(succs);

        nlohmann::json insns = nlohmann::json::array();
        for (const minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (seen < inst_offset)
            {
                ++seen;
                continue;
            }
            if (inst_limit != 0 && emitted >= inst_limit)
            {
                truncated = true;
                limit_hit = true;
                break;
            }
            insns.push_back(minsn_to_json_depth(*m, 0));
            ++emitted;
            ++seen;
        }
        blk_j["instructions"] = std::move(insns);
        blocks.push_back(std::move(blk_j));
    }

    result["blocks"]                 = std::move(blocks);
    result["returned_instructions"]  = emitted;
    result["truncated"]              = truncated;
    return result;
}

bool mop_equal(const mop_t& a, const mop_t& b)
{
    return a.equal_mops(b, 0);
}

bool mop_aliases(const mop_t& a, const mop_t& b)
{
    if (a.t == mop_z || b.t == mop_z)
        return false;

    if (a.t == mop_l && b.t == mop_l && a.l != nullptr && b.l != nullptr)
    {
        if (a.l->idx != b.l->idx)
            return false;
        sval_t a_off = a.l->off;
        sval_t b_off = b.l->off;
        return stk_ranges_overlap(a_off, a.size, b_off, b.size);
    }

    if (a.t == mop_S && b.t == mop_S && a.s != nullptr && b.s != nullptr)
        return stk_ranges_overlap(a.s->off, a.size, b.s->off, b.size);

    if (a.t == mop_r && b.t == mop_r)
        return reg_groups_overlap(a.r, a.size, b.r, b.size);

    if (a.t == mop_v && b.t == mop_v)
    {
        sval_t a_off = static_cast<sval_t>(a.g);
        sval_t b_off = static_cast<sval_t>(b.g);
        return stk_ranges_overlap(a_off, a.size, b_off, b.size);
    }

    if (a.t == mop_h && b.t == mop_h && a.helper != nullptr && b.helper != nullptr)
        return std::strcmp(a.helper, b.helper) == 0;

    if (a.t == b.t)
        return mop_equal(a, b);

    return false;
}

std::string mop_describe(const mop_t& op)
{
    return render_mop_text(op);
}

bool resolve_call_target(const minsn_t& ins, ea_t& callee_ea, std::string& callee_name)
{
    callee_ea   = BADADDR;
    callee_name.clear();

    if (ins.opcode != m_call && ins.opcode != m_icall)
        return false;

    const mop_t& target = ins.l;
    if (target.t == mop_v)
    {
        callee_ea = target.g;
        callee_name = global_name_for(callee_ea);
    }
    else if (target.t == mop_h && target.helper != nullptr)
    {
        callee_name = std::string(target.helper);
    }
    else if (target.t == mop_b)
    {
        callee_ea = BADADDR;
    }

    if (ins.d.t == mop_f && ins.d.f != nullptr)
    {
        ea_t fc = ins.d.f->callee;
        if (fc != BADADDR)
        {
            callee_ea = fc;
            if (callee_name.empty())
                callee_name = global_name_for(fc);
        }
    }

    if (callee_ea != BADADDR)
    {
        func_t* f = get_func(callee_ea);
        if (f != nullptr && (f->flags & FUNC_THUNK) != 0)
        {
            ea_t fptr = BADADDR;
            ea_t target_ea = calc_thunk_func_target(f, &fptr);
            if (target_ea != BADADDR && target_ea != callee_ea)
            {
                callee_ea = target_ea;
                std::string resolved = global_name_for(target_ea);
                if (!resolved.empty())
                    callee_name = resolved;
            }
        }
    }

    return !callee_name.empty() || callee_ea != BADADDR;
}

std::vector<call_arg_info_t> collect_call_arguments(const minsn_t& call_ins)
{
    std::vector<call_arg_info_t> out;
    if (!is_mcode_call(call_ins.opcode))
        return out;
    if (call_ins.d.t != mop_f || call_ins.d.f == nullptr)
        return out;

    const mcallargs_t& args = call_ins.d.f->args;
    out.reserve(args.size());
    for (size_t i = 0; i < args.size(); ++i)
    {
        const mcallarg_t& a = args[i];
        call_arg_info_t info;
        info.arg_index  = static_cast<int>(i);
        info.value      = static_cast<const mop_t&>(a);
        info.init_ea    = a.ea;
        info.is_literal = (a.t == mop_n) || (a.t == mop_str);
        if (a.t == mop_n && a.nnn != nullptr)
            info.literal_value = static_cast<std::uint64_t>(a.nnn->value);
        info.summary = render_mop_text(static_cast<const mop_t&>(a));
        out.push_back(std::move(info));
    }
    return out;
}

bool insn_predates(const mba_t& mba, ea_t earlier_ea, ea_t later_ea)
{
    if (earlier_ea == BADADDR || later_ea == BADADDR)
        return false;
    bool seen_earlier = false;
    bool found        = false;
    traverse_topinsns_const(mba, [&](int, const minsn_t& ins) -> bool {
        if (!seen_earlier)
        {
            if (ins.ea == earlier_ea)
                seen_earlier = true;
            return true;
        }
        if (ins.ea == later_ea)
        {
            found = true;
            return false;
        }
        return true;
    });
    return seen_earlier && found;
}

ea_t find_first_call_to(mba_t& mba, const std::vector<std::string>& callee_names)
{
    ea_t result = BADADDR;
    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        if (!is_mcode_call(ins.opcode))
            return true;
        std::string name;
        if (!resolve_callee_name(ins, name))
            return true;
        if (callee_in_list(name, callee_names))
        {
            result = ins.ea;
            return false;
        }
        return true;
    });
    return result;
}

std::vector<ea_t> find_all_calls_to(mba_t& mba, const std::vector<std::string>& callee_names)
{
    std::vector<ea_t> out;
    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        if (!is_mcode_call(ins.opcode))
            return true;
        std::string name;
        if (!resolve_callee_name(ins, name))
            return true;
        if (callee_in_list(name, callee_names))
            out.push_back(ins.ea);
        return true;
    });
    return out;
}

def_use_t def_use_chain(mba_t& mba, const mop_t& tracked)
{
    def_use_t result;
    if (tracked.t == mop_z)
        return result;

    mlist_t tracked_use;
    mlist_t tracked_def;
    bool have_tracked_list = false;
    for (int i = 0; i < mba.qty && !have_tracked_list; ++i)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        have_tracked_list = mlist_for_operand(*blk, tracked, false, MAY_ACCESS, tracked_use);
        mlist_t def_tmp;
        if (mlist_for_operand(*blk, tracked, true, MAY_ACCESS, def_tmp))
        {
            tracked_def.add(def_tmp);
            have_tracked_list = true;
        }
    }
    if (!tracked_def.empty())
        tracked_use.add(tracked_def);

    std::unordered_set<std::uint64_t> def_set;
    std::unordered_set<std::uint64_t> use_set;
    ea_t last_def_ea = BADADDR;

    traverse_topinsns(mba, [&](int block_serial, minsn_t& ins) -> bool {
        mblock_t* blk = nullptr;
        for (int b = 0; b < mba.qty; ++b)
        {
            mblock_t* candidate = mba.get_mblock(static_cast<uint>(b));
            if (candidate != nullptr && candidate->serial == block_serial)
            {
                blk = candidate;
                break;
            }
        }
        if (blk == nullptr)
            return true;

        auto lists = build_use_def_lists(*blk, ins, MAY_ACCESS);
        const bool is_use = !tracked_use.empty() && lists.first.has_common(tracked_use);
        const bool is_def = !tracked_use.empty() && lists.second.has_common(tracked_use);

        if (is_use)
        {
            if (use_set.insert(static_cast<std::uint64_t>(ins.ea)).second)
                result.uses.push_back(ins.ea);
            if (last_def_ea != BADADDR)
            {
                std::ostringstream rd;
                rd << "def@" << ea_to_hex(last_def_ea) << " -> use@" << ea_to_hex(ins.ea);
                result.reaching_defs.push_back(rd.str());
            }
        }

        if (is_def)
        {
            if (def_set.insert(static_cast<std::uint64_t>(ins.ea)).second)
                result.defs.push_back(ins.ea);
            last_def_ea = ins.ea;
        }

        collect_constraint_strings(ins, result.constraints);
        return true;
    });

    return result;
}

def_use_t def_use_chain_for_lvar(mba_t& mba, int lvar_idx)
{
    def_use_t empty;
    if (lvar_idx < 0 || static_cast<size_t>(lvar_idx) >= mba.vars.size())
        return empty;
    const lvar_t& v = mba.vars[lvar_idx];
    int width = v.width > 0 ? v.width : 1;
    mop_t synth;
    synth._make_lvar(&mba, lvar_idx, 0);
    synth.size = width;
    return def_use_chain(mba, synth);
}

def_use_t def_use_chain_for_stkvar(mba_t& mba, sval_t off)
{
    mop_t synth;
    synth._make_stkvar(&mba, off);
    synth.size = 1;
    return def_use_chain(mba, synth);
}

def_use_t def_use_chain_for_reg(mba_t& mba, mreg_t reg)
{
    mop_t synth;
    synth._make_reg(reg, 1);
    return def_use_chain(mba, synth);
}

bool hexrays_query_use_def(ea_t func_ea,
                           ea_t at_ea,
                           const mop_t& op,
                           bool def_not_use,
                           mlist_t* out_list,
                           qstring* err)
{
    if (out_list != nullptr)
        out_list->clear();
    auto handle = generate(func_ea, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
    {
        if (err != nullptr)
            *err = "microcode generation failed";
        return false;
    }
    mba_t& mba = *handle->mba;
    for (int i = 0; i < mba.qty; ++i)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (minsn_t* ins = blk->head; ins != nullptr; ins = ins->next)
        {
            if (ins->ea != at_ea)
                continue;
            mlist_t list;
            if (!mlist_for_operand(*blk, op, def_not_use, MAY_ACCESS, list))
            {
                if (err != nullptr)
                    *err = "operand has no SDK location list";
                return false;
            }
            if (out_list != nullptr)
                *out_list = list;
            return true;
        }
    }
    if (err != nullptr)
        *err = "instruction address not found in function microcode";
    return false;
}

bool is_freed_then_used(mba_t& mba, const mop_t& ptr, ea_t& free_ea, ea_t& use_ea)
{
    free_ea = BADADDR;
    use_ea  = BADADDR;
    if (ptr.t == mop_z)
        return false;

    bool tracking = false;
    bool result   = false;
    ea_t pending_free_ea = BADADDR;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        bool is_matching_free = false;
        if (is_mcode_call(ins.opcode))
        {
            std::string name;
            if (resolve_callee_name(ins, name) &&
                callee_in_signature_list(name, sig::FREE_FUNCS,
                                         sizeof(sig::FREE_FUNCS) / sizeof(sig::FREE_FUNCS[0])))
            {
                mop_t arg_ptr;
                arg_ptr.zero();
                if (collect_first_pointer_arg(ins, arg_ptr) && mop_aliases(arg_ptr, ptr))
                {
                    tracking = true;
                    pending_free_ea = ins.ea;
                    is_matching_free = true;
                }
            }
        }

        if (is_matching_free)
            return true;

        if (!tracking)
            return true;

        if (insn_defines_tracked(ins, ptr))
        {
            tracking = false;
            pending_free_ea = BADADDR;
            return true;
        }

        bool used_in_args = false;
        if (insn_uses_tracked(ins, ptr, used_in_args))
        {
            if (ins.opcode == m_ldx || ins.opcode == m_stx ||
                used_in_args || ins.opcode == m_call || ins.opcode == m_icall)
            {
                free_ea = pending_free_ea;
                use_ea  = ins.ea;
                result  = true;
                return false;
            }
        }
        return true;
    });

    return result;
}

bool is_double_freed(mba_t& mba, const mop_t& ptr, ea_t& free1_ea, ea_t& free2_ea)
{
    free1_ea = BADADDR;
    free2_ea = BADADDR;
    if (ptr.t == mop_z)
        return false;

    ea_t pending_free_ea = BADADDR;
    bool tracking        = false;
    bool result          = false;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        bool is_matching_free = false;
        if (is_mcode_call(ins.opcode))
        {
            std::string name;
            if (resolve_callee_name(ins, name) &&
                callee_in_signature_list(name, sig::FREE_FUNCS,
                                         sizeof(sig::FREE_FUNCS) / sizeof(sig::FREE_FUNCS[0])))
            {
                mop_t arg_ptr;
                arg_ptr.zero();
                if (collect_first_pointer_arg(ins, arg_ptr) && mop_aliases(arg_ptr, ptr))
                {
                    if (tracking && pending_free_ea != BADADDR)
                    {
                        free1_ea = pending_free_ea;
                        free2_ea = ins.ea;
                        result   = true;
                        return false;
                    }
                    tracking = true;
                    pending_free_ea = ins.ea;
                    is_matching_free = true;
                }
            }
        }

        if (is_matching_free)
            return true;

        if (tracking && insn_defines_tracked(ins, ptr))
        {
            tracking = false;
            pending_free_ea = BADADDR;
        }
        return true;
    });

    return result;
}

bool has_uninit_read(mba_t& mba, const mop_t& var, ea_t& read_ea)
{
    read_ea = BADADDR;
    if (var.t == mop_z)
        return false;

    bool seen_def = false;
    bool result   = false;

    traverse_topinsns(mba, [&](int, minsn_t& ins) -> bool {
        const bool is_def = insn_defines_tracked(ins, var);
        bool used_in_args = false;
        const bool is_use = insn_uses_tracked(ins, var, used_in_args);

        if (is_use && !seen_def)
        {
            read_ea = ins.ea;
            result  = true;
            return false;
        }
        if (is_def)
            seen_def = true;
        return true;
    });

    return result;
}

namespace
{

mreg_t reg_name_to_mreg(const std::string& name)
{
    if (name.empty())
        return mreg_t(-1);
    int r = ::str2reg(name.c_str());
    if (r < 0)
        return mreg_t(-1);
    mreg_t mr = reg2mreg(r);
    return mr;
}

bool parse_int64(const std::string& s, std::int64_t& out)
{
    if (s.empty())
        return false;
    std::string trimmed = s;
    bool neg = false;
    if (trimmed[0] == '-')
    {
        neg = true;
        trimmed.erase(0, 1);
    }
    if (trimmed.empty())
        return false;
    if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X'))
        trimmed.erase(0, 2);
    if (trimmed.empty())
        return false;
    const char* cstr = trimmed.c_str();
    char* endp = nullptr;
    errno = 0;
    unsigned long long v = ::strtoull(cstr, &endp, 16);
    if (errno != 0 || endp == nullptr || *endp != '\0' || endp == cstr)
        return false;
    std::int64_t signed_v = static_cast<std::int64_t>(v);
    if (neg)
        signed_v = -signed_v;
    out = signed_v;
    return true;
}

int find_lvar_by_name(const mba_t& mba, const std::string& name)
{
    for (size_t i = 0; i < mba.vars.size(); ++i)
    {
        const lvar_t& v = mba.vars[i];
        if (!v.name.empty() && std::strcmp(v.name.c_str(), name.c_str()) == 0)
            return static_cast<int>(i);
    }
    return -1;
}

nlohmann::json def_use_to_json(const def_use_t& du)
{
    nlohmann::json j;
    nlohmann::json defs = nlohmann::json::array();
    for (ea_t ea : du.defs)
        defs.push_back(ea_to_hex(ea));
    j["defs"] = std::move(defs);

    nlohmann::json uses = nlohmann::json::array();
    for (ea_t ea : du.uses)
        uses.push_back(ea_to_hex(ea));
    j["uses"] = std::move(uses);

    nlohmann::json reaching = nlohmann::json::array();
    for (const std::string& s : du.reaching_defs)
        reaching.push_back(s);
    j["reaching_defs"] = std::move(reaching);

    nlohmann::json constraints = nlohmann::json::array();
    for (const std::string& s : du.constraints)
        constraints.push_back(s);
    j["constraints"] = std::move(constraints);

    j["def_count"] = du.defs.size();
    j["use_count"] = du.uses.size();
    return j;
}

std::optional<ea_t> parse_required_address_param(const nlohmann::json& params,
                                                 const char* key,
                                                 agent_tools::tool_result_t& err)
{
    if (!params.contains(key) || !params.at(key).is_string())
    {
        err = agent_tools::tool_result_t::error(std::string("Missing address parameter: ") + key, "bad_param");
        return std::nullopt;
    }
    auto ea = agent_tools::helpers::parse_address(params.at(key).get<std::string>());
    if (!ea.has_value())
        err = agent_tools::tool_result_t::error(std::string("Invalid address parameter: ") + key, "bad_param");
    return ea;
}

int int_param(const nlohmann::json& params, const char* key, int def, int min_v, int max_v)
{
    int v = def;
    if (params.contains(key))
    {
        const auto& raw = params.at(key);
        if (raw.is_number_integer())
        {
            const std::int64_t value = raw.get<std::int64_t>();
            if (value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                v = static_cast<int>(value);
        }
        else if (raw.is_number_unsigned())
        {
            const std::uint64_t value = raw.get<std::uint64_t>();
            if (value <= static_cast<std::uint64_t>((std::numeric_limits<int>::max)()))
                v = static_cast<int>(value);
        }
        else if (raw.is_number_float())
        {
            const double value = raw.get<double>();
            if (std::isfinite(value) && value >= (std::numeric_limits<int>::min)() && value <= (std::numeric_limits<int>::max)())
                v = static_cast<int>(value);
        }
        else if (raw.is_string())
        {
            char* endp = nullptr;
            const std::string s = raw.get<std::string>();
            const char* cstr = s.c_str();
            long parsed = std::strtol(cstr, &endp, 0);
            if (endp != nullptr && endp != cstr
                && parsed >= (std::numeric_limits<int>::min)() && parsed <= (std::numeric_limits<int>::max)())
                v = static_cast<int>(parsed);
        }
    }
    if (v < min_v)
        v = min_v;
    if (v > max_v)
        v = max_v;
    return v;
}

int64_t int64_param(const nlohmann::json& params, const char* key, int64_t def)
{
    if (!params.contains(key))
        return def;
    const auto& raw = params.at(key);
    if (raw.is_number_integer())
        return raw.get<int64_t>();
    if (raw.is_number_unsigned())
    {
        const std::uint64_t value = raw.get<std::uint64_t>();
        if (value > static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
            return def;
        return static_cast<int64_t>(value);
    }
    if (raw.is_number_float())
    {
        const double value = raw.get<double>();
        if (!std::isfinite(value) || value < static_cast<double>((std::numeric_limits<std::int64_t>::min)()) || value > static_cast<double>((std::numeric_limits<std::int64_t>::max)()))
            return def;
        return static_cast<int64_t>(value);
    }
    if (raw.is_string())
    {
        const std::string s = raw.get<std::string>();
        char* endp = nullptr;
        const char* cstr = s.c_str();
        long long parsed = std::strtoll(cstr, &endp, 0);
        if (endp != nullptr && endp != cstr)
            return static_cast<int64_t>(parsed);
    }
    return def;
}

std::string string_param(const nlohmann::json& params, const char* key, const std::string& def = {})
{
    if (!params.contains(key))
        return def;
    const auto& raw = params.at(key);
    if (raw.is_string())
        return raw.get<std::string>();
    if (raw.is_number_integer())
        return std::to_string(raw.get<int64_t>());
    if (raw.is_number_unsigned())
        return std::to_string(raw.get<uint64_t>());
    return def;
}

bool resolve_variable_mop(mba_t& mba, const std::string& variable, mop_t& out, nlohmann::json& meta, std::string& err)
{
    out.zero();
    auto colon = variable.find(':');
    if (colon == std::string::npos)
    {
        err = "invalid variable spec";
        return false;
    }
    const std::string kind = ascii_lower(variable.substr(0, colon));
    const std::string value = variable.substr(colon + 1);
    meta["kind"] = kind;
    meta["value"] = value;
    if (kind == "lvar")
    {
        int idx = -1;
        if (!value.empty())
        {
            char* endp = nullptr;
            long parsed = std::strtol(value.c_str(), &endp, 0);
            if (endp != nullptr && *endp == '\0' && endp != value.c_str())
                idx = static_cast<int>(parsed);
        }
        if (idx < 0)
            idx = find_lvar_by_name(mba, value);
        if (idx < 0 || static_cast<size_t>(idx) >= mba.vars.size())
        {
            err = "lvar not found";
            return false;
        }
        out._make_lvar(&mba, idx, 0);
        out.size = mba.vars[idx].width > 0 ? mba.vars[idx].width : 1;
        meta["lvar_idx"] = idx;
        meta["lvar_name"] = std::string(mba.vars[idx].name.c_str());
        return true;
    }
    if (kind == "reg")
    {
        mreg_t reg = reg_name_to_mreg(value);
        if (reg == mr_none)
        {
            err = "register not found";
            return false;
        }
        out._make_reg(reg, 1);
        meta["reg"] = static_cast<int>(reg);
        return true;
    }
    if (kind == "stk")
    {
        std::int64_t off = 0;
        if (!parse_int64(value, off))
        {
            err = "invalid stack offset";
            return false;
        }
        out._make_stkvar(&mba, static_cast<sval_t>(off));
        out.size = 1;
        meta["stk_off"] = off;
        return true;
    }
    err = "unsupported variable kind";
    return false;
}

nlohmann::json path_constraints_to_json(const std::vector<aida::vuln::symbolic::path_constraint_t>& pcs)
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& pc : pcs)
        arr.push_back(aida::vuln::symbolic::to_json(pc));
    return arr;
}

agent_tools::tool_result_t handle_mc_path_smtlib(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    auto sink_opt = parse_required_address_param(params, "sink_ea", err);
    if (!sink_opt)
        return err;
    const int max_branches = int_param(params, "max_branches", 64, 1, 1024);
    const std::string maturity = string_param(params, "maturity", "glbopt3");

    aida::vuln::symbolic::SymbolicEngine sym;
    if (!sym.is_available())
        return agent_tools::tool_result_t::error(std::string("symbolic engine unavailable"), "microcode_failed");
    if (!sym.load_function(*ea_opt, parse_maturity(maturity)))
        return agent_tools::tool_result_t::error(std::string("symbolic load failed: ") + std::string(sym.last_error()), "microcode_failed");

    auto pcs = sym.collect_path_to(*sink_opt, max_branches);
    nlohmann::json data;
    data["function_ea"] = ea_to_hex(sym.current_function_ea());
    data["sink_ea"] = ea_to_hex(*sink_opt);
    data["maturity"] = maturity_str(parse_maturity(maturity));
    data["constraints"] = path_constraints_to_json(pcs);
    data["smt2_formula"] = sym.path_smtlib2(*sink_opt, max_branches);
    data["constraint_count"] = pcs.size();
    return agent_tools::tool_result_t::ok(std::string("Microcode path SMT-LIB2 generated"), data);
}

agent_tools::tool_result_t handle_mc_solve_path(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    auto sink_opt = parse_required_address_param(params, "sink_ea", err);
    if (!sink_opt)
        return err;
    const int max_branches = int_param(params, "max_branches", 64, 1, 1024);
    const int timeout_ms = int_param(params, "timeout_ms", 5000, 100, 60000);
    const std::string maturity = string_param(params, "maturity", "glbopt3");
    const std::string extra = string_param(params, "extra_smtlib2_assertions");

    aida::vuln::symbolic::SymbolicEngine sym;
    if (!sym.is_available())
        return agent_tools::tool_result_t::error(std::string("symbolic engine unavailable"), "microcode_failed");
    if (!sym.load_function(*ea_opt, parse_maturity(maturity)))
        return agent_tools::tool_result_t::error(std::string("symbolic load failed: ") + std::string(sym.last_error()), "microcode_failed");

    auto result = sym.solve_path_to(*sink_opt, extra, static_cast<uint32_t>(timeout_ms), max_branches);
    nlohmann::json data = aida::vuln::smt::to_json(result);
    data["function_ea"] = ea_to_hex(sym.current_function_ea());
    data["sink_ea"] = ea_to_hex(*sink_opt);
    data["maturity"] = maturity_str(parse_maturity(maturity));
    std::ostringstream msg;
    msg << std::string("Microcode path solve: ") << aida::vuln::smt::result_str(result.result)
        << std::string(" (solve_ms=") << result.solve_ms << std::string(")");
    return agent_tools::tool_result_t::ok(msg.str(), data);
}

agent_tools::tool_result_t handle_mc_dataflow_ssa(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    const std::string variable = string_param(params, "variable");
    if (variable.empty())
        return agent_tools::tool_result_t::error(std::string("variable is required"), "bad_param");
    const std::string chain_kind = ascii_lower(string_param(params, "chain_kind", "ud"));
    const gctype_t gctype = parse_gctype(string_param(params, "gctype", "regs_stk"));

    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode"), "microcode_failed");
    mba_t& mba = *handle->mba;
    mop_t target;
    nlohmann::json target_meta;
    std::string var_err;
    if (!resolve_variable_mop(mba, variable, target, target_meta, var_err))
        return agent_tools::tool_result_t::error(var_err, "bad_param");

    mbl_graph_t* graph = mba.get_graph();
    if (graph == nullptr)
        return agent_tools::tool_result_t::error(std::string("microcode graph unavailable"), "microcode_failed");
    graph_chains_t* raw = chain_kind == "du" ? graph->get_du(gctype) : graph->get_ud(gctype);
    if (raw == nullptr)
        return agent_tools::tool_result_t::error(std::string("use-def chains unavailable"), "microcode_failed");
    chain_keeper_t keeper(raw);

    nlohmann::json chains = nlohmann::json::array();
    for (size_t b = 0; b < raw->size(); ++b)
    {
        const block_chains_t& block_chains = (*raw)[b];
        for (auto it = block_chains.begin(); it != block_chains.end(); ++it)
        {
            mlist_t chain_list;
            it->append_list(&mba, &chain_list);
            mblock_t* blk = mba.get_mblock(static_cast<uint>(b));
            if (blk == nullptr)
                continue;
            mlist_t target_list;
            if (!mlist_for_operand(*blk, target, false, MAY_ACCESS, target_list))
                continue;
            if (!chain_list.has_common(target_list))
                continue;
            nlohmann::json cj = chain_to_json(*it);
            cj["block"] = static_cast<int>(b);
            chains.push_back(std::move(cj));
        }
    }

    nlohmann::json data;
    data["function_ea"] = ea_to_hex(handle->func_ea);
    data["chain_kind"] = chain_kind == "du" ? "du" : "ud";
    data["gctype"] = string_param(params, "gctype", "regs_stk");
    data["target"] = std::move(target_meta);
    data["chains"] = std::move(chains);
    data["chain_count"] = data["chains"].size();
    return agent_tools::tool_result_t::ok(std::string("Microcode SSA chains retrieved"), data);
}

agent_tools::tool_result_t handle_mc_find_uses_in_range(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    const std::string variable = string_param(params, "variable");
    if (variable.empty())
        return agent_tools::tool_result_t::error(std::string("variable is required"), "bad_param");
    auto from_opt = parse_required_address_param(params, "from_ea", err);
    if (!from_opt)
        return err;
    auto to_opt = parse_required_address_param(params, "to_ea", err);
    if (!to_opt)
        return err;

    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode"), "microcode_failed");
    mba_t& mba = *handle->mba;
    mop_t target;
    nlohmann::json target_meta;
    std::string var_err;
    if (!resolve_variable_mop(mba, variable, target, target_meta, var_err))
        return agent_tools::tool_result_t::error(var_err, "bad_param");

    const minsn_t* first_use = nullptr;
    const minsn_t* first_redef = nullptr;
    for (int i = 0; i < mba.qty; ++i)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        minsn_t* from = nullptr;
        const minsn_t* to = nullptr;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (m->ea == *from_opt)
                from = m;
            if (m->ea == *to_opt)
                to = m;
        }
        if (from == nullptr)
            continue;
        if (to == nullptr)
            to = blk->tail != nullptr && blk->tail->ea == *to_opt ? blk->tail : nullptr;
        mlist_t list;
        if (!mlist_for_operand(*blk, target, false, MAY_ACCESS, list))
            continue;
        mop_t roundtrip;
        roundtrip.zero();
        const bool roundtrip_ok = roundtrip.create_from_mlist(&mba, list, mba.fullsize);
        mlist_t use_list = list;
        first_use = blk->find_first_use(&use_list, from, to, parse_maymust(string_param(params, "maymust", "may")));
        first_redef = blk->find_redefinition(list, from, to, parse_maymust(string_param(params, "maymust", "may")));
        target_meta["sdk_mlist"] = mlist_to_string(list);
        target_meta["roundtrip_ok"] = roundtrip_ok;
        target_meta["roundtrip_mop"] = roundtrip_ok ? mop_describe(roundtrip) : std::string();
        break;
    }

    nlohmann::json data;
    data["function_ea"] = ea_to_hex(handle->func_ea);
    data["target"] = std::move(target_meta);
    data["first_use_ea"] = first_use != nullptr ? ea_to_hex(first_use->ea) : "";
    data["first_redefinition_ea"] = first_redef != nullptr ? ea_to_hex(first_redef->ea) : "";
    data["has_use"] = first_use != nullptr;
    data["has_redefinition"] = first_redef != nullptr;
    return agent_tools::tool_result_t::ok(std::string("Microcode range use/redefinition query complete"), data);
}

agent_tools::tool_result_t handle_mc_global_reachability(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    const std::string variable = string_param(params, "variable");
    if (variable.empty())
        return agent_tools::tool_result_t::error(std::string("variable is required"), "bad_param");
    const int from_block = int_param(params, "from_block", 0, 0, 1000000);
    const int to_block = int_param(params, "to_block", -1, -1, 1000000);
    const bool write = parse_bool_param(params, "write", false);

    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode"), "microcode_failed");
    mba_t& mba = *handle->mba;
    if (from_block >= mba.qty || (to_block >= 0 && to_block >= mba.qty))
        return agent_tools::tool_result_t::error(std::string("block index out of range"), "bad_param");
    mop_t target;
    nlohmann::json target_meta;
    std::string var_err;
    if (!resolve_variable_mop(mba, variable, target, target_meta, var_err))
        return agent_tools::tool_result_t::error(var_err, "bad_param");
    mblock_t* blk = mba.get_mblock(static_cast<uint>(from_block));
    if (blk == nullptr)
        return agent_tools::tool_result_t::error(std::string("source block unavailable"), "bad_param");
    mlist_t list;
    if (!mlist_for_operand(*blk, target, false, MAY_ACCESS, list))
        return agent_tools::tool_result_t::error(std::string("variable has no SDK location list"), "bad_param");

    mbl_graph_t* graph = mba.get_graph();
    if (graph == nullptr)
        return agent_tools::tool_result_t::error(std::string("microcode graph unavailable"), "microcode_failed");
    bool accessed = write
        ? graph->is_redefined_globally(list, from_block, to_block, nullptr, nullptr, parse_maymust(string_param(params, "maymust", "may")))
        : graph->is_used_globally(list, from_block, to_block, nullptr, nullptr, parse_maymust(string_param(params, "maymust", "may")));
    nlohmann::json data;
    data["function_ea"] = ea_to_hex(handle->func_ea);
    data["target"] = std::move(target_meta);
    data["from_block"] = from_block;
    data["to_block"] = to_block;
    data["access_type"] = write ? "write" : "read";
    data["reachable_access"] = accessed;
    return agent_tools::tool_result_t::ok(std::string("Microcode global reachability query complete"), data);
}

agent_tools::tool_result_t handle_mc_recognize_kernel_sinks(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode"), "microcode_failed");

    nlohmann::json calls = nlohmann::json::array();
    traverse_topinsns(*handle->mba, [&](int block_serial, minsn_t& ins) -> bool {
        if (!is_mcode_call(ins.opcode))
            return true;
        ea_t callee_ea = BADADDR;
        std::string name;
        if (!resolve_call_target(ins, callee_ea, name))
            return true;
        const std::string lower = ascii_lower(name);
        std::string role = "unknown";
        int cwe = 0;
        int len_arg = -1;
        int sensitive_arg = -1;
        int taint_arg = -1;
        if (sink_name_in(lower, sig::BUFFER_OVERFLOW_SINKS, cwe, len_arg, sensitive_arg) ||
            sink_name_in(lower, sig::COMMAND_INJECTION_SINKS, cwe, len_arg, sensitive_arg) ||
            sink_name_in(lower, sig::PATH_TRAVERSAL_SINKS, cwe, len_arg, sensitive_arg) ||
            sink_name_in(lower, sig::SAFEARRAY_PARSER_SINKS, cwe, len_arg, sensitive_arg) ||
            sink_name_in(lower, sig::DESERIALIZATION_SINKS, cwe, len_arg, sensitive_arg))
        {
            role = "sink";
        }
        else if (source_name_in(lower, sig::KERNEL_IRP_SOURCES, taint_arg) ||
                 source_name_in(lower, sig::NDIS_WSK_SOURCES, taint_arg) ||
                 source_name_in(lower, sig::INPUT_SOURCES, taint_arg))
        {
            role = "source";
        }
        else if (helper_name_in(lower, sig::KERNEL_VALIDATORS) ||
                 helper_name_in(lower, sig::LENGTH_VALIDATOR_HELPERS) ||
                 helper_name_in(lower, sig::AUTH_GATE_HELPERS))
        {
            role = "sanitizer";
        }
        if (role == "unknown")
            return true;
        nlohmann::json cj;
        cj["call_ea"] = ea_to_hex(ins.ea);
        cj["block"] = block_serial;
        cj["callee_ea"] = callee_ea != BADADDR ? ea_to_hex(callee_ea) : "";
        cj["callee_name"] = name;
        cj["role"] = role;
        cj["primary_cwe"] = cwe;
        cj["length_arg_index"] = len_arg;
        cj["sensitive_arg_index"] = sensitive_arg;
        cj["taint_arg_index"] = taint_arg;
        cj["does_return"] = callee_ea != BADADDR ? func_does_return(callee_ea) : true;
        calls.push_back(std::move(cj));
        return true;
    });

    nlohmann::json data;
    data["function_ea"] = ea_to_hex(handle->func_ea);
    data["calls"] = std::move(calls);
    data["count"] = data["calls"].size();
    return agent_tools::tool_result_t::ok(std::string("Microcode kernel source/sink recognition complete"), data);
}

agent_tools::tool_result_t handle_mc_ioctl_dispatch_summary(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "address", err);
    if (!ea_opt)
        return err;
    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode"), "microcode_failed");

    std::set<uint32_t> codes;
    traverse_topinsns(*handle->mba, [&](int, minsn_t& ins) -> bool {
        std::vector<uint64_t> nums;
        collect_numeric_mops(ins.l, nums);
        collect_numeric_mops(ins.r, nums);
        collect_numeric_mops(ins.d, nums);
        for (uint64_t n : nums)
        {
            if (n > 0xFFFFu && n <= 0xFFFFFFFFull)
                codes.insert(static_cast<uint32_t>(n));
        }
        return true;
    });

    auto method_name = [](uint32_t code) -> const char* {
        switch (code & 3u)
        {
        case 0: return "METHOD_BUFFERED";
        case 1: return "METHOD_IN_DIRECT";
        case 2: return "METHOD_OUT_DIRECT";
        case 3: return "METHOD_NEITHER";
        }
        return "UNKNOWN";
    };

    nlohmann::json arr = nlohmann::json::array();
    for (uint32_t code : codes)
    {
        nlohmann::json cj;
        char buf[16];
        ::qsnprintf(buf, sizeof(buf), "0x%08X", code);
        cj["ioctl"] = std::string(buf);
        cj["device_type"] = (code >> 16) & 0xFFFFu;
        cj["function"] = (code >> 2) & 0xFFFu;
        cj["method"] = code & 3u;
        cj["method_name"] = method_name(code);
        cj["access"] = (code >> 14) & 3u;
        cj["uses_user_pointer"] = (code & 3u) == 3u;
        arr.push_back(std::move(cj));
    }

    nlohmann::json data;
    data["function_ea"] = ea_to_hex(handle->func_ea);
    data["ioctls"] = std::move(arr);
    data["count"] = data["ioctls"].size();
    return agent_tools::tool_result_t::ok(std::string("Microcode IOCTL dispatch summary complete"), data);
}

agent_tools::tool_result_t handle_mc_set_input_constraint(const nlohmann::json& params)
{
    const std::string name = string_param(params, "name");
    if (name.empty())
        return agent_tools::tool_result_t::error(std::string("name is required"), "bad_param");
    nlohmann::json record = params;
    record["kind"] = "input_constraint";
    {
        std::lock_guard<std::mutex> lk(microcode_session_constraints_mutex());
        microcode_session_constraints()[name] = record;
    }
    nlohmann::json data;
    data["name"] = name;
    data["constraint"] = std::move(record);
    return agent_tools::tool_result_t::ok(std::string("Microcode input constraint stored"), data);
}

agent_tools::tool_result_t handle_mc_assume_attacker_buffer(const nlohmann::json& params)
{
    const std::string name = string_param(params, "name", "attacker_buffer");
    const int argidx = int_param(params, "argidx", 0, 0, 1024);
    const int size = int_param(params, "size", 256, 1, 1048576);
    nlohmann::json record = params;
    record["kind"] = "attacker_buffer";
    record["argidx"] = argidx;
    record["size"] = size;
    {
        std::lock_guard<std::mutex> lk(microcode_session_constraints_mutex());
        microcode_session_constraints()[name] = record;
    }
    nlohmann::json data;
    data["name"] = name;
    data["assumption"] = std::move(record);
    return agent_tools::tool_result_t::ok(std::string("Microcode attacker buffer assumption stored"), data);
}

agent_tools::tool_result_t handle_mc_smt_bv_extremum(const nlohmann::json& params)
{
    const std::string var = string_param(params, "variable");
    if (var.empty())
        return agent_tools::tool_result_t::error(std::string("variable is required"), "bad_param");
    const int width = int_param(params, "width", 64, 1, 64);
    const int timeout_ms = int_param(params, "timeout_ms", 5000, 100, 60000);
    const std::string formula = string_param(params, "formula");
    const std::string mode = ascii_lower(string_param(params, "mode", "max"));

    aida::vuln::smt::SmtContext local;
    if (!local.is_available())
        return agent_tools::tool_result_t::error(std::string("SMT unavailable: ") + std::string(local.last_error()), "smt_unsat");
    if (!local.declare_bv(var, width))
        return agent_tools::tool_result_t::error(std::string("SMT declaration failed: ") + std::string(local.last_error()), "bad_param");
    if (!formula.empty() && !local.assert_smtlib2(formula))
        return agent_tools::tool_result_t::error(std::string("SMT formula rejected: ") + std::string(local.last_error()), "bad_param");
    auto value = mode == "min" ? local.min_value_bv(var, width, static_cast<uint32_t>(timeout_ms))
                               : local.max_value_bv(var, width, static_cast<uint32_t>(timeout_ms));
    nlohmann::json data;
    data["variable"] = var;
    data["width"] = width;
    data["mode"] = mode == "min" ? "min" : "max";
    data["satisfiable"] = value.has_value();
    data["value"] = value.has_value() ? *value : 0;
    data["smtlib_dump"] = local.to_smtlib2();
    return agent_tools::tool_result_t::ok(std::string("Bit-vector extremum query complete"), data);
}

agent_tools::tool_result_t handle_query_value_ranges(const nlohmann::json& params)
{
    agent_tools::tool_result_t err;
    auto ea_opt = parse_required_address_param(params, "ea", err);
    if (!ea_opt)
        return err;
    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode"), "microcode_failed");
    mba_t& mba = *handle->mba;
    mblock_t* found_blk = nullptr;
    minsn_t* found_ins = nullptr;
    for (int i = 0; i < mba.qty && found_ins == nullptr; ++i)
    {
        mblock_t* blk = mba.get_mblock(static_cast<uint>(i));
        if (blk == nullptr)
            continue;
        for (minsn_t* m = blk->head; m != nullptr; m = m->next)
        {
            if (m->ea == *ea_opt)
            {
                found_blk = blk;
                found_ins = m;
                break;
            }
        }
    }
    if (found_blk == nullptr)
        return agent_tools::tool_result_t::error(std::string("instruction not found in microcode"), "bad_param");

    vivl_t vivl;
    const int width = int_param(params, "width", 8, 1, 8);
    const std::string reg = string_param(params, "reg");
    if (!reg.empty())
    {
        mreg_t mr = reg_name_to_mreg(reg);
        if (mr == mr_none)
            return agent_tools::tool_result_t::error(std::string("unknown register"), "bad_param");
        vivl.set_reg(mr, width);
    }
    else
    {
        const std::int64_t stk = int64_param(params, "stkvar_offset", 0);
        vivl.set_stkoff(static_cast<sval_t>(stk), width);
    }
    const std::string pos = ascii_lower(string_param(params, "position", "exact"));
    int flags = pos == "end" ? VR_AT_END : VR_AT_START;
    if (pos == "exact")
        flags |= VR_EXACT;
    valrng_t range(width);
    bool ok = found_blk->get_valranges(&range, vivl, found_ins, flags);
    qstring text;
    if (ok)
        range.print(&text);

    nlohmann::json data;
    data["function_ea"] = ea_to_hex(handle->func_ea);
    data["ea"] = ea_to_hex(*ea_opt);
    data["available"] = ok;
    data["range"] = ok && !text.empty() ? std::string(text.c_str()) : std::string();
    data["all_values"] = ok && range.all_values();
    data["unknown"] = ok && range.is_unknown();
    data["empty"] = ok && range.empty();
    return agent_tools::tool_result_t::ok(std::string("Value range query complete"), data);
}

agent_tools::tool_result_t handle_decompile_with_microcode(const nlohmann::json& params)
{
    std::optional<ea_t> ea_opt;
    if (params.contains("address") && params["address"].is_string())
        ea_opt = agent_tools::helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt.has_value())
        return agent_tools::tool_result_t::error(std::string("Invalid or missing address"));

    std::string maturity_str_in = "lvars";
    if (params.contains("maturity") && params["maturity"].is_string())
        maturity_str_in = params["maturity"].get<std::string>();
    mba_maturity_t mat = parse_maturity(maturity_str_in);

    size_t offset = 0;
    if (params.contains("offset"))
    {
        const auto& o = params["offset"];
        if (o.is_number_integer())
            offset = static_cast<size_t>(std::max<std::int64_t>(0, o.get<std::int64_t>()));
        else if (o.is_number_unsigned())
            offset = static_cast<size_t>(o.get<std::uint64_t>());
        else if (o.is_number())
            offset = static_cast<size_t>(std::max<double>(0.0, o.get<double>()));
    }

    size_t limit = 2000;
    if (params.contains("limit"))
    {
        const auto& l = params["limit"];
        if (l.is_number_integer())
            limit = static_cast<size_t>(std::max<std::int64_t>(0, l.get<std::int64_t>()));
        else if (l.is_number_unsigned())
            limit = static_cast<size_t>(l.get<std::uint64_t>());
        else if (l.is_number())
            limit = static_cast<size_t>(std::max<double>(0.0, l.get<double>()));
    }
    if (limit == 0)
        limit = 2000;
    if (limit > 50000)
        limit = 50000;

    auto handle = generate(*ea_opt, mat);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode for the function"));

    nlohmann::json data = dump_mba(*handle->mba, offset, limit);
    std::string msg = std::string("Microcode generated at maturity ") + std::string(maturity_str(mat));
    return agent_tools::tool_result_t::ok(msg, data);
}

agent_tools::tool_result_t handle_get_microcode_dataflow(const nlohmann::json& params)
{
    std::optional<ea_t> ea_opt;
    if (params.contains("address") && params["address"].is_string())
        ea_opt = agent_tools::helpers::parse_address(params["address"].get<std::string>());
    if (!ea_opt.has_value())
        return agent_tools::tool_result_t::error(std::string("Invalid or missing address"));

    std::string variable;
    if (params.contains("variable") && params["variable"].is_string())
        variable = params["variable"].get<std::string>();
    if (variable.empty())
        return agent_tools::tool_result_t::error(std::string("Missing 'variable' parameter (lvar:NAME, lvar:INDEX, reg:NAME, stk:OFFSET)"));

    auto handle = generate(*ea_opt, MMAT_LVARS);
    if (!handle.has_value() || handle->mba == nullptr)
        return agent_tools::tool_result_t::error(std::string("Failed to generate microcode for the function"));

    mba_t& mba = *handle->mba;

    auto colon = variable.find(':');
    if (colon == std::string::npos)
        return agent_tools::tool_result_t::error(std::string("Invalid variable spec; expected lvar:NAME or lvar:INDEX or reg:NAME or stk:OFFSET"));

    std::string kind  = ascii_lower(variable.substr(0, colon));
    std::string value = variable.substr(colon + 1);

    def_use_t du;
    nlohmann::json target_meta;
    target_meta["kind"]  = kind;
    target_meta["value"] = value;

    if (kind == "lvar")
    {
        int idx = -1;
        if (!value.empty())
        {
            const char* cstr = value.c_str();
            char* endp = nullptr;
            long parsed = ::strtol(cstr, &endp, 10);
            if (endp != nullptr && *endp == '\0' && endp != cstr &&
                parsed >= 0 && parsed <= std::numeric_limits<int>::max())
            {
                idx = static_cast<int>(parsed);
            }
        }
        if (idx < 0)
            idx = find_lvar_by_name(mba, value);
        if (idx < 0)
            return agent_tools::tool_result_t::error(std::string("lvar not found: ") + value);
        target_meta["lvar_idx"] = idx;
        if (idx >= 0 && static_cast<size_t>(idx) < mba.vars.size())
            target_meta["lvar_name"] = std::string(mba.vars[idx].name.c_str());
        du = def_use_chain_for_lvar(mba, idx);
    }
    else if (kind == "reg")
    {
        mreg_t reg = reg_name_to_mreg(value);
        if (reg == mr_none)
            return agent_tools::tool_result_t::error(std::string("Unknown register: ") + value);
        target_meta["reg"] = static_cast<int>(reg);
        du = def_use_chain_for_reg(mba, reg);
    }
    else if (kind == "stk")
    {
        std::int64_t off = 0;
        if (!parse_int64(value, off))
            return agent_tools::tool_result_t::error(std::string("Invalid stack offset (hex expected): ") + value);
        target_meta["stk_off"] = off;
        du = def_use_chain_for_stkvar(mba, static_cast<sval_t>(off));
    }
    else
    {
        return agent_tools::tool_result_t::error(std::string("Unknown variable kind: ") + kind);
    }

    nlohmann::json data = def_use_to_json(du);
    data["target"]   = std::move(target_meta);
    data["func_ea"]  = ea_to_hex(handle->func_ea);
    data["maturity"] = maturity_str(handle->maturity);

    std::string msg = std::string("Dataflow: ") +
                      std::to_string(du.defs.size()) +
                      std::string(" def(s), ") +
                      std::to_string(du.uses.size()) +
                      std::string(" use(s)");
    return agent_tools::tool_result_t::ok(msg, data);
}

}

void register_tier1_microcode_tools()
{
    auto& registry = agent_tools::ToolRegistry::instance();

    registry.register_tool({
        std::string("decompile_with_microcode"),
        std::string("vuln"),
        std::string("Generate Hex-Rays microcode for a function at a specified maturity level "
               "(generated/preoptimized/locopt/calls/glbopt1/glbopt2/glbopt3/lvars) and return "
               "a structured JSON dump of every basic block, control-flow edges, and decoded "
               "instructions with operand-level detail. Useful for low-level vulnerability "
               "analysis where C decompilation hides taint propagation, opaque predicates, or "
               "intermediate value-numbered locations."),
        {
            {std::string("address"),  std::string("string"),
             std::string("Function address (0x...) or function name"), true},
            {std::string("maturity"), std::string("string"),
             std::string("Microcode maturity level (default: lvars)"), false,
             {std::string("generated"), std::string("preoptimized"), std::string("locopt"),
              std::string("calls"), std::string("glbopt1"), std::string("glbopt2"),
              std::string("glbopt3"), std::string("lvars")}},
            {std::string("offset"),   std::string("number"),
             std::string("Skip this many top-level instructions before emitting (default 0)"), false},
            {std::string("limit"),    std::string("number"),
             std::string("Maximum top-level instructions to return (default 2000, max 50000)"), false},
        },
        handle_decompile_with_microcode,
        true,
    });

    registry.register_tool({
        std::string("get_microcode_dataflow"),
        std::string("vuln"),
        std::string("Compute the def/use chain at MMAT_LVARS for a single named local variable, "
               "register, or stack slot inside a function. Returns the addresses of every "
               "definition and use, the linear reaching-definition pairs, and any conditional "
               "constraints encountered along the way. Inputs format: 'lvar:NAME', 'lvar:INDEX', "
               "'reg:NAME' (e.g. reg:rax), or 'stk:OFFSET' (decompiler-stkoff in hex)."),
        {
            {std::string("address"),  std::string("string"),
             std::string("Function address (0x...) or function name"), true},
            {std::string("variable"), std::string("string"),
             std::string("Variable spec: lvar:NAME or lvar:INDEX or reg:NAME or stk:OFFSET"), true},
        },
        handle_get_microcode_dataflow,
        true,
    });

    registry.register_tool({
        std::string("mc_path_smtlib"),
        std::string("vuln"),
        std::string("Collect branch predicates along a real microcode CFG path from function entry to sink_ea and emit SMT-LIB2."),
        {
            {std::string("address"), std::string("string"), std::string("Function address or name."), true},
            {std::string("sink_ea"), std::string("string"), std::string("Target instruction address."), true},
            {std::string("maturity"), std::string("string"), std::string("Microcode maturity, default glbopt3."), false},
            {std::string("max_branches"), std::string("number"), std::string("Maximum branch predicates to emit."), false},
        },
        handle_mc_path_smtlib,
        true,
    });

    registry.register_tool({
        std::string("mc_solve_path"),
        std::string("vuln"),
        std::string("Solve feasibility for a real microcode CFG path from function entry to sink_ea with optional extra SMT-LIB2 assertions."),
        {
            {std::string("address"), std::string("string"), std::string("Function address or name."), true},
            {std::string("sink_ea"), std::string("string"), std::string("Target instruction address."), true},
            {std::string("maturity"), std::string("string"), std::string("Microcode maturity, default glbopt3."), false},
            {std::string("extra_smtlib2_assertions"), std::string("string"), std::string("Additional SMT-LIB2 assertions."), false},
            {std::string("timeout_ms"), std::string("number"), std::string("Solver timeout in milliseconds."), false},
            {std::string("max_branches"), std::string("number"), std::string("Maximum branch predicates to emit."), false},
        },
        handle_mc_solve_path,
        true,
    });

    registry.register_tool({
        std::string("mc_dataflow_ssa"),
        std::string("vuln"),
        std::string("Query Hex-Rays microcode use-def or def-use SSA chains for one lvar, register, or stack slot."),
        {
            {std::string("address"), std::string("string"), std::string("Function address or name."), true},
            {std::string("variable"), std::string("string"), std::string("Variable spec lvar:NAME, reg:rax, or stk:OFFSET."), true},
            {std::string("chain_kind"), std::string("string"), std::string("ud or du."), false},
            {std::string("gctype"), std::string("string"), std::string("regs_stk, asr, or xdsu."), false},
        },
        handle_mc_dataflow_ssa,
        true,
    });

    registry.register_tool({
        std::string("mc_find_uses_in_range"),
        std::string("vuln"),
        std::string("Use Hex-Rays microcode location lists to find first use and redefinition of a variable in an instruction range."),
        {
            {std::string("address"), std::string("string"), std::string("Function address or name."), true},
            {std::string("variable"), std::string("string"), std::string("Variable spec lvar:NAME, reg:rax, or stk:OFFSET."), true},
            {std::string("from_ea"), std::string("string"), std::string("Range start instruction EA."), true},
            {std::string("to_ea"), std::string("string"), std::string("Range end instruction EA."), true},
            {std::string("maymust"), std::string("string"), std::string("may or must."), false},
        },
        handle_mc_find_uses_in_range,
        true,
    });

    registry.register_tool({
        std::string("mc_global_reachability"),
        std::string("vuln"),
        std::string("Ask the Hex-Rays microcode graph whether a variable is read or written globally between blocks."),
        {
            {std::string("address"), std::string("string"), std::string("Function address or name."), true},
            {std::string("variable"), std::string("string"), std::string("Variable spec lvar:NAME, reg:rax, or stk:OFFSET."), true},
            {std::string("from_block"), std::string("number"), std::string("Source microcode block serial."), false},
            {std::string("to_block"), std::string("number"), std::string("Destination microcode block serial, -1 for any."), false},
            {std::string("write"), std::string("boolean"), std::string("Check writes instead of reads."), false},
            {std::string("maymust"), std::string("string"), std::string("may or must."), false},
        },
        handle_mc_global_reachability,
        true,
    });

    registry.register_tool({
        std::string("mc_recognize_kernel_sinks"),
        std::string("vuln"),
        std::string("Classify microcode calls as kernel/user-input sources, sinks, or sanitizers using the signature database."),
        {
            {std::string("address"), std::string("string"), std::string("Function address or name."), true},
        },
        handle_mc_recognize_kernel_sinks,
        true,
    });

    registry.register_tool({
        std::string("mc_ioctl_dispatch_summary"),
        std::string("vuln"),
        std::string("Summarize IOCTL constants seen in a dispatcher function and decode method/access fields."),
        {
            {std::string("address"), std::string("string"), std::string("Dispatcher function address or name."), true},
        },
        handle_mc_ioctl_dispatch_summary,
        true,
    });

    registry.register_tool({
        std::string("mc_set_input_constraint"),
        std::string("vuln"),
        std::string("Store a symbolic input constraint in the microcode analysis session."),
        {
            {std::string("name"), std::string("string"), std::string("Constraint name."), true},
            {std::string("width"), std::string("number"), std::string("Bit width."), false},
            {std::string("unsigned_lt"), std::string("number"), std::string("Unsigned upper bound."), false},
        },
        handle_mc_set_input_constraint,
        false,
    });

    registry.register_tool({
        std::string("mc_assume_attacker_buffer"),
        std::string("vuln"),
        std::string("Store an attacker-controlled buffer assumption for a function argument in the microcode analysis session."),
        {
            {std::string("name"), std::string("string"), std::string("Assumption name."), false},
            {std::string("argidx"), std::string("number"), std::string("Function argument index."), true},
            {std::string("size"), std::string("number"), std::string("Symbolic byte length."), false},
        },
        handle_mc_assume_attacker_buffer,
        false,
    });

    registry.register_tool({
        std::string("mc_smt_bv_extremum"),
        std::string("vuln"),
        std::string("Use Z3 optimize to compute a min or max value for a bit-vector variable under optional SMT-LIB2 constraints."),
        {
            {std::string("variable"), std::string("string"), std::string("Bit-vector variable name."), true},
            {std::string("width"), std::string("number"), std::string("Bit width, 1..64."), true},
            {std::string("mode"), std::string("string"), std::string("max or min."), false},
            {std::string("formula"), std::string("string"), std::string("Optional SMT-LIB2 assertions."), false},
            {std::string("timeout_ms"), std::string("number"), std::string("Optimizer timeout in milliseconds."), false},
        },
        handle_mc_smt_bv_extremum,
        true,
    });

    registry.register_tool({
        std::string("query_value_ranges"),
        std::string("vuln"),
        std::string("Query Hex-Rays value ranges for a register or stack interval at a microcode instruction."),
        {
            {std::string("ea"), std::string("string"), std::string("Instruction address."), true},
            {std::string("reg"), std::string("string"), std::string("Register name."), false},
            {std::string("stkvar_offset"), std::string("number"), std::string("Stack offset if no register is provided."), false},
            {std::string("width"), std::string("number"), std::string("Width in bytes."), false},
            {std::string("position"), std::string("string"), std::string("start, end, or exact."), false},
        },
        handle_query_value_ranges,
        true,
    });
}

}
}
}
