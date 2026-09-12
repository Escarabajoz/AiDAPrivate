#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_jwt_mcp.hpp"
#include "jwt_lab.hpp"

#include "../../settings/standalone_compat.hpp"
#include "../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace aida {
namespace burp {

namespace {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

tool_result_t handle_decode(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_decode entry");
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    const std::string token = params["token"].get<std::string>();
    const auto parsed = jwt_lab::decode(token);
    json out;
    out["valid_structure"] = parsed.valid_structure;
    out["alg"] = parsed.alg;
    out["kid"] = parsed.kid;
    out["header"] = parsed.header;
    out["payload"] = parsed.payload;
    out["header_b64"] = parsed.header_b64;
    out["payload_b64"] = parsed.payload_b64;
    out["signature_b64"] = parsed.signature_b64;
    diag::log_tagged_fmt("mcp_burp", "jwt_decode ok alg=%s valid=%d", parsed.alg.c_str(), (int)parsed.valid_structure);
    return tool_result_t::ok(out);
}

tool_result_t handle_forge(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_forge alg=%s", params.value("alg", std::string("HS256")).c_str());
    jwt_lab::jwt_forge_input_t in;
    if (params.contains("header") && params["header"].is_object()) in.header = params["header"];
    else in.header = json::object();
    if (params.contains("payload") && params["payload"].is_object()) in.payload = params["payload"];
    else in.payload = json::object();
    in.alg = params.value("alg", std::string("HS256"));
    in.hmac_secret = params.value("hmac_secret", std::string());
    in.rsa_private_pem = params.value("rsa_private_pem", std::string());
    in.ecdsa_private_pem = params.value("ecdsa_private_pem", std::string());
    const std::string out_token = jwt_lab::forge(in);
    if (out_token.empty()) { diag::log_tagged_fmt("mcp_burp", "jwt_forge failed err=%s", jwt_lab::last_error().c_str()); return tool_result_t::error(std::string("forge failed: ") + jwt_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "jwt_forge ok token_len=%zu", out_token.size());
    json out;
    out["token"] = out_token;
    return tool_result_t::ok(out);
}

tool_result_t handle_verify(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_verify mode=%s", params.value("mode", std::string("auto")).c_str());
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    const std::string token = params["token"].get<std::string>();
    const std::string key = params.value("key", std::string());
    const std::string mode = params.value("mode", std::string("auto"));
    bool ok = false;
    if (mode == "hmac" || mode == "auto") ok = jwt_lab::verify_hmac(token, key);
    if (!ok && (mode == "rsa" || mode == "auto")) ok = jwt_lab::verify_rsa(token, key);
    if (!ok && (mode == "ecdsa" || mode == "auto")) ok = jwt_lab::verify_ecdsa(token, key);
    diag::log_tagged_fmt("mcp_burp", "jwt_verify ok verified=%d mode=%s", (int)ok, mode.c_str());
    json out;
    out["verified"] = ok;
    return tool_result_t::ok(out);
}

tool_result_t handle_crack_start(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_start wordlist=%s concurrency=%d", params.value("wordlist_id", std::string("common_passwords")).c_str(), params.value("concurrency", 8));
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    jwt_lab::crack_config_t cfg;
    cfg.token = params["token"].get<std::string>();
    cfg.wordlist_id = params.value("wordlist_id", std::string("common_passwords"));
    if (params.contains("custom_words") && params["custom_words"].is_array()) {
        for (const auto& w : params["custom_words"]) {
            if (w.is_string()) cfg.custom_words.push_back(w.get<std::string>());
        }
    }
    {
        long long cv = 8;
        if (params.contains("concurrency")) {
            if (!params["concurrency"].is_number_integer()) return tool_result_t::error("concurrency must be an integer");
            cv = params["concurrency"].get<long long>();
            if (cv < 1 || cv > 64) return tool_result_t::error("concurrency must be in 1..64");
        }
        cfg.concurrency = static_cast<size_t>(cv);
    }
    {
        long long mv = 1000000;
        if (params.contains("max_attempts")) {
            if (!params["max_attempts"].is_number_integer()) return tool_result_t::error("max_attempts must be an integer");
            mv = params["max_attempts"].get<long long>();
            if (mv < 1 || mv > 10000000) return tool_result_t::error("max_attempts must be in 1..10000000");
        }
        cfg.max_attempts = static_cast<size_t>(mv);
    }
    const uint64_t id = jwt_lab::start_crack(cfg);
    if (id == 0) { diag::log_tagged_fmt("mcp_burp", "jwt_crack_start failed err=%s", jwt_lab::last_error().c_str()); return tool_result_t::error(std::string("start_crack failed: ") + jwt_lab::last_error()); }
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_start ok crack_id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["crack_id"] = id;
    return tool_result_t::ok(out);
}

tool_result_t handle_crack_status(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("crack_id", 0));
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_status crack_id=%llu", static_cast<unsigned long long>(id));
    const auto status = jwt_lab::crack_status(id);
    json out;
    out["id"] = status.id;
    out["attempts"] = status.attempts;
    out["running"] = status.running;
    out["secret_found"] = status.secret_found;
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_status ok id=%llu running=%d found=%s attempts=%zu", static_cast<unsigned long long>(id), (int)status.running, status.secret_found.c_str(), status.attempts);
    return tool_result_t::ok(out);
}

tool_result_t handle_crack_stop(const json& params)
{
    const uint64_t id = static_cast<uint64_t>(params.value("crack_id", 0));
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_stop crack_id=%llu", static_cast<unsigned long long>(id));
    jwt_lab::crack_stop(id);
    diag::log_tagged_fmt("mcp_burp", "jwt_crack_stop ok id=%llu", static_cast<unsigned long long>(id));
    json out;
    out["stopped"] = true;
    return tool_result_t::ok(out);
}

tool_result_t handle_attack(const json& params)
{
    diag::log_tagged_fmt("mcp_burp", "jwt_attack attack=%s", params.value("attack", std::string("alg_none")).c_str());
    if (!params.contains("token") || !params["token"].is_string())
        return tool_result_t::error("missing 'token'");
    const std::string token = params["token"].get<std::string>();
    const std::string attack = params.value("attack", std::string("alg_none"));
    std::vector<std::string> candidates;
    if (attack == "alg_none") candidates = jwt_lab::attack_alg_none(token);
    else if (attack == "alg_confusion") {
        const std::string pub_pem = params.value("rsa_public_pem", std::string());
        if (pub_pem.empty()) return tool_result_t::error("alg_confusion requires rsa_public_pem");
        candidates = jwt_lab::attack_alg_confusion(token, pub_pem);
    }
    else if (attack == "kid_traversal") candidates = jwt_lab::attack_kid_traversal(token);
    else if (attack == "jku_injection") {
        const std::string url = params.value("attacker_jku_url", std::string());
        candidates = jwt_lab::attack_jku_injection(token, url);
    }
    else if (attack == "signature_strip") candidates = jwt_lab::attack_signature_strip(token);
    else return tool_result_t::error("unknown attack");

    diag::log_tagged_fmt("mcp_burp", "jwt_attack ok attack=%s candidates=%zu", attack.c_str(), candidates.size());
    json out;
    out["count"] = candidates.size();
    out["candidates"] = candidates;
    return tool_result_t::ok(out);
}

}

void register_jwt_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "burp_jwt_manage",
        "Manage JWT decoding, verification, forging, cracking, and attack generation. Actions: decode, forge, verify, crack_start, crack_status, crack_stop, attack.",
        {{"action", "string", "decode|forge|verify|crack_start|crack_status|crack_stop|attack", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        false,
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "decode") return handle_decode(p);
            if (action == "forge") return handle_forge(p);
            if (action == "verify") return handle_verify(p);
            if (action == "crack_start") return handle_crack_start(p);
            if (action == "crack_status") return handle_crack_status(p);
            if (action == "crack_stop") return handle_crack_stop(p);
            if (action == "attack") return handle_attack(p);
            return compat_unknown_action("burp_jwt_manage", action);
        }
    });
}

}
}
