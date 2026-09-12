#include "standalone_compat.hpp"
#include "helpers/diag_log.hpp"
#include "../mcp/mcp_standalone.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <functional>
#include <regex>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace network_tools
{
namespace
{

struct alias_target_t
{
    const char* action;
    const char* target;
};

std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool sensitive_key(const std::string& key)
{
    const std::string k = lower_ascii(key);
    return k.find("authorization") != std::string::npos ||
           k.find("cookie") != std::string::npos ||
           k.find("token") != std::string::npos ||
           k.find("secret") != std::string::npos ||
           k.find("password") != std::string::npos ||
           k.find("passwd") != std::string::npos ||
           k.find("api_key") != std::string::npos ||
           k.find("apikey") != std::string::npos ||
           k.find("api-key") != std::string::npos ||
           k.find("private_key") != std::string::npos ||
           k.find("private-key") != std::string::npos ||
           k.find("license") != std::string::npos ||
           k.find("session") != std::string::npos ||
           k == "raw_request" ||
           k == "raw_response" ||
           k == "request_body" ||
           k == "response_body" ||
           k == "body" ||
           k == "body_base64" ||
           k == "modified_request_b64" ||
           k == "source" ||
           k == "source_code" ||
           k == "script_source";
}

std::uint64_t fnv1a64(const std::string& s)
{
    std::uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ULL;
    }
    return h;
}

std::string hex_u64(std::uint64_t v)
{
    static const char* digits = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = digits[v & 0xF];
        v >>= 4;
    }
    return out;
}

std::string summary_string(const std::string& s)
{
    return "<redacted len=" + std::to_string(s.size()) + " fnv1a64=" + hex_u64(fnv1a64(s)) + ">";
}

std::string redact_text(std::string text)
{
    try {
        static const std::regex key_value(
            R"((\"?(?:password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|private[_-]?key|license[_-]?key|authorization|cookie|session[_-]?id)\"?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^&\s,}]+))",
            std::regex_constants::icase);
        text = std::regex_replace(text, key_value, "$1<redacted>");
        static const std::regex bearer(R"(\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,})", std::regex_constants::icase);
        text = std::regex_replace(text, bearer, "$1 <redacted>");
        static const std::regex private_key(R"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)", std::regex_constants::icase);
        text = std::regex_replace(text, private_key, "<redacted-private-key>");
        static const std::regex aida_key(R"(\bAIDA-[A-Za-z0-9-]{8,}\b)", std::regex_constants::icase);
        text = std::regex_replace(text, aida_key, "<redacted-license-key>");
    } catch (...) {
        if (text.size() > 1024)
            text.resize(1024);
    }
    return text;
}

bool text_contains_secret_marker(const std::string& text)
{
    const std::string lc = lower_ascii(text);
    return lc.find("-----begin") != std::string::npos ||
           lc.find("private key") != std::string::npos ||
           lc.find("access_token") != std::string::npos ||
           lc.find("refresh_token") != std::string::npos ||
           lc.find("api_key") != std::string::npos ||
           lc.find("apikey") != std::string::npos ||
           lc.find("authorization") != std::string::npos ||
           lc.find("bearer ") != std::string::npos ||
           lc.find("set-cookie") != std::string::npos ||
           lc.find("license_key") != std::string::npos ||
           lc.find("password") != std::string::npos;
}

json sanitize_json(const json& in, const std::string& key = std::string())
{
    if (mcp_standalone::current_call_cancelled())
        return "<redacted-cancelled>";
    if (in.is_object()) {
        json out = json::object();
        bool header_like = false;
        std::string header_name;
        if (in.contains("name") && in["name"].is_string() && in.contains("value") && in["value"].is_string()) {
            header_name = in["name"].get<std::string>();
            header_like = true;
        }
        for (auto it = in.begin(); it != in.end(); ++it) {
            if (header_like && it.key() == "value" && sensitive_key(header_name) && it.value().is_string()) {
                out[it.key()] = summary_string(it.value().get<std::string>());
                continue;
            }
            out[it.key()] = sanitize_json(it.value(), it.key());
        }
        return out;
    }
    if (in.is_array()) {
        json out = json::array();
        for (const auto& item : in)
            out.push_back(sanitize_json(item, key));
        return out;
    }
    if (in.is_string()) {
        const std::string s = in.get<std::string>();
        if (sensitive_key(key) || text_contains_secret_marker(s))
            return summary_string(s);
        if (key.find("preview") != std::string::npos || s.size() <= 4096)
            return redact_text(s);
        return summary_string(s);
    }
    return in;
}

tool_result_t sanitize_result(tool_result_t result)
{
    if (!result.data.is_null() && !result.data.empty()) {
        result.data = sanitize_json(result.data);
        result.text = result.data.dump(2);
    } else {
        result.text = redact_text(result.text);
    }
    if (!result.error_details.is_null() && !result.error_details.empty())
        result.error_details = sanitize_json(result.error_details);
    return result;
}

json forwarded_args(const json& args)
{
    if (!args.is_object())
        return json::object();
    json out = args;
    if (args.contains("payload") && args["payload"].is_object()) {
        for (auto it = args["payload"].begin(); it != args["payload"].end(); ++it) {
            if (!out.contains(it.key()))
                out[it.key()] = it.value();
        }
        out.erase("payload");
    }
    return out;
}

std::vector<mcp_standalone::tool_param_t> passthrough_params()
{
    return {
        {"action", "string", "Canonical tool action when the target tool is action-based.", false},
        {"operation", "string", "Alias for action on tools that use operation.", false},
        {"payload", "object", "Action-specific parameters; top-level fields are also accepted.", false}
    };
}

void register_direct_alias(mcp_standalone::server_t& srv,
                           const char* alias,
                           const char* target,
                           const char* description,
                           bool read_only,
                           std::vector<mcp_standalone::tool_param_t> params = passthrough_params())
{
    srv.register_tool({
        alias,
        description,
        std::move(params),
        read_only,
        [&srv, target, alias](const json& args) -> tool_result_t {
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error(std::string(alias) + " cancelled before dispatch", std::string("cancelled"), json::object());
            diag::log_tagged_fmt("tool_alias", "dispatch alias=%s target=%s", alias, target);
            return sanitize_result(srv.call_registered_tool(target, forwarded_args(args), false));
        }
    });
}

void register_dispatch_alias(mcp_standalone::server_t& srv,
                             const char* alias,
                             const char* description,
                             bool read_only,
                             std::vector<alias_target_t> targets)
{
    srv.register_tool({
        alias,
        description,
        passthrough_params(),
        read_only,
        [&srv, alias, targets = std::move(targets)](const json& args) -> tool_result_t {
            if (mcp_standalone::current_call_cancelled())
                return tool_result_t::error(std::string(alias) + " cancelled before dispatch", std::string("cancelled"), json::object());
            std::string action = lower_ascii(compat_action_name(args));
            if (action.empty() && args.contains("tool") && args["tool"].is_string())
                action = lower_ascii(args["tool"].get<std::string>());
            if (action.empty() && args.contains("module") && args["module"].is_string())
                action = lower_ascii(args["module"].get<std::string>());
            for (const auto& target : targets) {
                if (action == target.action) {
                    diag::log_tagged_fmt("tool_alias", "dispatch alias=%s action=%s target=%s", alias, action.c_str(), target.target);
                    return sanitize_result(srv.call_registered_tool(target.target, forwarded_args(args), false));
                }
            }
            json detail;
            detail["action"] = action;
            json accepted = json::array();
            for (const auto& target : targets)
                accepted.push_back(target.action);
            detail["accepted_actions"] = accepted;
            return tool_result_t::error(std::string(alias) + " unknown action", "unknown_action", detail);
        }
    });
}

}

void register_network_tool_aliases(mcp_standalone::server_t& srv)
{
    diag::log_tagged("tool_alias", "register_network_tool_aliases entry");
    register_direct_alias(srv, "aida.network.capture", "network_capture_manage", "Alias for kernel packet capture management.", false);
    register_direct_alias(srv, "aida.network.filter", "network_filter_manage", "Alias for kernel network filter rule management.", false);
    register_direct_alias(srv, "aida.network.bandwidth", "network_bandwidth_manage", "Alias for bandwidth monitoring.", false);
    register_direct_alias(srv, "aida.network.firewall", "network_firewall_manage", "Alias for quick firewall actions.", false);
    register_direct_alias(srv, "aida.network.deep_inspect", "network_deep_inspect", "Alias for deep packet inspection.", true);
    register_direct_alias(srv, "aida.network.parse_http", "network_parse_http", "Alias for parsing captured HTTP traffic.", true);
    register_direct_alias(srv, "aida.network.parse_tls", "network_parse_tls", "Alias for parsing captured TLS handshakes.", true);
    register_direct_alias(srv, "aida.network.wfp_callouts", "network_enumerate_wfp_callouts", "Alias for WFP callout enumeration.", true);
    register_direct_alias(srv, "aida.network.socket_handles", "network_get_socket_handles", "Alias for socket handle enumeration.", true);
    register_direct_alias(srv, "aida.network.tcpip_dump", "network_dump_tcpip", "Alias for TCPIP stack connection dumps.", true);
    register_direct_alias(srv, "aida.network.interfaces", "network_enumerate_interfaces", "Alias for network interface enumeration.", true);
    register_direct_alias(srv, "aida.network.inject", "network_inject_packet", "Alias for packet injection.", false);
    register_direct_alias(srv, "aida.network.packet_mod", "network_packet_mod_manage", "Alias for packet modification rule management.", false);
    register_direct_alias(srv, "aida.network.redirect", "network_redirect_manage", "Alias for traffic redirect rule management.", false);
    register_direct_alias(srv, "aida.network.intercept", "network_intercept_manage", "Alias for packet interception management.", false);
    register_direct_alias(srv, "aida.network.dns", "network_dns_manage", "Alias for DNS logging and spoofing management.", false);
    register_direct_alias(srv, "aida.network.os_fingerprint", "network_os_fingerprint", "Alias for passive OS fingerprinting.", false);
    register_direct_alias(srv, "aida.network.decode", "network_decode_data", "Alias for CyberChef-style network data transforms.", false);
    register_direct_alias(srv, "aida.network.transforms", "network_list_transforms", "Alias for listing network transforms.", true);
    register_direct_alias(srv, "aida.network.stream", "network_stream_track", "Alias for TCP stream tracking.", false);
    register_direct_alias(srv, "aida.network.pg_sniff", "network_pg_sniff", "Alias for PAGE_GUARD pre-encryption sniffing.", false);
    register_direct_alias(srv, "aida.network.packet_callstack", "network_packet_callstack", "Alias for packet callstack capture.", false);
    register_direct_alias(srv, "aida.network.pre_encrypt_hook", "network_pre_encrypt_hook", "Alias for SSL/TLS pre-encryption hooks.", false);
    register_direct_alias(srv, "aida.network.display_filter", "network_display_filter", "Alias for BPF-style display filter checks.", true);
    register_direct_alias(srv, "aida.network.protobuf", "network_protobuf_decode", "Alias for protobuf and gRPC decoding.", true);

    register_direct_alias(srv, "aida.tls.manage", "tls_manage", "Alias for TLS key extraction and keylog capture.", false);
    register_direct_alias(srv, "aida.tls.cert", "cert_manage", "Alias for certificate management.", false);
    register_direct_alias(srv, "aida.tls.pin_bypass", "pin_bypass", "Alias for certificate pinning diagnostics.", true);
    register_direct_alias(srv, "aida.tls.quic", "quic_manage", "Alias for QUIC analysis.", false);
    register_direct_alias(srv, "aida.tls.dtls", "dtls_manage", "Alias for DTLS analysis.", false);
    register_direct_alias(srv, "aida.tls.autoresponder", "autoresponder_manage", "Alias for AutoResponder rule management.", false);
    register_direct_alias(srv, "aida.tls.decrypt", "network_decrypt_capture", "Alias for capture decryption using TLS keys.", true);

    register_dispatch_alias(srv, "aida.burp.sitemap", "Alias group for sitemap host/path/exchange actions.", false, {
        {"list_hosts", "burp_sitemap_list_hosts"},
        {"list_paths", "burp_sitemap_list_paths"},
        {"get_exchange", "burp_sitemap_get_exchange"},
        {"send_to", "burp_sitemap_send_to"}
    });
    register_direct_alias(srv, "aida.burp.scope", "burp_scope_manage", "Alias for Burp scope management.", false);
    register_direct_alias(srv, "aida.burp.cookie", "burp_cookie_manage", "Alias for Burp cookie jar management.", false);
    register_direct_alias(srv, "aida.burp.proxy", "burp_proxy_manage", "Alias for loopback MITM proxy management.", false);
    register_direct_alias(srv, "aida.burp.scanner", "burp_scanner_manage", "Alias for active and passive scanner management.", false);
    register_direct_alias(srv, "aida.burp.dom_xss", "burp_dom_xss_manage", "Alias for DOM-XSS testing.", false);
    register_direct_alias(srv, "aida.burp.crawler", "burp_crawler_manage", "Alias for Burp crawler jobs.", false);
    register_direct_alias(srv, "aida.burp.content_discovery", "burp_content_discovery_manage", "Alias for content discovery jobs.", false);
    register_direct_alias(srv, "aida.burp.subdomain_enum", "burp_subdomain_enum_manage", "Alias for subdomain enumeration.", false);
    register_direct_alias(srv, "aida.burp.crawl_audit", "burp_crawl_audit_manage", "Alias for combined crawl and audit jobs.", false);
    register_direct_alias(srv, "aida.burp.repeater", "burp_repeater_manage", "Alias for Burp Repeater tab management.", false);
    register_direct_alias(srv, "aida.burp.decoder", "burp_decoder_manage", "Alias for Burp decoder workflows.", false);
    register_direct_alias(srv, "aida.burp.intruder", "burp_intruder_manage", "Alias for Intruder and Turbo attack jobs.", false);
    register_direct_alias(srv, "aida.burp.param_miner", "burp_param_miner_manage", "Alias for hidden parameter discovery.", false);
    register_direct_alias(srv, "aida.burp.h2", "burp_h2_send", "Alias for controlled HTTP/2 requests.", false);
    register_direct_alias(srv, "aida.burp.collaborator", "burp_collaborator_manage", "Alias for Collaborator-style OOB interactions.", false);
    register_direct_alias(srv, "aida.burp.sequencer", "burp_sequencer_manage", "Alias for token sequencer jobs.", false);
    register_direct_alias(srv, "aida.burp.comparer", "burp_comparer_manage", "Alias for Burp Comparer slots and diffs.", false);
    register_direct_alias(srv, "aida.burp.match_replace", "burp_match_replace_manage", "Alias for match-and-replace rules.", false);
    register_direct_alias(srv, "aida.burp.api", "burp_api_manage", "Alias for API collection management.", false);
    register_direct_alias(srv, "aida.burp.graphql", "burp_graphql_manage", "Alias for GraphQL tooling.", false);
    register_direct_alias(srv, "aida.burp.ws", "burp_ws_manage", "Alias for WebSocket tooling.", false);
    register_direct_alias(srv, "aida.burp.logger", "burp_logger_manage", "Alias for Burp logger query/export.", false);
    register_direct_alias(srv, "aida.burp.report", "burp_report_manage", "Alias for report generation management.", false);
    register_direct_alias(srv, "aida.burp.report_generate", "burp_report_generate", "Alias for vulnerability report generation.", false);
    register_direct_alias(srv, "aida.burp.jwt", "burp_jwt_manage", "Alias for JWT lab operations.", false);
    register_direct_alias(srv, "aida.burp.upstream", "burp_upstream_manage", "Alias for upstream proxy chain management.", false);
    register_direct_alias(srv, "aida.burp.project", "burp_project_manage", "Alias for Burp project import, export, save, and load.", false);
    register_direct_alias(srv, "aida.burp.search", "burp_global_search", "Alias for global Burp search.", true);
    register_direct_alias(srv, "aida.burp.extensions.list", "burp_extensions_list", "Alias for listing Burp extensions.", true);
    register_direct_alias(srv, "aida.burp.extensions.refresh", "burp_extensions_refresh", "Alias for refreshing Burp extensions.", false);
    register_direct_alias(srv, "aida.burp.extensions.get", "burp_extensions_get", "Alias for reading extension metadata.", true);
    register_direct_alias(srv, "aida.burp.extensions.set_enabled", "burp_extensions_set_enabled", "Alias for enabling or disabling an extension.", false);
    register_direct_alias(srv, "aida.burp.proxy.set_mode", "proxy_set_mode", "Alias for MITM proxy mode control.", false);
    register_direct_alias(srv, "aida.burp.proxy.start_listener", "proxy_start_listener", "Alias for MITM listener startup.", false);
    register_direct_alias(srv, "aida.burp.proxy.stop_listener", "proxy_stop_listener", "Alias for MITM listener shutdown.", false);
    register_direct_alias(srv, "aida.burp.proxy.list_listeners", "proxy_list_listeners", "Alias for MITM listener snapshots.", true);
    register_direct_alias(srv, "aida.burp.proxy.set_pac", "proxy_set_pac", "Alias for bounded MITM PAC routing control.", false);
    register_direct_alias(srv, "aida.burp.proxy.set_tls_policy", "proxy_set_tls_policy", "Alias for MITM TLS policy control.", false);
    register_direct_alias(srv, "aida.burp.flow.save", "flow_save", "Alias for saving captured flows.", false);
    register_direct_alias(srv, "aida.burp.flow.load", "flow_load", "Alias for loading captured flows.", false);
    register_direct_alias(srv, "aida.burp.flow.note", "flow_note", "Alias for captured flow notes.", false);
    register_direct_alias(srv, "aida.burp.client_replay", "client_replay", "Alias for client-side replay.", false);
    register_direct_alias(srv, "aida.burp.server_replay.start", "server_replay_start", "Alias for server replay startup.", false);
    register_direct_alias(srv, "aida.burp.server_replay.stop", "server_replay_stop", "Alias for server replay shutdown.", false);
    register_dispatch_alias(srv, "aida.burp.payloads", "Alias group for Burp payload set operations.", false, {
        {"list", "burp_payloads_list"},
        {"get", "burp_payloads_get"},
        {"search", "burp_payloads_search"},
        {"add_custom", "burp_payloads_add_custom"}
    });
    register_dispatch_alias(srv, "aida.burp.auth", "Alias group for HTTP auth helper tools.", false, {
        {"basic_encode", "burp_auth_basic_encode"},
        {"basic_decode", "burp_auth_basic_decode"},
        {"digest_solve", "burp_auth_digest_solve"},
        {"ntlm_type1", "burp_auth_ntlm_type1"},
        {"ntlm_type3", "burp_auth_ntlm_type3"},
        {"bearer", "burp_auth_bearer"},
        {"oauth2_pkce", "burp_auth_oauth2_pkce"},
        {"oauth2_build_auth_url", "burp_auth_oauth2_build_auth_url"},
        {"oauth2_exchange_code", "burp_auth_oauth2_exchange_code"},
        {"oauth2_refresh", "burp_auth_oauth2_refresh"},
        {"saml_decode_request", "burp_auth_saml_decode_request"},
        {"saml_decode_response", "burp_auth_saml_decode_response"}
    });
    register_dispatch_alias(srv, "aida.burp.bambda", "Alias group for Bambda compile/test/help.", true, {
        {"compile", "burp_bambda_compile"},
        {"test", "burp_bambda_test"},
        {"help", "burp_bambda_help"}
    });
    register_dispatch_alias(srv, "aida.burp.csp", "Alias group for CSP analysis.", false, {
        {"analyze", "burp_csp_analyze"},
        {"analyze_url", "burp_csp_analyze_url"}
    });
    register_dispatch_alias(srv, "aida.burp.tech", "Alias group for technology fingerprinting.", false, {
        {"fingerprint", "burp_tech_fingerprint"},
        {"inventory", "burp_tech_inventory"},
        {"clear", "burp_tech_clear"}
    });
    register_dispatch_alias(srv, "aida.burp.session", "Alias group for macro and session-rule management.", false, {
        {"macro", "burp_macro_manage"},
        {"rule", "burp_session_rule_manage"}
    });
    register_dispatch_alias(srv, "aida.burp.recon", "Alias group for crawler, content discovery, subdomain enum, payloads, and crawl audit.", false, {
        {"crawler", "burp_crawler_manage"},
        {"content_discovery", "burp_content_discovery_manage"},
        {"subdomain_enum", "burp_subdomain_enum_manage"},
        {"payloads", "burp_payloads_list"},
        {"crawl_audit", "burp_crawl_audit_manage"}
    });

    register_direct_alias(srv, "aida.browser.lifecycle", "browser_lifecycle", "Alias for Camoufox lifecycle management.", false);
    register_direct_alias(srv, "aida.browser.navigation", "browser_navigation", "Alias for Camoufox navigation.", false);
    register_direct_alias(srv, "aida.browser.interaction", "browser_interaction", "Alias for Camoufox interaction.", false);
    register_direct_alias(srv, "aida.browser.inspect", "browser_inspect", "Alias for Camoufox inspection.", false);
    register_direct_alias(srv, "aida.browser.state", "browser_state", "Alias for Camoufox cookies and storage state.", false);
    register_direct_alias(srv, "aida.browser.network", "browser_network", "Alias for Camoufox network capture and interception.", false);
    register_direct_alias(srv, "aida.browser.hooks", "browser_hooks", "Alias for Camoufox JavaScript hooks.", false);
    register_direct_alias(srv, "aida.browser.instrumentation", "browser_instrumentation", "Alias for Camoufox instrumentation.", false);
    register_direct_alias(srv, "aida.browser.service_worker", "browser_service_worker", "Alias for service worker inspection.", false);
    register_direct_alias(srv, "aida.browser.fingerprint_spoof", "browser_fingerprint_spoof", "Alias for Camoufox fingerprint spoofing.", false);
    register_direct_alias(srv, "aida.browser.scripts", "scripts", "Alias for loaded browser scripts.", false);
    register_direct_alias(srv, "aida.browser.console", "get_console_logs", "Alias for browser console logs.", false);
    register_direct_alias(srv, "aida.browser.search_code", "search_code", "Alias for searching loaded scripts.", true);
    register_dispatch_alias(srv, "aida.browser.env", "Alias group for browser environment checks.", true, {
        {"compare", "compare_env"},
        {"check", "check_environment"}
    });
    register_direct_alias(srv, "aida.browser.signer.verify_offline", "verify_signer_offline", "Alias for offline JS signer verification.", true);
    register_direct_alias(srv, "aida.browser.cookie_sources", "analyze_cookie_sources", "Alias for cookie source attribution.", true);

    register_direct_alias(srv, "aida.proto.find_sendrecv", "net_proto_find_sendrecv", "Alias for locating send/recv handlers.", true);
    register_direct_alias(srv, "aida.proto.trace_serializer", "net_proto_trace_serializer", "Alias for serializer tracing.", false);
    register_direct_alias(srv, "aida.proto.udp_reassemble", "net_udp_session_reassemble", "Alias for UDP session reassembly.", false);
    register_direct_alias(srv, "aida.proto.replay_mutate", "net_replay_mutate", "Alias for protocol replay and mutation.", false);
    register_direct_alias(srv, "aida.proto.protobuf", "network_protobuf_decode", "Alias for protobuf and gRPC decoding.", true);
    register_direct_alias(srv, "aida.proto.decode", "network_protobuf_decode", "Alias for protocol decode operations.", true);
    register_direct_alias(srv, "aida.proto.game_detect", "gameproto_detect", "Alias for game protocol detection.", false);
    register_direct_alias(srv, "aida.proto.game_enet_decode", "gameproto_enet_decode", "Alias for ENet packet decoding.", true);
    register_direct_alias(srv, "aida.proto.game_heuristic", "gameproto_decode_heuristic", "Alias for heuristic binary protocol decoding.", true);
    register_direct_alias(srv, "aida.proto.game_replay", "gameproto_replay", "Alias for game protocol replay.", false);
    diag::log_tagged("tool_alias", "register_network_tool_aliases complete");
}

}
