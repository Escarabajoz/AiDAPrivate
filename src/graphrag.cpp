

#include "aida_pro.hpp"
#include "graphrag.hpp"
#include "settings.hpp"
#include "ida_utils.hpp"
#include "analysis_db.hpp"

#include <sstream>
#include <regex>
#include <random>
#include <numeric>
#include <limits>
#include <nalt.hpp>
#include <idp.hpp>
#include <entry.hpp>
#include <strlist.hpp>
#include <lines.hpp>
#include <netnode.hpp>

namespace graphrag
{


static uint64_t now_ms()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
}

static uint64_t stable_hash64(const std::string& s)
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s)
    {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

static nodeidx_t stable_netnode_slot(const std::string& s)
{
    uint64_t h = stable_hash64(s);
    if (sizeof(nodeidx_t) < sizeof(uint64_t))
        h = (h ^ (h >> 32)) & 0x7fffffffull;
    else
        h &= 0x7fffffffffffffffull;
    nodeidx_t slot = static_cast<nodeidx_t>(h);
    if (slot == BADNODE || slot == 0)
        slot = static_cast<nodeidx_t>(1);
    return slot;
}

static nodeidx_t graph_dirty_slot(const std::string& binary_hash)
{
    return stable_netnode_slot(std::string("graph_dirty:") + binary_hash);
}

static void save_graph_dirty_set(const std::string& binary_hash, const std::unordered_set<int>& dirty)
{
    if (binary_hash.empty()) return;
    netnode nn("$ AiDA.graph.dirty", 0, true);
    if (nn == BADNODE) return;
    if (dirty.empty())
    {
        nn.delblob(graph_dirty_slot(binary_hash), 'D');
        return;
    }
    std::vector<int> ids(dirty.begin(), dirty.end());
    std::sort(ids.begin(), ids.end());
    nlohmann::json j;
    j["v"] = 1;
    j["binary_hash"] = binary_hash;
    j["dirty"] = ids;
    auto blob = nlohmann::json::to_msgpack(j);
    if (!blob.empty())
        nn.setblob(blob.data(), blob.size(), graph_dirty_slot(binary_hash), 'D');
}

static std::unordered_set<int> load_graph_dirty_set(const std::string& binary_hash)
{
    std::unordered_set<int> out;
    if (binary_hash.empty()) return out;
    netnode nn("$ AiDA.graph.dirty");
    if (nn == BADNODE) return out;
    qvector<uchar> blob;
    if (nn.getblob(&blob, graph_dirty_slot(binary_hash), 'D') <= 0)
        return out;
    try
    {
        std::vector<uint8_t> data(blob.begin(), blob.end());
        auto j = nlohmann::json::from_msgpack(data);
        if (j.value("binary_hash", std::string()) != binary_hash)
            return out;
        if (j.contains("dirty") && j["dirty"].is_array())
        {
            for (const auto& id : j["dirty"])
                if (id.is_number_integer()
                    && id.get<nlohmann::json::number_integer_t>() >= std::numeric_limits<int>::min()
                    && id.get<nlohmann::json::number_integer_t>() <= std::numeric_limits<int>::max())
                    out.insert(id.get<int>());
        }
    }
    catch (...) { out.clear(); }
    return out;
}

static void clear_graph_dirty_set(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;
    netnode nn("$ AiDA.graph.dirty");
    if (nn == BADNODE) return;
    nn.delblob(graph_dirty_slot(binary_hash), 'D');
}

static bool icontains(const std::string& haystack, const std::string& needle)
{
    if (needle.empty()) return true;
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); }
    );
    return it != haystack.end();
}

static bool has_any(const std::vector<std::string>& vec, const std::set<std::string>& targets)
{
    for (auto& s : vec)
        if (targets.count(s)) return true;
    return false;
}

static bool rva_from_ea(ea_t addr, uint64_t& rva)
{
    if (addr == BADADDR)
        return false;
    const ea_t base = static_cast<ea_t>(get_imagebase());
    if (base == BADADDR || base == 0 || addr < base)
        return false;
    rva = static_cast<uint64_t>(addr - base);
    return true;
}

static GraphStore::addr_key_t make_addr_key(const std::string& module_key, node_type_t type, ea_t addr, bool prefer_rva, uint64_t supplied_rva)
{
    GraphStore::addr_key_t key;
    key.module_id = module_key;
    key.type = type;
    key.has_rva = prefer_rva;
    key.canonical_addr = prefer_rva ? supplied_rva : static_cast<uint64_t>(addr);
    return key;
}

static void normalize_graph_node_identity(graph_node_t& node)
{
    const bool legacy_only = node.module_id.empty() && !node.binary_hash.empty();
    if (legacy_only)
    {
        node.module_id = node.binary_hash;
        node.legacy_binary_hash_alias = true;
        if (node.identity_source.empty())
            node.identity_source = "legacy_binary_hash_compat";
        if (node.confidence > 0.5)
            node.confidence = 0.5;
    }
    node.binary_hash = node.module_id;
    if (node.identity_source.empty())
        node.identity_source = "module_id_rva";
    uint64_t computed = 0;
    if (!node.has_rva && rva_from_ea(node.address, computed))
    {
        node.rva = computed;
        node.has_rva = true;
    }
    if (node.has_rva)
    {
        std::ostringstream ss;
        ss << node.module_id << "+0x" << std::hex << std::nouppercase << node.rva;
        node.address_key = ss.str();
    }
}

static std::string graph_module_key(const graph_node_t& node)
{
    return !node.module_id.empty() ? node.module_id : node.binary_hash;
}

static void normalize_graph_edge_identity(graph_edge_t& edge,
                                          const std::unordered_map<int, graph_node_t>& nodes)
{
    const bool legacy_only = edge.module_id.empty() && !edge.binary_hash.empty();
    if (legacy_only)
        edge.legacy_binary_hash_alias = true;
    auto sit = nodes.find(edge.source_id);
    auto tit = nodes.find(edge.target_id);
    if (edge.module_id.empty())
    {
        if (sit != nodes.end() && tit != nodes.end() && graph_module_key(sit->second) == graph_module_key(tit->second))
            edge.module_id = graph_module_key(sit->second);
        else if (sit != nodes.end())
            edge.module_id = graph_module_key(sit->second);
        else if (tit != nodes.end())
            edge.module_id = graph_module_key(tit->second);
        else
            edge.module_id = edge.binary_hash;
    }
    edge.binary_hash = edge.module_id;
}

static void normalize_community_identity(community_t& comm)
{
    const bool legacy_only = comm.module_id.empty() && !comm.binary_hash.empty();
    if (legacy_only)
    {
        comm.module_id = comm.binary_hash;
        comm.legacy_binary_hash_alias = true;
    }
    if (comm.module_id.empty())
        comm.module_id = comm.binary_hash;
    comm.binary_hash = comm.module_id;
}


float VectorStore::dot_product(const float* a, const float* b, int n)
{
    float sum = 0.0f;
    int i = 0;
#if defined(_MSC_VER) && defined(__AVX2__)
    for (; i + 8 <= n; i += 8)
    {
        __m256 va = _mm256_loadu_ps(a + i);
        __m256 vb = _mm256_loadu_ps(b + i);
        __m256 vp = _mm256_mul_ps(va, vb);
        __m256 hs = _mm256_hadd_ps(vp, vp);
        hs = _mm256_hadd_ps(hs, hs);
        sum += ((float*)&hs)[0] + ((float*)&hs)[4];
    }
#endif
    for (; i < n; ++i)
        sum += a[i] * b[i];
    return sum;
}

void VectorStore::l2_normalize(std::vector<float>& v)
{
    float norm = 0.0f;
    for (float f : v)
        norm += f * f;
    if (norm < 1e-12f) return;
    norm = 1.0f / std::sqrt(norm);
    for (float& f : v)
        f *= norm;
}

void VectorStore::add(int node_id, std::vector<float> embedding)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    if (embedding.empty()) return;

    if (m_dimensions == 0)
        m_dimensions = static_cast<int>(embedding.size());

    if (static_cast<int>(embedding.size()) != m_dimensions)
        return;

    l2_normalize(embedding);
    m_embeddings[node_id] = std::move(embedding);
}

void VectorStore::remove(int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_embeddings.erase(node_id);
}

bool VectorStore::has(int node_id) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_embeddings.count(node_id) > 0;
}

size_t VectorStore::size() const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    return m_embeddings.size();
}

void VectorStore::clear()
{
    std::lock_guard<std::mutex> lk(m_mtx);
    m_embeddings.clear();
    m_dimensions = 0;
}

std::vector<VectorStore::search_result_t>
VectorStore::search(const std::vector<float>& query, int top_k) const
{
    std::lock_guard<std::mutex> lk(m_mtx);

    if (m_embeddings.empty() || query.empty() || m_dimensions == 0)
        return {};

    std::vector<float> q = query;
    l2_normalize(q);

    if (static_cast<int>(q.size()) != m_dimensions)
        return {};

    std::vector<search_result_t> scored;
    scored.reserve(m_embeddings.size());

    const float* qp = q.data();
    for (auto& [id, emb] : m_embeddings)
    {
        float score = dot_product(qp, emb.data(), m_dimensions);
        scored.push_back({id, score});
    }

    if (static_cast<int>(scored.size()) <= top_k)
    {
        std::sort(scored.begin(), scored.end(),
                  [](auto& a, auto& b) { return a.score > b.score; });
        return scored;
    }

    std::partial_sort(scored.begin(), scored.begin() + top_k, scored.end(),
                      [](auto& a, auto& b) { return a.score > b.score; });
    scored.resize(top_k);
    return scored;
}

std::string VectorStore::get_embeddings_path(const std::string& binary_hash) const
{
    qstring dir = get_user_idadir();
    dir.append("/aida_db");
#ifdef __NT__
    CreateDirectoryA(dir.c_str(), nullptr);
#else
    mkdir(dir.c_str(), 0755);
#endif
    std::string result(dir.c_str());
    result += "/embeddings_";
    result += binary_hash;
    result += ".bin";
    return result;
}

bool VectorStore::save_to_file(const std::string& path) const
{
    std::lock_guard<std::mutex> lk(m_mtx);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return false;

    const char magic[4] = {'A', 'V', 'E', 'C'};
    ofs.write(magic, 4);

    int32_t version = 1;
    ofs.write(reinterpret_cast<const char*>(&version), 4);

    int32_t dims = m_dimensions;
    ofs.write(reinterpret_cast<const char*>(&dims), 4);

    int32_t count = static_cast<int32_t>(m_embeddings.size());
    ofs.write(reinterpret_cast<const char*>(&count), 4);

    for (auto& [id, emb] : m_embeddings)
    {
        int32_t nid = id;
        ofs.write(reinterpret_cast<const char*>(&nid), 4);
        ofs.write(reinterpret_cast<const char*>(emb.data()),
                  static_cast<std::streamsize>(emb.size() * sizeof(float)));
    }

    return ofs.good();
}

bool VectorStore::load_from_file(const std::string& path)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return false;

    char magic[4];
    ifs.read(magic, 4);
    if (magic[0] != 'A' || magic[1] != 'V' || magic[2] != 'E' || magic[3] != 'C')
        return false;

    int32_t version;
    ifs.read(reinterpret_cast<char*>(&version), 4);
    if (version != 1) return false;

    int32_t dims;
    ifs.read(reinterpret_cast<char*>(&dims), 4);
    if (dims <= 0 || dims > 16384) return false;

    int32_t count;
    ifs.read(reinterpret_cast<char*>(&count), 4);
    if (count < 0 || count > 1000000) return false;

    m_embeddings.clear();
    m_dimensions = dims;

    for (int32_t i = 0; i < count; ++i)
    {
        int32_t nid;
        ifs.read(reinterpret_cast<char*>(&nid), 4);

        std::vector<float> emb(dims);
        ifs.read(reinterpret_cast<char*>(emb.data()),
                 static_cast<std::streamsize>(dims * sizeof(float)));

        if (!ifs.good()) break;
        m_embeddings[nid] = std::move(emb);
    }

    return true;
}


std::vector<std::string> LocalVectorizer::tokenize(const std::string& text)
{
    std::vector<std::string> tokens;
    tokens.reserve(256);

    std::string current;
    auto flush = [&]()
    {
        if (current.size() >= 2 && current.size() <= 64)
        {
            std::string lower = current;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            tokens.push_back(std::move(lower));
        }
        current.clear();
    };

    for (size_t i = 0; i < text.size(); ++i)
    {
        char c = text[i];

        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
        {
            if (!current.empty() && std::isupper(static_cast<unsigned char>(c))
                && !std::isupper(static_cast<unsigned char>(current.back())))
            {
                flush();
            }
            current += c;
        }
        else
        {
            flush();
        }
    }
    flush();

    size_t n = tokens.size();
    for (size_t i = 0; i + 1 < n; ++i)
        tokens.push_back(tokens[i] + "_" + tokens[i + 1]);

    return tokens;
}

uint32_t LocalVectorizer::hash_token(const std::string& token)
{
    uint32_t h = 0x811c9dc5u;
    for (unsigned char c : token)
    {
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

void LocalVectorizer::build(const std::vector<std::pair<int, std::string>>& documents)
{
    m_idf.assign(DIMENSIONS, 0.0f);
    m_doc_count = static_cast<int>(documents.size());
    if (m_doc_count == 0) { m_built = false; return; }

    std::vector<int> df(DIMENSIONS, 0);

    for (auto& [id, text] : documents)
    {
        auto tokens = tokenize(text);
        std::vector<bool> seen(DIMENSIONS, false);
        for (auto& tok : tokens)
        {
            int bucket = static_cast<int>(hash_token(tok) % static_cast<uint32_t>(DIMENSIONS));
            if (!seen[bucket])
            {
                ++df[bucket];
                seen[bucket] = true;
            }
        }
    }

    for (int i = 0; i < DIMENSIONS; ++i)
    {
        if (df[i] > 0)
            m_idf[i] = std::log(static_cast<float>(m_doc_count + 1) / static_cast<float>(df[i] + 1)) + 1.0f;
        else
            m_idf[i] = std::log(static_cast<float>(m_doc_count + 1)) + 1.0f;
    }

    m_built = true;
}

std::vector<float> LocalVectorizer::vectorize(const std::string& text) const
{
    std::vector<float> vec(DIMENSIONS, 0.0f);
    if (text.empty()) return vec;

    auto tokens = tokenize(text);
    if (tokens.empty()) return vec;

    for (auto& tok : tokens)
    {
        int bucket = static_cast<int>(hash_token(tok) % static_cast<uint32_t>(DIMENSIONS));
        vec[bucket] += 1.0f;
    }

    float max_tf = *std::max_element(vec.begin(), vec.end());
    if (max_tf > 0.0f)
    {
        for (int i = 0; i < DIMENSIONS; ++i)
        {
            if (vec[i] > 0.0f)
                vec[i] = (0.5f + 0.5f * vec[i] / max_tf) * (m_built ? m_idf[i] : 1.0f);
        }
    }

    return vec;
}

std::string LocalVectorizer::get_vectorizer_path(const std::string& binary_hash) const
{
    qstring dir = get_user_idadir();
    dir.append("/aida_db");
#ifdef __NT__
    CreateDirectoryA(dir.c_str(), nullptr);
#else
    mkdir(dir.c_str(), 0755);
#endif
    std::string result(dir.c_str());
    result += "/vectorizer_";
    result += binary_hash;
    result += ".bin";
    return result;
}

bool LocalVectorizer::save_to_file(const std::string& path) const
{
    if (!m_built) return false;
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return false;

    const char magic[4] = {'T', 'F', 'I', 'D'};
    ofs.write(magic, 4);
    int32_t version = 1;
    ofs.write(reinterpret_cast<const char*>(&version), 4);
    int32_t dims = DIMENSIONS;
    ofs.write(reinterpret_cast<const char*>(&dims), 4);
    int32_t doc_count = m_doc_count;
    ofs.write(reinterpret_cast<const char*>(&doc_count), 4);
    ofs.write(reinterpret_cast<const char*>(m_idf.data()),
              static_cast<std::streamsize>(m_idf.size() * sizeof(float)));
    return ofs.good();
}

bool LocalVectorizer::load_from_file(const std::string& path)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return false;

    char magic[4];
    ifs.read(magic, 4);
    if (magic[0] != 'T' || magic[1] != 'F' || magic[2] != 'I' || magic[3] != 'D')
        return false;

    int32_t version;
    ifs.read(reinterpret_cast<char*>(&version), 4);
    if (version != 1) return false;

    int32_t dims;
    ifs.read(reinterpret_cast<char*>(&dims), 4);
    if (dims != DIMENSIONS) return false;

    int32_t doc_count;
    ifs.read(reinterpret_cast<char*>(&doc_count), 4);
    m_doc_count = doc_count;

    m_idf.resize(DIMENSIONS);
    ifs.read(reinterpret_cast<char*>(m_idf.data()),
             static_cast<std::streamsize>(DIMENSIONS * sizeof(float)));

    m_built = ifs.good();
    return m_built;
}


EmbeddingClient::EmbeddingClient()
{
    configure();
}

void EmbeddingClient::configure()
{
    extern settings_t g_settings;

    m_model_name = g_settings.embedding_model_name;
    m_dimensions = g_settings.embedding_dimensions;
    m_batch_size = g_settings.embedding_batch_size;
    if (m_batch_size < 1) m_batch_size = 1;
    if (m_batch_size > 256) m_batch_size = 256;

    if (!g_settings.embedding_api_url.empty())
        m_api_host = g_settings.embedding_api_url;
    else if (!g_settings.openai_base_url.empty())
        m_api_host = g_settings.openai_base_url;
    else if (g_settings.api_provider == "openai" || g_settings.api_provider == "OpenAI")
        m_api_host = "https://api.openai.com";

    if (!g_settings.embedding_api_key.empty())
        m_api_key = g_settings.embedding_api_key;
    else if (!g_settings.openai_api_key.empty())
        m_api_key = g_settings.openai_api_key;
}

bool EmbeddingClient::is_available() const
{
    return !m_api_host.empty() && (!m_api_key.empty() || m_api_host.find("localhost") != std::string::npos
                                   || m_api_host.find("127.0.0.1") != std::string::npos);
}

std::shared_ptr<httplib::Client> EmbeddingClient::get_client()
{
    std::lock_guard<std::mutex> lk(m_client_mtx);
    if (!m_client)
    {
        m_client = std::make_shared<httplib::Client>(m_api_host.c_str());
        m_client->set_connection_timeout(10);
        m_client->set_read_timeout(120);
        m_client->set_write_timeout(10);
        m_client->set_tcp_nodelay(true);
        m_client->set_keep_alive(true);
        m_client->set_decompress(true);
        m_client->set_compress(true);
    }
    return m_client;
}

std::vector<float> EmbeddingClient::embed_single(const std::string& text)
{
    auto result = embed_batch({text});
    if (result.empty()) return {};
    return result[0];
}

std::vector<std::vector<float>> EmbeddingClient::embed_batch(const std::vector<std::string>& texts)
{
    if (!is_available() || texts.empty())
        return {};

    std::vector<std::vector<float>> all_embeddings;
    all_embeddings.reserve(texts.size());

    for (size_t offset = 0; offset < texts.size(); offset += static_cast<size_t>(m_batch_size))
    {
        size_t batch_end = (std::min)(offset + static_cast<size_t>(m_batch_size), texts.size());

        nlohmann::json input_arr = nlohmann::json::array();
        for (size_t i = offset; i < batch_end; ++i)
        {
            std::string truncated = texts[i];
            if (truncated.size() > 8000)
                truncated.resize(8000);
            input_arr.push_back(truncated);
        }

        nlohmann::json payload;
        payload["model"] = m_model_name;
        payload["input"] = input_arr;
        if (m_dimensions > 0)
            payload["dimensions"] = m_dimensions;

        httplib::Headers headers = {{"Content-Type", "application/json"}};
        if (!m_api_key.empty())
            headers.emplace("Authorization", "Bearer " + m_api_key);

        auto client = get_client();
        std::string body = payload.dump();

        auto res = client->Post(
            "/v1/embeddings",
            body.c_str(), body.length(),
            "application/json");

        if (!res || res->status != 200)
        {
            int status = res ? res->status : 0;
            msg("[AiDA RAG] Embedding API error: status %d\n", status);
            for (size_t i = offset; i < batch_end; ++i)
                all_embeddings.push_back({});
            continue;
        }

        try
        {
            auto jres = nlohmann::json::parse(res->body);
            auto& data = jres["data"];

            std::vector<std::pair<int, std::vector<float>>> indexed;
            for (auto& item : data)
            {
                int idx = item.value("index", 0);
                auto& emb_arr = item["embedding"];
                std::vector<float> emb;
                emb.reserve(emb_arr.size());
                for (auto& v : emb_arr)
                    emb.push_back(v.get<float>());
                indexed.push_back({idx, std::move(emb)});
            }

            std::sort(indexed.begin(), indexed.end(),
                      [](auto& a, auto& b) { return a.first < b.first; });

            for (auto& [idx, emb] : indexed)
                all_embeddings.push_back(std::move(emb));
        }
        catch (const std::exception& e)
        {
            msg("[AiDA RAG] Failed to parse embedding response: %s\n", e.what());
            for (size_t i = offset; i < batch_end; ++i)
                all_embeddings.push_back({});
        }
    }

    return all_embeddings;
}


VectorStore& get_vector_store()
{
    static VectorStore s_store;
    return s_store;
}

LocalVectorizer& get_local_vectorizer()
{
    static LocalVectorizer s_vec;
    return s_vec;
}

std::string build_embedding_text(const graph_node_t& node)
{
    std::string text;
    text.reserve(3000);

    text += node.name;
    text += "\n";

    if (!node.security_flags.empty())
    {
        for (auto& f : node.security_flags)
        {
            text += f;
            text += " ";
        }
        text += "\n";
    }

    if (!node.activity_profile.empty())
    {
        text += node.activity_profile;
        text += "\n";
    }

    if (!node.risk_level.empty() && node.risk_level != "NONE")
    {
        text += "RISK:";
        text += node.risk_level;
        text += "\n";
    }

    if (!node.llm_summary.empty())
    {
        text += node.llm_summary;
        text += "\n";
    }

    if (!node.raw_code.empty())
    {
        std::string code = node.raw_code;
        if (code.size() > 2000)
            code.resize(2000);
        text += code;
    }

    return text;
}

void index_embeddings(const std::string& binary_hash,
                      StructureExtractor::progress_fn on_progress)
{
    auto& store    = GraphStore::instance();
    auto& vs       = get_vector_store();
    auto& lv       = get_local_vectorizer();

    auto nodes = store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    if (nodes.empty()) return;

    int total = static_cast<int>(nodes.size());

    std::vector<std::pair<int, std::string>> doc_texts;
    doc_texts.reserve(nodes.size());

    for (auto* n : nodes)
    {
        std::string emb_text = build_embedding_text(*n);
        doc_texts.push_back({n->id, std::move(emb_text)});
    }

    if (on_progress)
        on_progress(0, total, "Building local TF-IDF vectorizer...");

    lv.build(doc_texts);

    EmbeddingClient emb_client;
    bool use_api = emb_client.is_available();

    if (use_api)
    {
        msg("[AiDA RAG] Using API embeddings from %s (model: %s, dims: %d)\n",
            "configured endpoint",
            g_settings.embedding_model_name.c_str(),
            g_settings.embedding_dimensions);

        std::vector<std::string> batch_texts;
        std::vector<int>         batch_ids;
        batch_texts.reserve(emb_client.dimensions());
        batch_ids.reserve(emb_client.dimensions());

        int processed = 0;
        for (size_t di = 0; di < doc_texts.size(); ++di)
        {
            batch_texts.push_back(doc_texts[di].second);
            batch_ids.push_back(doc_texts[di].first);

            bool is_last = (di + 1 == doc_texts.size());
            if (static_cast<int>(batch_texts.size()) >= g_settings.embedding_batch_size || is_last)
            {
                auto embeddings = emb_client.embed_batch(batch_texts);
                for (size_t i = 0; i < embeddings.size(); ++i)
                {
                    if (!embeddings[i].empty())
                        vs.add(batch_ids[i], std::move(embeddings[i]));
                }

                processed += static_cast<int>(batch_texts.size());
                if (on_progress)
                    on_progress(processed, total,
                                "Embedding (API): " + std::to_string(processed) + "/" + std::to_string(total));

                batch_texts.clear();
                batch_ids.clear();
            }
        }

        msg("[AiDA RAG] API embeddings indexed: %zu vectors, %d dimensions\n",
            vs.size(), vs.dimensions());
    }
    else
    {
        msg("[AiDA RAG] No embedding API configured; using local TF-IDF vectorizer (%d dims)\n",
            LocalVectorizer::DIMENSIONS);

        int processed = 0;
        for (auto& [id, text] : doc_texts)
        {
            auto vec = lv.vectorize(text);
            vs.add(id, std::move(vec));
            ++processed;

            if (on_progress && (processed % 500 == 0 || processed == total))
                on_progress(processed, total,
                            "Vectorizing (local): " + std::to_string(processed) + "/" + std::to_string(total));
        }

        msg("[AiDA RAG] Local TF-IDF vectors: %zu vectors, %d dimensions\n",
            vs.size(), LocalVectorizer::DIMENSIONS);
    }
}

void save_vectors(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;

    auto& vs = get_vector_store();
    auto& lv = get_local_vectorizer();

    std::string emb_path = vs.get_embeddings_path(binary_hash);
    bool saved_vectors = false;
    if (vs.save_to_file(emb_path))
    {
        saved_vectors = true;
        msg("[AiDA RAG] Saved %zu embeddings to %s\n", vs.size(), emb_path.c_str());
    }

    if (lv.is_built())
    {
        std::string vec_path = lv.get_vectorizer_path(binary_hash);
        saved_vectors = lv.save_to_file(vec_path) || saved_vectors;
    }
    if (saved_vectors)
        aida_db::AnalysisDB::instance().mark_binary_capabilities(
            binary_hash,
            GraphStore::instance().get_stats(binary_hash).nodes > 0,
            true);
}

void load_vectors(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;

    auto& vs = get_vector_store();
    auto& lv = get_local_vectorizer();

    std::string emb_path = vs.get_embeddings_path(binary_hash);
    if (vs.load_from_file(emb_path))
        msg("[AiDA RAG] Loaded %zu embeddings (%d dims)\n", vs.size(), vs.dimensions());

    std::string vec_path = lv.get_vectorizer_path(binary_hash);
    lv.load_from_file(vec_path);
}


static const std::vector<std::string> NETWORK_API_PATTERNS = {
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "sendto", "recvfrom", "sendmsg", "recvmsg",
    "WSASocket", "WSAConnect", "WSASend", "WSARecv", "WSASendTo", "WSARecvFrom",
    "WSAAccept", "WSAStartup", "WSACleanup",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
    "InternetOpen", "InternetConnect", "InternetReadFile", "InternetWriteFile",
    "HttpOpenRequest", "HttpSendRequest", "HttpQueryInfo",
    "getaddrinfo", "gethostbyname", "gethostbyaddr", "getnameinfo", "gethostname",
    "SSL_read", "SSL_write", "SSL_connect", "SSL_accept",
    "curl_easy_perform", "curl_easy_send", "curl_easy_recv",
    "select", "poll", "epoll", "shutdown", "closesocket",
};

static const std::vector<std::string> FILE_IO_API_PATTERNS = {
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fgetc", "fputc",
    "fprintf", "fscanf", "fseek", "ftell", "fflush", "freopen",
    "open", "close", "read", "write", "lseek", "stat", "fstat",
    "CreateFile", "ReadFile", "WriteFile", "CloseHandle", "DeleteFile",
    "CopyFile", "MoveFile", "FindFirstFile", "FindNextFile",
    "CreateDirectory", "RemoveDirectory", "GetTempPath", "GetTempFileName",
    "MapViewOfFile", "UnmapViewOfFile", "CreateFileMapping",
    "NtReadFile", "NtWriteFile", "NtCreateFile", "ZwReadFile", "ZwWriteFile",
};

static const std::vector<std::string> CRYPTO_API_PATTERNS = {
    "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
    "CryptEncrypt", "CryptDecrypt", "BCryptOpenAlgorithmProvider",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptCreateHash", "BCryptHashData",
    "MD5Init", "MD5Update", "MD5Final", "SHA1Init", "SHA1Update",
    "EVP_EncryptInit", "EVP_DecryptInit", "EVP_DigestInit",
    "AES_encrypt", "AES_decrypt", "RSA_public_encrypt", "RSA_private_decrypt",
    "base64_encode", "base64_decode",
};

static const std::vector<std::string> PROCESS_API_PATTERNS = {
    "CreateProcess", "CreateProcessA", "CreateProcessW",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "TerminateProcess", "ExitProcess", "ExitThread",
    "OpenProcess", "OpenThread", "NtOpenProcess",
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory", "NtWriteVirtualMemory",
    "ShellExecute", "ShellExecuteW", "WinExec", "system",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "NtMapViewOfSection", "LdrLoadDll",
};


static const std::map<std::string, std::string> DANGEROUS_FUNCTIONS = {
    {"strcpy", "BUFFER_OVERFLOW_RISK"}, {"strcat", "BUFFER_OVERFLOW_RISK"},
    {"sprintf", "FORMAT_STRING_RISK"}, {"vsprintf", "FORMAT_STRING_RISK"},
    {"gets", "BUFFER_OVERFLOW_RISK"}, {"scanf", "BUFFER_OVERFLOW_RISK"},
    {"wcscpy", "BUFFER_OVERFLOW_RISK"}, {"wcscat", "BUFFER_OVERFLOW_RISK"},
    {"lstrcpy", "BUFFER_OVERFLOW_RISK"}, {"lstrcpyA", "BUFFER_OVERFLOW_RISK"},
    {"lstrcpyW", "BUFFER_OVERFLOW_RISK"}, {"lstrcat", "BUFFER_OVERFLOW_RISK"},
    {"printf", "FORMAT_STRING_RISK"}, {"fprintf", "FORMAT_STRING_RISK"},
    {"wprintf", "FORMAT_STRING_RISK"}, {"fwprintf", "FORMAT_STRING_RISK"},
    {"system", "COMMAND_INJECTION_RISK"}, {"popen", "COMMAND_INJECTION_RISK"},
    {"_popen", "COMMAND_INJECTION_RISK"}, {"WinExec", "COMMAND_INJECTION_RISK"},
    {"CreateProcess", "COMMAND_INJECTION_RISK"}, {"CreateProcessA", "COMMAND_INJECTION_RISK"},
    {"CreateProcessW", "COMMAND_INJECTION_RISK"},
    {"ShellExecute", "COMMAND_INJECTION_RISK"}, {"ShellExecuteW", "COMMAND_INJECTION_RISK"},
    {"mysql_query", "SQL_INJECTION_RISK"}, {"sqlite3_exec", "SQL_INJECTION_RISK"},
    {"PQexec", "SQL_INJECTION_RISK"},
    {"memcpy", "BUFFER_OVERFLOW_RISK"}, {"memmove", "BUFFER_OVERFLOW_RISK"},
    {"RtlCopyMemory", "BUFFER_OVERFLOW_RISK"},
};

SecurityFeatureExtractor::features_t
SecurityFeatureExtractor::extract_from_code(const std::string& func_name, const std::string& code) const
{
    features_t f;
    if (code.empty() && func_name.empty()) return f;

    std::string combined = func_name + "\n" + code;


    for (auto& api : NETWORK_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.network_apis.insert(api);

    for (auto& api : FILE_IO_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.file_io_apis.insert(api);

    for (auto& api : CRYPTO_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.crypto_apis.insert(api);

    for (auto& api : PROCESS_API_PATTERNS)
        if (combined.find(api) != std::string::npos)
            f.process_apis.insert(api);


    for (auto& [name, vuln] : DANGEROUS_FUNCTIONS)
        if (combined.find(name) != std::string::npos)
            f.dangerous_functions[name] = vuln;


    static const std::regex ip_re(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), ip_re); it != std::sregex_iterator{}; ++it)
    {
        std::string ip = (*it)[1].str();
        if (ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "255.255.255.255")
            f.ip_addresses.insert(ip);
    }


    static const std::regex url_re(R"(https?://[^\s\"'<>]+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), url_re); it != std::sregex_iterator{}; ++it)
        f.urls.insert((*it)[0].str());


    static const std::regex win_path_re(R"([A-Za-z]:\\[^\s\"']+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), win_path_re); it != std::sregex_iterator{}; ++it)
        f.file_paths.insert((*it)[0].str());


    static const std::regex unix_path_re(R"(/(?:etc|var|tmp|usr|home|root|opt)/[^\s\"']+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), unix_path_re); it != std::sregex_iterator{}; ++it)
        f.file_paths.insert((*it)[0].str());


    static const std::regex reg_re(R"(HK(?:EY_[A-Z_]+|LM|CU|CR|CC|U)\\[^\s\"']+)");
    for (std::sregex_iterator it(combined.begin(), combined.end(), reg_re); it != std::sregex_iterator{}; ++it)
        f.registry_keys.insert((*it)[0].str());

    return f;
}

std::vector<std::string> SecurityFeatureExtractor::features_t::generate_security_flags() const
{
    std::vector<std::string> flags;

    if (!network_apis.empty())
    {
        flags.push_back("NETWORK_CAPABLE");
        bool has_listen = false, has_connect = false, has_send = false, has_recv = false;
        for (auto& a : network_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("listen") != std::string::npos || low.find("accept") != std::string::npos)
                has_listen = true;
            if (low.find("connect") != std::string::npos)
                has_connect = true;
            if (low.find("send") != std::string::npos || low.find("write") != std::string::npos)
                has_send = true;
            if (low.find("recv") != std::string::npos || low.find("read") != std::string::npos)
                has_recv = true;
        }
        if (has_listen) flags.push_back("ACCEPTS_CONNECTIONS");
        if (has_connect) flags.push_back("INITIATES_CONNECTIONS");
        if (has_send) flags.push_back("SENDS_DATA");
        if (has_recv) flags.push_back("RECEIVES_DATA");

        for (auto& a : network_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("getaddrinfo") != std::string::npos ||
                low.find("gethostbyname") != std::string::npos ||
                low.find("gethostname") != std::string::npos)
            {
                flags.push_back("PERFORMS_DNS_LOOKUP");
                break;
            }
        }
    }

    if (!file_io_apis.empty())
    {
        bool has_read = false, has_write = false;
        for (auto& a : file_io_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("read") != std::string::npos || low.find("fread") != std::string::npos ||
                low.find("fgets") != std::string::npos || low.find("mapview") != std::string::npos)
                has_read = true;
            if (low.find("write") != std::string::npos || low.find("fwrite") != std::string::npos ||
                low.find("fputs") != std::string::npos || low.find("copy") != std::string::npos)
                has_write = true;
        }
        if (has_read) flags.push_back("READS_FILES");
        if (has_write) flags.push_back("WRITES_FILES");
    }

    if (!crypto_apis.empty())
        flags.push_back("USES_CRYPTO");

    if (!process_apis.empty())
    {
        flags.push_back("MANIPULATES_PROCESSES");
        for (auto& a : process_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("writeprocessmemory") != std::string::npos ||
                low.find("createremotethread") != std::string::npos ||
                low.find("ntmapviewofsection") != std::string::npos)
            {
                flags.push_back("PROCESS_INJECTION_CAPABLE");
                break;
            }
        }
    }

    for (auto& [name, vuln_type] : dangerous_functions)
    {
        if (std::find(flags.begin(), flags.end(), vuln_type) == flags.end())
            flags.push_back(vuln_type);
    }
    if (!dangerous_functions.empty())
        flags.push_back("CALLS_DANGEROUS_FUNCTIONS");

    if (!ip_addresses.empty()) flags.push_back("HAS_IP_ADDRESSES");
    if (!urls.empty()) flags.push_back("HAS_URLS");
    if (!domains.empty()) flags.push_back("HAS_DOMAINS");
    if (!registry_keys.empty()) flags.push_back("ACCESSES_REGISTRY");

    for (auto& p : file_paths)
    {
        std::string low = p;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("\\system32") != std::string::npos ||
            low.find("\\windows") != std::string::npos ||
            low.find("/etc/") != std::string::npos ||
            low.find("/root/") != std::string::npos)
        {
            flags.push_back("ACCESSES_SYSTEM_PATHS");
            break;
        }
    }

    return flags;
}

std::string SecurityFeatureExtractor::features_t::get_activity_profile() const
{
    std::vector<std::string> profiles;

    if (!network_apis.empty())
    {
        bool has_server = false, has_client = false;
        for (auto& a : network_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("listen") != std::string::npos || low.find("accept") != std::string::npos)
                has_server = true;
            if (low.find("connect") != std::string::npos || low.find("http") != std::string::npos ||
                low.find("internet") != std::string::npos || low.find("winhttp") != std::string::npos)
                has_client = true;
        }
        if (has_server) profiles.push_back("NETWORK_SERVER");
        if (has_client) profiles.push_back("NETWORK_CLIENT");
        if (!has_server && !has_client) profiles.push_back("NETWORK_IO");
    }

    if (!file_io_apis.empty())
    {
        bool has_read = false, has_write = false;
        for (auto& a : file_io_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("read") != std::string::npos) has_read = true;
            if (low.find("write") != std::string::npos) has_write = true;
        }
        if (has_read && has_write) profiles.push_back("FILE_RW");
        else if (has_write) profiles.push_back("FILE_WRITER");
        else if (has_read) profiles.push_back("FILE_READER");
    }

    if (!crypto_apis.empty())
    {
        bool enc = false, dec = false, hash = false;
        for (auto& a : crypto_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("encrypt") != std::string::npos) enc = true;
            if (low.find("decrypt") != std::string::npos) dec = true;
            if (low.find("hash") != std::string::npos || low.find("md5") != std::string::npos ||
                low.find("sha") != std::string::npos || low.find("digest") != std::string::npos)
                hash = true;
        }
        if (enc && dec) profiles.push_back("CRYPTO_CIPHER");
        else if (enc) profiles.push_back("CRYPTO_ENCRYPT");
        else if (dec) profiles.push_back("CRYPTO_DECRYPT");
        else if (hash) profiles.push_back("CRYPTO_HASH");
        else profiles.push_back("CRYPTO_USER");
    }

    if (!process_apis.empty())
    {
        bool inject = false;
        for (auto& a : process_apis)
        {
            std::string low = a;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.find("writeprocessmemory") != std::string::npos ||
                low.find("createremotethread") != std::string::npos)
                inject = true;
        }
        profiles.push_back(inject ? "PROCESS_INJECTOR" : "PROCESS_SPAWNER");
    }

    std::string result;
    for (size_t i = 0; i < profiles.size(); ++i)
    {
        if (i > 0) result += ",";
        result += profiles[i];
    }
    return result;
}

std::string SecurityFeatureExtractor::features_t::get_risk_level() const
{
    int score = 0;
    if (!dangerous_functions.empty()) score += 3;
    if (!network_apis.empty()) score += 2;
    if (!process_apis.empty()) score += 2;
    if (!crypto_apis.empty()) score += 1;
    if (!ip_addresses.empty()) score += 1;
    if (!urls.empty()) score += 1;


    for (auto& a : process_apis)
    {
        std::string low = a;
        std::transform(low.begin(), low.end(), low.begin(), ::tolower);
        if (low.find("writeprocessmemory") != std::string::npos ||
            low.find("createremotethread") != std::string::npos)
        {
            score += 3;
            break;
        }
    }

    if (score >= 7) return "CRITICAL";
    if (score >= 5) return "HIGH";
    if (score >= 3) return "MEDIUM";
    if (score >= 1) return "LOW";
    return "NONE";
}

bool SecurityFeatureExtractor::features_t::is_empty() const
{
    return network_apis.empty() && file_io_apis.empty() && crypto_apis.empty() &&
           process_apis.empty() && dangerous_functions.empty() && ip_addresses.empty() &&
           urls.empty() && file_paths.empty() && domains.empty() && registry_keys.empty();
}


// ---- Slice H3: inverted-index helpers ---------------------------------------
void GraphStore::vec_insert_unique(std::vector<int>& v, int id)
{
    auto it = std::lower_bound(v.begin(), v.end(), id);
    if (it == v.end() || *it != id) v.insert(it, id);
}

void GraphStore::vec_remove(std::vector<int>& v, int id)
{
    auto it = std::lower_bound(v.begin(), v.end(), id);
    if (it != v.end() && *it == id) v.erase(it);
}

void GraphStore::index_add_node_locked(const graph_node_t& node)
{
    for (const auto& f : node.security_flags)
        vec_insert_unique(m_flag_index[f], node.id);
    auto add_apis = [&](const std::vector<std::string>& apis) {
        for (const auto& a : apis) vec_insert_unique(m_api_index[a], node.id);
    };
    add_apis(node.network_apis);
    add_apis(node.file_io_apis);
    add_apis(node.crypto_apis);
    add_apis(node.process_apis);
}

void GraphStore::index_remove_node_locked(int node_id)
{
    auto nit = m_nodes.find(node_id);
    if (nit == m_nodes.end()) return;
    const graph_node_t& node = nit->second;
    for (const auto& f : node.security_flags)
    {
        auto fit = m_flag_index.find(f);
        if (fit != m_flag_index.end()) vec_remove(fit->second, node_id);
    }
    auto rm_apis = [&](const std::vector<std::string>& apis) {
        for (const auto& a : apis)
        {
            auto ait = m_api_index.find(a);
            if (ait != m_api_index.end()) vec_remove(ait->second, node_id);
        }
    };
    rm_apis(node.network_apis);
    rm_apis(node.file_io_apis);
    rm_apis(node.crypto_apis);
    rm_apis(node.process_apis);
}

graph_node_t* GraphStore::upsert_node(graph_node_t node)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    normalize_graph_node_identity(node);

    const std::string node_key = graph_module_key(node);
    addr_key_t key = make_addr_key(node_key, node.node_type, node.address, node.has_rva, node.rva);
    auto it = m_addr_index.find(key);
    if (it == m_addr_index.end() && node.has_rva)
    {
        addr_key_t legacy = make_addr_key(node_key, node.node_type, node.address, false, 0);
        it = m_addr_index.find(legacy);
    }

    uint64_t ts = now_ms();

    if (it != m_addr_index.end())
    {
        auto& existing = m_nodes[it->second];
        // H3: O(diff) index update — drop old node from indices,
        // then re-add after we mutate the in-place record below.
        index_remove_node_locked(existing.id);

        existing.name = node.name;
        if (!node.raw_code.empty()) existing.raw_code = node.raw_code;
        existing.security_flags = node.security_flags;
        existing.network_apis = node.network_apis;
        existing.file_io_apis = node.file_io_apis;
        existing.crypto_apis = node.crypto_apis;
        existing.process_apis = node.process_apis;
        existing.ip_addresses = node.ip_addresses;
        existing.urls = node.urls;
        existing.file_paths = node.file_paths;
        existing.domains = node.domains;
        existing.registry_keys = node.registry_keys;
        existing.risk_level = node.risk_level;
        existing.activity_profile = node.activity_profile;
        if (!node.llm_summary.empty()) existing.llm_summary = node.llm_summary;
        if (node.confidence > 0) existing.confidence = node.confidence;
        existing.is_stale = node.is_stale;
        existing.updated_at = ts;
        normalize_graph_node_identity(existing);
        const std::string existing_key = graph_module_key(existing);
        m_addr_index[make_addr_key(existing_key, existing.node_type, existing.address, existing.has_rva, existing.rva)] = existing.id;
        index_add_node_locked(existing);
        m_dirty_nodes[existing_key].insert(existing.id);
        if (m_nodes.size() > 10000)
            save_graph_dirty_set(existing_key, m_dirty_nodes[existing_key]);
        return &existing;
    }

    node.id = m_next_node_id++;
    node.created_at = ts;
    node.updated_at = ts;
    int id = node.id;
    const std::string bh = graph_module_key(node);
    m_nodes[id] = std::move(node);
    m_addr_index[key] = id;
    index_add_node_locked(m_nodes[id]);
    m_dirty_nodes[bh].insert(id);
    if (m_nodes.size() > 10000)
        save_graph_dirty_set(bh, m_dirty_nodes[bh]);
    return &m_nodes[id];
}

graph_node_t* GraphStore::get_node(int id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_nodes.find(id);
    return it != m_nodes.end() ? &it->second : nullptr;
}

graph_node_t* GraphStore::get_node_by_address(const std::string& binary_hash, node_type_t type, ea_t addr)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    uint64_t rva = 0;
    const bool has_rva = rva_from_ea(addr, rva);
    addr_key_t key = make_addr_key(binary_hash, type, addr, has_rva, rva);
    auto it = m_addr_index.find(key);
    if (it == m_addr_index.end() && has_rva)
        it = m_addr_index.find(make_addr_key(binary_hash, type, addr, false, 0));
    if (it == m_addr_index.end())
        return nullptr;
    auto nit = m_nodes.find(it->second);
    return nit != m_nodes.end() ? &nit->second : nullptr;
}

std::vector<graph_node_t*> GraphStore::get_nodes_by_type(const std::string& binary_hash, node_type_t type)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash && node.node_type == type)
            result.push_back(&node);
    return result;
}

std::vector<graph_node_t*> GraphStore::get_all_nodes(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash)
            result.push_back(&node);
    return result;
}

graph_edge_t* GraphStore::add_edge(graph_edge_t edge)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    normalize_graph_edge_identity(edge, m_nodes);

    for (auto& eid : m_edges_from[edge.source_id])
    {
        auto& e = m_edges[eid];
        if (e.target_id == edge.target_id && e.edge_type == edge.edge_type)
        {
            if (e.module_id.empty() && !edge.module_id.empty())
            {
                e.module_id = edge.module_id;
                e.binary_hash = edge.module_id;
                auto& vec = m_edges_by_binary[e.module_id];
                if (std::find(vec.begin(), vec.end(), eid) == vec.end())
                    vec.push_back(eid);
            }
            return &e;
        }
    }

    edge.id = m_next_edge_id++;
    int id = edge.id;
    m_edges[id] = std::move(edge);
    m_edges_from[m_edges[id].source_id].push_back(id);
    m_edges_to[m_edges[id].target_id].push_back(id);
    if (!m_edges[id].module_id.empty())
        m_edges_by_binary[m_edges[id].module_id].push_back(id);
    return &m_edges[id];
}

bool GraphStore::has_edge(int source_id, int target_id, edge_type_t type) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_edges_from.find(source_id);
    if (it == m_edges_from.end()) return false;
    for (int eid : it->second)
    {
        auto eit = m_edges.find(eid);
        if (eit != m_edges.end() && eit->second.target_id == target_id && eit->second.edge_type == type)
            return true;
    }
    return false;
}

std::vector<graph_edge_t*> GraphStore::get_edges_from(int source_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_edge_t*> result;
    auto it = m_edges_from.find(source_id);
    if (it != m_edges_from.end())
        for (int eid : it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    return result;
}

std::vector<graph_edge_t*> GraphStore::get_edges_to(int target_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_edge_t*> result;
    auto it = m_edges_to.find(target_id);
    if (it != m_edges_to.end())
        for (int eid : it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    return result;
}

std::vector<graph_edge_t*> GraphStore::get_edges_for_node(int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_edge_t*> result;
    auto from_it = m_edges_from.find(node_id);
    if (from_it != m_edges_from.end())
        for (int eid : from_it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    auto to_it = m_edges_to.find(node_id);
    if (to_it != m_edges_to.end())
        for (int eid : to_it->second)
            if (m_edges.count(eid)) result.push_back(&m_edges[eid]);
    return result;
}

std::vector<graph_edge_t*> GraphStore::get_edges_by_types(const std::string& binary_hash, const std::vector<edge_type_t>& types)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::set<edge_type_t> type_set(types.begin(), types.end());
    std::vector<graph_edge_t*> result;
    for (auto& [id, edge] : m_edges)
        if (edge.binary_hash == binary_hash && type_set.count(edge.edge_type))
            result.push_back(&edge);
    return result;
}

std::vector<graph_node_t*> GraphStore::get_callers(const std::string& binary_hash, int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    auto it = m_edges_to.find(node_id);
    if (it != m_edges_to.end())
    {
        for (int eid : it->second)
        {
            auto eit = m_edges.find(eid);
            if (eit == m_edges.end()) continue;
            if (eit->second.edge_type != edge_type_t::CALLS) continue;
            auto nit = m_nodes.find(eit->second.source_id);
            if (nit != m_nodes.end() && nit->second.binary_hash == binary_hash)
                result.push_back(&nit->second);
        }
    }
    return result;
}

std::vector<graph_node_t*> GraphStore::get_callees(const std::string& binary_hash, int node_id)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;
    auto it = m_edges_from.find(node_id);
    if (it != m_edges_from.end())
    {
        for (int eid : it->second)
        {
            auto eit = m_edges.find(eid);
            if (eit == m_edges.end()) continue;
            if (eit->second.edge_type != edge_type_t::CALLS) continue;
            auto nit = m_nodes.find(eit->second.target_id);
            if (nit != m_nodes.end() && nit->second.binary_hash == binary_hash)
                result.push_back(&nit->second);
        }
    }
    return result;
}

void GraphStore::add_community(community_t comm)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    normalize_community_identity(comm);
    m_communities.push_back(std::move(comm));
}

std::vector<community_t> GraphStore::get_communities(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<community_t> result;
    for (auto& c : m_communities)
        if (c.binary_hash == binary_hash)
            result.push_back(c);
    return result;
}

bool GraphStore::communities_exist(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& c : m_communities)
        if (c.binary_hash == binary_hash) return true;
    return false;
}

int GraphStore::delete_communities(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    int count = 0;
    auto it = m_communities.begin();
    while (it != m_communities.end())
    {
        if (it->binary_hash == binary_hash)
        {
            it = m_communities.erase(it);
            ++count;
        }
        else ++it;
    }

    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash)
            node.community_id = -1;
    return count;
}

std::vector<graph_node_t*> GraphStore::search_nodes(const std::string& binary_hash,
                                                     const std::string& query, int limit)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> result;


    std::vector<std::string> tokens;
    std::istringstream iss(query);
    std::string tok;
    while (iss >> tok)
    {

        if (tok == "OR" || tok == "or") continue;
        std::transform(tok.begin(), tok.end(), tok.begin(), ::tolower);
        tokens.push_back(tok);
    }


    auto match_lower = [&](const std::string& text_lower, const std::string& t) -> bool {
        return text_lower.find(t) != std::string::npos;
    };


    auto match_vec = [&](const std::vector<std::string>& vec, const std::string& t) -> bool {
        for (auto& s : vec)
        {
            std::string sl = s;
            std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
            if (sl.find(t) != std::string::npos) return true;
        }
        return false;
    };

    struct scored_t { graph_node_t* node; int score; };
    std::vector<scored_t> scored;

    for (auto& [id, node] : m_nodes)
    {
        if (node.binary_hash != binary_hash) continue;

        int score = 0;
        std::string name_lower = node.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        std::string summary_lower = node.llm_summary;
        std::transform(summary_lower.begin(), summary_lower.end(), summary_lower.begin(), ::tolower);


        std::string code_lower;
        bool code_lowered = false;

        for (auto& t : tokens)
        {

            if (match_lower(name_lower, t)) score += 5;


            if (match_lower(summary_lower, t)) score += 3;


            if (match_vec(node.security_flags, t)) score += 2;


            if (match_vec(node.urls, t))           score += 4;
            if (match_vec(node.ip_addresses, t))   score += 4;
            if (match_vec(node.file_paths, t))     score += 4;
            if (match_vec(node.domains, t))        score += 4;
            if (match_vec(node.registry_keys, t))  score += 4;


            if (match_vec(node.network_apis, t))   score += 3;
            if (match_vec(node.file_io_apis, t))   score += 3;
            if (match_vec(node.crypto_apis, t))    score += 3;
            if (match_vec(node.process_apis, t))   score += 3;


            if (!node.raw_code.empty())
            {
                if (!code_lowered)
                {
                    code_lower = node.raw_code;
                    std::transform(code_lower.begin(), code_lower.end(), code_lower.begin(), ::tolower);
                    code_lowered = true;
                }
                if (match_lower(code_lower, t)) score += 1;
            }
        }

        if (score > 0) scored.push_back({&node, score});
    }

    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) { return a.score > b.score; });

    int count = 0;
    for (auto& s : scored)
    {
        result.push_back(s.node);
        if (++count >= limit) break;
    }
    return result;
}

GraphStore::graph_stats_t GraphStore::get_stats(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    graph_stats_t stats;
    for (auto& [id, node] : m_nodes)
    {
        if (node.binary_hash != binary_hash) continue;
        ++stats.nodes;
        if (node.is_stale) ++stats.stale;
    }
    for (auto& [id, edge] : m_edges)
        if (edge.binary_hash == binary_hash) ++stats.edges;
    for (auto& c : m_communities)
        if (c.binary_hash == binary_hash) ++stats.communities;
    return stats;
}

void GraphStore::delete_graph(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    std::unordered_set<int> node_ids;
    for (const auto& kv : m_nodes)
        if (kv.second.binary_hash == binary_hash)
            node_ids.insert(kv.first);

    std::unordered_set<int> edge_ids;
    auto ebit = m_edges_by_binary.find(binary_hash);
    if (ebit != m_edges_by_binary.end())
        edge_ids.insert(ebit->second.begin(), ebit->second.end());

    for (int nid : node_ids)
    {
        auto fit = m_edges_from.find(nid);
        if (fit != m_edges_from.end())
            edge_ids.insert(fit->second.begin(), fit->second.end());
        auto tit = m_edges_to.find(nid);
        if (tit != m_edges_to.end())
            edge_ids.insert(tit->second.begin(), tit->second.end());
    }

    for (int eid : edge_ids)
        m_edges.erase(eid);

    if (ebit != m_edges_by_binary.end())
        m_edges_by_binary.erase(ebit);

    auto nit = m_nodes.begin();
    while (nit != m_nodes.end())
    {
        if (nit->second.binary_hash == binary_hash)
        {
            index_remove_node_locked(nit->second.id);
            normalize_graph_node_identity(nit->second);
            addr_key_t key = make_addr_key(binary_hash, nit->second.node_type, nit->second.address, nit->second.has_rva, nit->second.rva);
            m_addr_index.erase(key);
            if (nit->second.has_rva)
                m_addr_index.erase(make_addr_key(binary_hash, nit->second.node_type, nit->second.address, false, 0));
            nit = m_nodes.erase(nit);
        }
        else ++nit;
    }

    auto cit = m_communities.begin();
    while (cit != m_communities.end())
    {
        if (cit->binary_hash == binary_hash)
            cit = m_communities.erase(cit);
        else ++cit;
    }
    m_dirty_nodes.erase(binary_hash);
    clear_graph_dirty_set(binary_hash);

    m_edges_from.clear();
    m_edges_to.clear();
    for (auto bit = m_edges_by_binary.begin(); bit != m_edges_by_binary.end(); )
    {
        auto& ids = bit->second;
        ids.erase(std::remove_if(ids.begin(), ids.end(), [&](int eid) {
            return m_edges.find(eid) == m_edges.end();
        }), ids.end());
        if (ids.empty())
        {
            bit = m_edges_by_binary.erase(bit);
            continue;
        }
        for (int eid : ids)
        {
            auto eit = m_edges.find(eid);
            if (eit == m_edges.end()) continue;
            m_edges_from[eit->second.source_id].push_back(eid);
            m_edges_to[eit->second.target_id].push_back(eid);
        }
        ++bit;
    }
}

std::string GraphStore::get_graph_path(const std::string& binary_hash) const
{
    qstring dir = get_user_idadir();
    dir.append("/aida_db");
#ifdef __NT__
    CreateDirectoryA(dir.c_str(), nullptr);
#else
    mkdir(dir.c_str(), 0755);
#endif
    std::string result(dir.c_str());
    result += "/graph_";
    result += binary_hash;
    result += ".json";
    return result;
}

bool GraphStore::save_to_file(const std::string& path)
{
    return save_to_file(path, std::string());
}

bool GraphStore::save_to_file(const std::string& path, const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    nlohmann::json j;
    j["version"] = 1;
    j["address_model"] = "module_id+rva";
    j["legacy_binary_hash_compat"] = true;
    j["graph_key"] = binary_hash.empty() ? std::string("all_modules") : binary_hash;
    j["next_node_id"] = m_next_node_id;
    j["next_edge_id"] = m_next_edge_id;

    j["nodes"] = nlohmann::json::array();
    for (auto& [id, node] : m_nodes)
        if (binary_hash.empty() || node.binary_hash == binary_hash)
            j["nodes"].push_back(node);

    j["edges"] = nlohmann::json::array();
    for (auto& [id, edge] : m_edges)
        if (binary_hash.empty() || edge.binary_hash == binary_hash)
            j["edges"].push_back(edge);

    j["communities"] = nlohmann::json::array();
    for (const auto& c : m_communities)
        if (binary_hash.empty() || c.binary_hash == binary_hash)
            j["communities"].push_back(c);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return false;
    ofs << j.dump(2);
    if (binary_hash.empty())
    {
        for (const auto& kv : m_dirty_nodes)
            clear_graph_dirty_set(kv.first);
        m_dirty_nodes.clear();
    }
    else
    {
        m_dirty_nodes.erase(binary_hash);
        clear_graph_dirty_set(binary_hash);
    }
    return true;
}

int GraphStore::save_incremental(const std::string& binary_hash, const std::string& path)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    auto dit = m_dirty_nodes.find(binary_hash);
    if (dit == m_dirty_nodes.end() || dit->second.empty())
    {
        auto recovered = load_graph_dirty_set(binary_hash);
        if (!recovered.empty())
        {
            auto& dst = m_dirty_nodes[binary_hash];
            dst.insert(recovered.begin(), recovered.end());
            dit = m_dirty_nodes.find(binary_hash);
        }
    }
    if (dit == m_dirty_nodes.end() || dit->second.empty()) return 0;

    nlohmann::json j;
    j["version"] = 1;
    j["address_model"] = "module_id+rva";
    j["legacy_binary_hash_compat"] = true;
    j["graph_key"] = binary_hash;
    j["next_node_id"] = m_next_node_id;
    j["next_edge_id"] = m_next_edge_id;
    j["nodes"] = nlohmann::json::array();
    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash)
            j["nodes"].push_back(node);
    j["edges"] = nlohmann::json::array();
    for (auto& [id, edge] : m_edges)
        if (edge.binary_hash == binary_hash)
            j["edges"].push_back(edge);
    j["communities"] = nlohmann::json::array();
    for (const auto& c : m_communities)
        if (c.binary_hash == binary_hash)
            j["communities"].push_back(c);

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return 0;
    ofs << j.dump(2);

    int n_flushed = static_cast<int>(dit->second.size());

    m_dirty_nodes.erase(dit);
    clear_graph_dirty_set(binary_hash);
    return n_flushed;
}

int GraphStore::dirty_count(const std::string& binary_hash) const
{
    std::lock_guard<std::mutex> lk(m_mtx);
    auto it = m_dirty_nodes.find(binary_hash);
    return it == m_dirty_nodes.end() ? 0 : static_cast<int>(it->second.size());
}

void GraphStore::rebuild_inverted_indices(const std::string& binary_hash)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    // Wipe entries that belong to this binary, then re-add.
    auto drop_from = [&](std::unordered_map<std::string, std::vector<int>>& idx) {
        for (auto& [k, v] : idx)
        {
            v.erase(std::remove_if(v.begin(), v.end(), [&](int id) {
                auto nit = m_nodes.find(id);
                return nit == m_nodes.end() || nit->second.binary_hash == binary_hash;
            }), v.end());
        }
    };
    drop_from(m_flag_index);
    drop_from(m_api_index);
    for (auto& [id, node] : m_nodes)
        if (node.binary_hash == binary_hash) index_add_node_locked(node);
}

std::vector<graph_node_t*> GraphStore::filter_nodes(const std::string& binary_hash,
                                                    const nlohmann::json& criteria)
{
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<graph_node_t*> out;
    if (!criteria.is_object()) return out;

    auto str_list = [](const nlohmann::json& j, const char* key,
                       std::vector<std::string>& out) {
        if (!j.contains(key) || !j[key].is_array()) return;
        for (auto& v : j[key])
            if (v.is_string()) out.push_back(v.get<std::string>());
    };

    std::vector<std::string> all_flags, any_flags, all_apis, any_apis, risk_levels;
    str_list(criteria, "all_flags", all_flags);
    str_list(criteria, "any_flags", any_flags);
    str_list(criteria, "all_apis",  all_apis);
    str_list(criteria, "any_apis",  any_apis);
    str_list(criteria, "risk_levels", risk_levels);

    auto intersect_apply = [&](std::vector<int>& acc,
                               const std::unordered_map<std::string, std::vector<int>>& idx,
                               const std::string& key, bool& seeded) {
        auto it = idx.find(key);
        if (it == idx.end())
        {
            // missing flag/api => intersection becomes empty.
            acc.clear();
            seeded = true;
            return;
        }
        if (!seeded) { acc = it->second; seeded = true; return; }
        std::vector<int> next;
        std::set_intersection(acc.begin(), acc.end(),
                              it->second.begin(), it->second.end(),
                              std::back_inserter(next));
        acc = std::move(next);
    };

    // Start with all_flags intersection.
    std::vector<int> candidates;
    bool seeded = false;
    for (const auto& f : all_flags) intersect_apply(candidates, m_flag_index, f, seeded);
    for (const auto& a : all_apis)  intersect_apply(candidates, m_api_index,  a, seeded);

    if (!seeded)
    {
        // No all-* constraints; iterate full node list for this binary.
        candidates.reserve(m_nodes.size());
        for (auto& [id, node] : m_nodes)
            if (node.binary_hash == binary_hash) candidates.push_back(id);
        std::sort(candidates.begin(), candidates.end());
    }

    // Apply any_flags / any_apis (OR of sets, intersected with candidates).
    auto any_filter = [&](const std::vector<std::string>& items,
                          const std::unordered_map<std::string, std::vector<int>>& idx) {
        if (items.empty()) return;
        std::vector<int> union_acc;
        for (const auto& k : items)
        {
            auto it = idx.find(k);
            if (it == idx.end()) continue;
            std::vector<int> merged;
            std::set_union(union_acc.begin(), union_acc.end(),
                           it->second.begin(), it->second.end(),
                           std::back_inserter(merged));
            union_acc = std::move(merged);
        }
        std::vector<int> next;
        std::set_intersection(candidates.begin(), candidates.end(),
                              union_acc.begin(), union_acc.end(),
                              std::back_inserter(next));
        candidates = std::move(next);
    };
    any_filter(any_flags, m_flag_index);
    any_filter(any_apis,  m_api_index);

    // Finally project to nodes and apply binary_hash + risk_levels filter.
    out.reserve(candidates.size());
    for (int id : candidates)
    {
        auto nit = m_nodes.find(id);
        if (nit == m_nodes.end()) continue;
        auto& n = nit->second;
        if (n.binary_hash != binary_hash) continue;
        if (!risk_levels.empty())
        {
            bool ok = false;
            for (const auto& r : risk_levels) if (n.risk_level == r) { ok = true; break; }
            if (!ok) continue;
        }
        out.push_back(&n);
    }
    return out;
}

bool GraphStore::load_from_file(const std::string& path)
{
    std::lock_guard<std::mutex> lk(m_mtx);

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return false;

    try
    {
        nlohmann::json j = nlohmann::json::parse(ifs);

        m_nodes.clear();
        m_edges.clear();
        m_communities.clear();
        m_addr_index.clear();
        m_edges_from.clear();
        m_edges_to.clear();
        m_edges_by_binary.clear();
        m_flag_index.clear();
        m_api_index.clear();
        m_dirty_nodes.clear();

        m_next_node_id = j.value("next_node_id", 1);
        m_next_edge_id = j.value("next_edge_id", 1);

        if (j.contains("nodes"))
        {
            for (auto& nj : j["nodes"])
            {
                graph_node_t n = nj.get<graph_node_t>();
                normalize_graph_node_identity(n);
                int id = n.id;
                addr_key_t key = make_addr_key(graph_module_key(n), n.node_type, n.address, n.has_rva, n.rva);
                m_addr_index[key] = id;
                m_nodes[id] = std::move(n);
                index_add_node_locked(m_nodes[id]);
            }
        }

        if (j.contains("edges"))
        {
            for (auto& ej : j["edges"])
            {
                graph_edge_t e = ej.get<graph_edge_t>();
                int id = e.id;
                normalize_graph_edge_identity(e, m_nodes);
                m_edges_from[e.source_id].push_back(id);
                m_edges_to[e.target_id].push_back(id);
                if (!e.module_id.empty())
                    m_edges_by_binary[e.module_id].push_back(id);
                m_edges[id] = std::move(e);
            }
        }

        if (j.contains("communities"))
        {
            m_communities = j["communities"].get<std::vector<community_t>>();
            for (auto& c : m_communities)
                normalize_community_identity(c);
        }

        std::unordered_set<std::string> hashes;
        for (const auto& kv : m_nodes)
            if (!graph_module_key(kv.second).empty())
                hashes.insert(graph_module_key(kv.second));
        for (const auto& h : hashes)
        {
            auto recovered = load_graph_dirty_set(h);
            if (!recovered.empty())
                m_dirty_nodes[h].insert(recovered.begin(), recovered.end());
        }

        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}


StructureExtractor::StructureExtractor(GraphStore& store) : m_store(store) {}

std::string StructureExtractor::get_raw_code(ea_t func_ea)
{
    func_t* pfn = get_func(func_ea);
    if (pfn != nullptr
        && ida_utils::is_safely_decompilable(pfn)
        && !((pfn->flags & FUNC_LIB) && pfn->size() == 0)
        && init_hexrays_plugin())
    {
        try
        {
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(pfn, &hf, DECOMP_NO_WAIT | DECOMP_WARNINGS);
            if (cfunc != nullptr)
            {
                const strvec_t& sv = cfunc->get_pseudocode();
                std::string code;
                for (size_t i = 0; i < sv.size(); ++i)
                {
                    qstring buf;
                    tag_remove(&buf, sv[i].line);
                    code += buf.c_str();
                    code += "\n";
                }
                return code;
            }
        }
        catch (const vd_failure_t&) {  }
        catch (...) {  }
    }

    func_t* func = pfn ? pfn : get_func(func_ea);
    if (!func) return {};

    std::string asm_text;
    ea_t ea = func->start_ea;
    while (ea < func->end_ea && ea != BADADDR)
    {
        qstring buf;
        generate_disasm_line(&buf, ea, GENDSM_REMOVE_TAGS);
        asm_text += buf.c_str();
        asm_text += "\n";
        ea = next_head(ea, func->end_ea);
    }
    return asm_text;
}

graph_node_t* StructureExtractor::extract_function(ea_t func_ea, const std::string& binary_hash)
{
    if (func_ea == BADADDR || binary_hash.empty()) return nullptr;


    qstring name_buf;
    get_func_name(&name_buf, func_ea);
    std::string func_name = name_buf.c_str();
    if (func_name.empty())
        func_name = "sub_" + std::to_string(func_ea);


    graph_node_t* existing = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, func_ea);

    graph_node_t node;
    if (existing)
        node = *existing;
    else
    {
        node.module_id = binary_hash;
        node.binary_hash = node.module_id;
        node.identity_source = "module_id_rva";
        node.node_type = node_type_t::FUNCTION;
        node.address = func_ea;
    }
    node.name = func_name;


    std::string raw_code = get_raw_code(func_ea);


    auto features = m_security.extract_from_code(func_name, raw_code);
    node.security_flags = features.generate_security_flags();
    node.network_apis.assign(features.network_apis.begin(), features.network_apis.end());
    node.file_io_apis.assign(features.file_io_apis.begin(), features.file_io_apis.end());
    node.crypto_apis.assign(features.crypto_apis.begin(), features.crypto_apis.end());
    node.process_apis.assign(features.process_apis.begin(), features.process_apis.end());
    node.ip_addresses.assign(features.ip_addresses.begin(), features.ip_addresses.end());
    node.urls.assign(features.urls.begin(), features.urls.end());
    node.file_paths.assign(features.file_paths.begin(), features.file_paths.end());
    node.domains.assign(features.domains.begin(), features.domains.end());
    node.registry_keys.assign(features.registry_keys.begin(), features.registry_keys.end());
    node.activity_profile = features.get_activity_profile();
    node.risk_level = features.get_risk_level();
    if (!raw_code.empty()) node.raw_code = raw_code;
    node.is_stale = true;

    graph_node_t* result = m_store.upsert_node(node);


    extract_call_edges(func_ea, binary_hash, *result);
    return result;
}

int StructureExtractor::extract_call_edges(ea_t func_ea, const std::string& binary_hash,
                                            graph_node_t& node)
{
    int edges_created = 0;
    func_t* func = get_func(func_ea);
    if (!func) return 0;


    std::set<ea_t> callee_addrs;
    ea_t ea = func->start_ea;
    while (ea < func->end_ea && ea != BADADDR)
    {
        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_FAR); ok; ok = xb.next_from())
        {
            if (xb.type == fl_CN || xb.type == fl_CF)
            {
                func_t* callee_func = get_func(xb.to);
                if (callee_func && callee_func->start_ea != func_ea)
                    callee_addrs.insert(callee_func->start_ea);
            }
        }
        ea = next_head(ea, func->end_ea);
    }

    for (ea_t callee_ea : callee_addrs)
    {
        if (m_cancelled) break;

        qstring callee_name_buf;
        get_func_name(&callee_name_buf, callee_ea);
        std::string callee_name = callee_name_buf.c_str();
        if (callee_name.empty()) callee_name = "sub_" + std::to_string(callee_ea);

        graph_node_t* callee_node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, callee_ea);
        if (!callee_node)
        {
            graph_node_t cn;
            cn.module_id = binary_hash;
            cn.binary_hash = cn.module_id;
            cn.identity_source = "module_id_rva";
            cn.node_type = node_type_t::FUNCTION;
            cn.address = callee_ea;
            cn.name = callee_name;
            cn.is_stale = true;
            callee_node = m_store.upsert_node(cn);
        }

        graph_edge_t edge;
        edge.module_id = binary_hash;
        edge.binary_hash = edge.module_id;
        edge.source_id = node.id;
        edge.target_id = callee_node->id;
        edge.edge_type = edge_type_t::CALLS;
        edge.weight = 1.0;
        m_store.add_edge(edge);
        ++edges_created;


        if (!callee_node->security_flags.empty())
        {
            bool has_risk = false;
            for (auto& f : callee_node->security_flags)
                if (f.find("_RISK") != std::string::npos) { has_risk = true; break; }
            if (has_risk)
            {
                graph_edge_t vuln_edge;
                vuln_edge.module_id = binary_hash;
                vuln_edge.binary_hash = vuln_edge.module_id;
                vuln_edge.source_id = node.id;
                vuln_edge.target_id = callee_node->id;
                vuln_edge.edge_type = edge_type_t::CALLS_VULNERABLE;
                vuln_edge.weight = 1.0;
                m_store.add_edge(vuln_edge);
                ++edges_created;

                if (std::find(node.security_flags.begin(), node.security_flags.end(),
                              "CALLS_VULNERABLE_FUNCTION") == node.security_flags.end())
                {
                    node.security_flags.push_back("CALLS_VULNERABLE_FUNCTION");
                    m_store.upsert_node(node);
                }
            }
        }
    }

    return edges_created;
}

StructureExtractor::extraction_result_t
StructureExtractor::extract_all(const std::string& binary_hash, progress_fn on_progress)
{
    extraction_result_t result;
    m_cancelled = false;


    size_t total = get_func_qty();
    if (total == 0) return result;

    for (size_t i = 0; i < total; ++i)
    {
        if (m_cancelled) break;


        func_t* func = getn_func(i);
        if (!func) continue;

        if (on_progress)
            on_progress(static_cast<int>(i + 1), static_cast<int>(total), "Indexing: " + std::to_string(i + 1) + "/" + std::to_string(total));

        graph_node_t* node = extract_function(func->start_ea, binary_hash);
        if (node)
        {
            ++result.functions_extracted;
        }
    }

    return result;
}


bool ensure_function_indexed(const std::string& binary_hash, ea_t func_ea)
{
    if (binary_hash.empty() || func_ea == BADADDR)
        return false;

    auto_wait();

    auto& store = GraphStore::instance();
    if (store.get_node_by_address(binary_hash, node_type_t::FUNCTION, func_ea) != nullptr)
        return true;

    StructureExtractor extractor(store);
    return extractor.extract_function(func_ea, binary_hash) != nullptr;
}


bool ensure_full_binary_index(const std::string& binary_hash,
                              StructureExtractor::progress_fn on_progress,
                              bool* reindexed)
{
    if (reindexed != nullptr)
        *reindexed = false;

    if (binary_hash.empty())
        return false;

    auto_wait();

    auto& store = GraphStore::instance();
    auto& vs    = get_vector_store();

    const size_t total_functions = get_func_qty();
    if (total_functions == 0)
        return true;

    const auto existing_functions = store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    const auto stats = store.get_stats(binary_hash);
    const bool needs_graph_reindex = existing_functions.size() < total_functions || stats.stale > 0;
    const bool needs_vector_reindex = vs.size() < total_functions;

    if (!needs_graph_reindex && !needs_vector_reindex)
        return true;

    if (needs_graph_reindex)
    {
        StructureExtractor extractor(store);
        extractor.extract_all(binary_hash, on_progress);
    }

    if (needs_graph_reindex || needs_vector_reindex)
    {
        if (g_settings.embedding_enabled)
        {
            index_embeddings(binary_hash, on_progress);
            save_vectors(binary_hash);
        }
    }

    save_graph(binary_hash);

    if (reindexed != nullptr)
        *reindexed = true;

    return store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION).size() >= total_functions;
}


TaintAnalyzer::TaintAnalyzer(GraphStore& store) : m_store(store) {}

const std::set<std::string>& TaintAnalyzer::taint_sources()
{
    static const std::set<std::string> s = {
        "recv", "recvfrom", "recvmsg", "read", "WSARecv", "WSARecvFrom",
        "InternetReadFile", "HttpQueryInfo", "WinHttpReadData",
        "fread", "fgets", "fgetc", "getc", "ReadFile", "ReadFileEx",
        "NtReadFile", "ZwReadFile",
        "scanf", "fscanf", "sscanf", "gets", "getline", "getdelim",
        "getenv", "GetEnvironmentVariable",
        "MapViewOfFile", "mmap",
    };
    return s;
}

const std::set<std::string>& TaintAnalyzer::taint_sinks()
{
    static const std::set<std::string> s = {
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "wcscpy", "wcscat",
        "lstrcpy", "lstrcpyA", "lstrcpyW", "lstrcat",
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
        "system", "popen", "_popen", "CreateProcess", "CreateProcessA",
        "CreateProcessW", "ShellExecute", "ShellExecuteA", "ShellExecuteW", "WinExec",
        "fopen", "open", "CreateFile", "CreateFileA", "CreateFileW",
        "mysql_query", "sqlite3_exec", "PQexec",
        "memcpy", "memmove", "memset", "RtlCopyMemory",
    };
    return s;
}

static const std::set<std::string> TAINT_SOURCE_FLAGS = {
    "NETWORK_CAPABLE", "READS_FILES", "ACCEPTS_CONNECTIONS",
    "INITIATES_CONNECTIONS", "PERFORMS_DNS_LOOKUP",
};

static const std::set<std::string> TAINT_SINK_FLAGS = {
    "BUFFER_OVERFLOW_RISK", "COMMAND_INJECTION_RISK",
    "FORMAT_STRING_RISK", "PATH_TRAVERSAL_RISK",
    "SQL_INJECTION_RISK", "CALLS_DANGEROUS_FUNCTIONS",
};

std::vector<graph_node_t*> TaintAnalyzer::find_source_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::vector<graph_node_t*> sources;
    auto& ts = taint_sources();
    for (auto* n : nodes)
    {
        bool is_source = false;
        for (auto& f : n->security_flags)
            if (TAINT_SOURCE_FLAGS.count(f)) { is_source = true; break; }
        if (!is_source)
            for (auto& a : n->network_apis)
                if (ts.count(a)) { is_source = true; break; }
        if (!is_source)
            for (auto& a : n->file_io_apis)
                if (ts.count(a)) { is_source = true; break; }
        if (is_source) sources.push_back(n);
    }
    return sources;
}

std::vector<graph_node_t*> TaintAnalyzer::find_sink_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::vector<graph_node_t*> sinks;
    auto& ts = taint_sinks();
    for (auto* n : nodes)
    {
        bool is_sink = false;
        for (auto& f : n->security_flags)
            if (TAINT_SINK_FLAGS.count(f)) { is_sink = true; break; }
        if (!is_sink)
            for (auto& a : n->network_apis)
                if (ts.count(a)) { is_sink = true; break; }
        if (!is_sink)
            for (auto& a : n->file_io_apis)
                if (ts.count(a)) { is_sink = true; break; }
        if (is_sink) sinks.push_back(n);
    }
    return sinks;
}

std::vector<std::pair<std::vector<int>, graph_node_t*>> TaintAnalyzer::dfs_paths(
    int source_id, const std::unordered_map<int, graph_node_t*>& sinks,
    const std::string& binary_hash, int remaining)
{
    std::vector<std::pair<std::vector<int>, graph_node_t*>> results;
    std::vector<std::pair<int, std::vector<int>>> stack;
    stack.push_back({source_id, {source_id}});

    while (!stack.empty() && remaining > 0)
    {
        if (m_cancelled) break;
        auto [node_id, path] = stack.back();
        stack.pop_back();

        if (static_cast<int>(path.size()) > MAX_PATH_LENGTH) continue;

        if (node_id != source_id)
        {
            auto it = sinks.find(node_id);
            if (it != sinks.end())
            {
                results.push_back({path, it->second});
                --remaining;
                continue;
            }
        }


        auto edges = m_store.get_edges_from(node_id);
        for (auto* e : edges)
        {
            if (e->edge_type != edge_type_t::CALLS) continue;

            bool in_path = false;
            for (int pid : path)
                if (pid == e->target_id) { in_path = true; break; }
            if (in_path) continue;

            auto new_path = path;
            new_path.push_back(e->target_id);
            stack.push_back({e->target_id, new_path});
        }
    }
    return results;
}

std::vector<taint_path_t> TaintAnalyzer::find_taint_paths(const std::string& binary_hash,
                                                           int max_paths, bool create_edges)
{
    m_cancelled = false;

    auto sources = find_source_nodes(binary_hash);
    auto sink_nodes = find_sink_nodes(binary_hash);

    if (sources.empty() || sink_nodes.empty()) return {};

    std::unordered_map<int, graph_node_t*> sink_map;
    for (auto* n : sink_nodes) sink_map[n->id] = n;

    std::vector<taint_path_t> paths;
    for (auto* source : sources)
    {
        if (m_cancelled) break;
        if (static_cast<int>(paths.size()) >= max_paths) break;

        auto found = dfs_paths(source->id, sink_map, binary_hash, max_paths - static_cast<int>(paths.size()));
        for (auto& [path_ids, sink_node] : found)
        {
            if (m_cancelled) break;

            taint_path_t tp;
            tp.source_id = source->id;
            tp.sink_id = sink_node->id;
            tp.path = path_ids;
            tp.source_name = source->name;
            tp.sink_name = sink_node->name;

            for (int pid : path_ids)
            {
                auto* pn = m_store.get_node(pid);
                tp.path_names.push_back(pn ? pn->name : ("node_" + std::to_string(pid)));
            }

            auto& ts = taint_sources();
            for (auto& a : source->network_apis)
                if (ts.count(a)) tp.source_apis.push_back(a);
            for (auto& a : source->file_io_apis)
                if (ts.count(a)) tp.source_apis.push_back(a);

            auto& tsinks = taint_sinks();
            for (auto& a : sink_node->network_apis)
                if (tsinks.count(a)) tp.sink_apis.push_back(a);
            for (auto& a : sink_node->file_io_apis)
                if (tsinks.count(a)) tp.sink_apis.push_back(a);
            for (auto& f : sink_node->security_flags)
            {
                if (f.find("_RISK") != std::string::npos && tp.vulnerability_type.empty())
                    tp.vulnerability_type = f;
            }

            paths.push_back(tp);

            if (create_edges)
            {

                for (size_t i = 0; i + 1 < path_ids.size(); ++i)
                {
                    graph_edge_t edge;
                    edge.module_id = binary_hash;
                    edge.binary_hash = edge.module_id;
                    edge.source_id = path_ids[i];
                    edge.target_id = path_ids[i + 1];
                    edge.edge_type = edge_type_t::TAINT_FLOWS_TO;
                    edge.weight = 1.0;
                    m_store.add_edge(edge);
                }


                graph_edge_t vuln_edge;
                vuln_edge.module_id = binary_hash;
                vuln_edge.binary_hash = vuln_edge.module_id;
                vuln_edge.source_id = source->id;
                vuln_edge.target_id = sink_node->id;
                vuln_edge.edge_type = edge_type_t::VULNERABLE_VIA;
                vuln_edge.weight = 1.0;
                m_store.add_edge(vuln_edge);
            }
        }
    }
    return paths;
}


CommunityDetector::CommunityDetector(GraphStore& store) : m_store(store) {}


static const std::map<std::string, std::vector<std::string>> PURPOSE_PATTERNS = {
    {"network", {"socket", "connect", "send", "recv", "http", "dns", "net", "tcp", "udp",
                 "WSA", "inet", "listen", "accept", "bind", "gethost"}},
    {"file_io", {"file", "read", "write", "open", "close", "fopen", "fwrite", "fread",
                 "CreateFile", "ReadFile", "WriteFile"}},
    {"crypto", {"crypt", "aes", "sha", "md5", "encrypt", "decrypt", "hash", "rsa",
                "cipher", "hmac", "base64"}},
    {"memory", {"alloc", "malloc", "free", "heap", "realloc", "calloc", "mmap",
                "VirtualAlloc", "VirtualFree", "HeapAlloc"}},
    {"string", {"str", "sprintf", "strcpy", "strcat", "strlen", "strcmp", "string",
                "wcs", "memcpy", "memset"}},
    {"process", {"thread", "process", "exec", "spawn", "fork", "CreateProcess",
                 "CreateThread", "TerminateProcess", "ExitProcess"}},
    {"registry", {"reg", "registry", "hkey", "RegOpen", "RegQuery", "RegSet"}},
    {"init", {"init", "setup", "start", "main", "entry", "constructor", "ctor",
              "initialize", "DllMain", "WinMain"}},
    {"gui", {"window", "dialog", "button", "menu", "paint", "draw", "CreateWindow",
             "ShowWindow", "MessageBox", "SendMessage"}},
};

std::string CommunityDetector::infer_community_purpose(const std::vector<graph_node_t*>& members)
{
    std::map<std::string, int> scores;
    for (auto* m : members)
    {
        std::string name_lower = m->name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        for (auto& [purpose, keywords] : PURPOSE_PATTERNS)
            for (auto& kw : keywords)
            {
                std::string kw_lower = kw;
                std::transform(kw_lower.begin(), kw_lower.end(), kw_lower.begin(), ::tolower);
                if (name_lower.find(kw_lower) != std::string::npos)
                    ++scores[purpose];
            }
    }

    if (scores.empty()) return "general";

    auto best = std::max_element(scores.begin(), scores.end(),
        [](auto& a, auto& b) { return a.second < b.second; });
    return best->first;
}

int CommunityDetector::detect(const std::string& binary_hash, int min_size,
                               int max_iterations, bool force, progress_fn on_progress)
{
    m_cancelled = false;

    if (!force && m_store.communities_exist(binary_hash))
        return static_cast<int>(m_store.get_communities(binary_hash).size());

    if (force)
        m_store.delete_communities(binary_hash);

    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    if (nodes.empty()) return 0;


    auto edges = m_store.get_edges_by_types(binary_hash, {edge_type_t::CALLS, edge_type_t::CALLS_VULNERABLE});
    std::unordered_map<int, std::set<int>> adjacency;
    for (auto* e : edges)
    {
        adjacency[e->source_id].insert(e->target_id);
        adjacency[e->target_id].insert(e->source_id);
    }


    std::unordered_map<int, int> labels;
    for (auto* n : nodes)
        labels[n->id] = n->id;


    for (int iter = 0; iter < max_iterations; ++iter)
    {
        if (m_cancelled) return 0;
        if (on_progress) on_progress(iter + 1, max_iterations);

        bool changed = false;
        for (auto* n : nodes)
        {
            auto& neighbors = adjacency[n->id];
            if (neighbors.empty()) continue;


            std::map<int, int> label_counts;
            for (int neighbor_id : neighbors)
            {
                auto it = labels.find(neighbor_id);
                if (it != labels.end())
                    ++label_counts[it->second];
            }
            if (label_counts.empty()) continue;


            int best_label = labels[n->id];
            int best_count = 0;
            for (auto& [lbl, cnt] : label_counts)
            {
                if (cnt > best_count)
                {
                    best_count = cnt;
                    best_label = lbl;
                }
            }


            int current_count = label_counts.count(labels[n->id]) ? label_counts[labels[n->id]] : 0;
            if (current_count < best_count)
            {
                labels[n->id] = best_label;
                changed = true;
            }
        }

        if (!changed) break;
    }

    if (m_cancelled) return 0;


    std::unordered_map<int, std::vector<graph_node_t*>> groups;
    for (auto* n : nodes)
        groups[labels[n->id]].push_back(n);


    std::unordered_map<int, int> merge_map;
    for (auto& [label, members] : groups)
    {
        if (static_cast<int>(members.size()) >= min_size) continue;


        std::map<int, int> neighbor_community_sizes;
        for (auto* m : members)
        {
            for (int neighbor_id : adjacency[m->id])
            {
                int neighbor_label = labels[neighbor_id];
                if (neighbor_label != label)
                    ++neighbor_community_sizes[neighbor_label];
            }
        }
        if (!neighbor_community_sizes.empty())
        {
            int best = std::max_element(neighbor_community_sizes.begin(),
                                         neighbor_community_sizes.end(),
                                         [](auto& a, auto& b) { return a.second < b.second; })->first;
            merge_map[label] = best;
        }
    }


    for (auto& [old_label, new_label] : merge_map)
    {
        for (auto* n : groups[old_label])
            labels[n->id] = new_label;
    }


    groups.clear();
    for (auto* n : nodes)
        groups[labels[n->id]].push_back(n);


    int comm_id = 1;
    int count = 0;
    for (auto& [label, members] : groups)
    {
        if (static_cast<int>(members.size()) < min_size) continue;

        community_t comm;
        comm.id = comm_id++;
        comm.module_id = binary_hash;
        comm.binary_hash = comm.module_id;
        comm.purpose = infer_community_purpose(members);
        comm.label = comm.purpose + "_" + std::to_string(comm.id);
        for (auto* m : members)
        {
            comm.member_ids.push_back(m->id);
            m->community_id = comm.id;
            m_store.upsert_node(*m);
        }
        m_store.add_community(comm);
        ++count;
    }

    return count;
}


NetworkFlowAnalyzer::NetworkFlowAnalyzer(GraphStore& store) : m_store(store) {}

const std::set<std::string>& NetworkFlowAnalyzer::send_apis()
{
    static const std::set<std::string> s = {
        "send", "sendto", "sendmsg", "write",
        "WSASend", "WSASendTo", "WSASendMsg",
        "SSL_write", "WinHttpWriteData", "WinHttpSendRequest",
        "InternetWriteFile", "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
        "curl_easy_send",
    };
    return s;
}

const std::set<std::string>& NetworkFlowAnalyzer::recv_apis()
{
    static const std::set<std::string> s = {
        "recv", "recvfrom", "recvmsg", "read",
        "WSARecv", "WSARecvFrom", "WSARecvMsg",
        "SSL_read", "WinHttpReadData", "WinHttpReceiveResponse",
        "InternetReadFile", "InternetReadFileEx", "HttpQueryInfo",
        "curl_easy_recv",
    };
    return s;
}

const std::set<std::string>& NetworkFlowAnalyzer::entry_point_names()
{
    static const std::set<std::string> s = {
        "main", "_main", "wmain", "_wmain",
        "WinMain", "wWinMain", "_WinMain@16", "_wWinMain@16",
        "DllMain", "_DllMain@12", "DllEntryPoint",
        "start", "_start", "entry", "_entry",
        "mainCRTStartup", "wmainCRTStartup",
        "WinMainCRTStartup", "wWinMainCRTStartup",
    };
    return s;
}

std::vector<graph_node_t*> NetworkFlowAnalyzer::find_send_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    auto& apis = send_apis();
    std::vector<graph_node_t*> result;
    for (auto* n : nodes)
    {
        for (auto& a : n->network_apis)
            if (apis.count(a)) { result.push_back(n); break; }
    }
    return result;
}

std::vector<graph_node_t*> NetworkFlowAnalyzer::find_recv_nodes(const std::string& binary_hash)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    auto& apis = recv_apis();
    std::vector<graph_node_t*> result;
    for (auto* n : nodes)
    {
        for (auto& a : n->network_apis)
            if (apis.count(a)) { result.push_back(n); break; }
    }
    return result;
}

NetworkFlowAnalyzer::result_t
NetworkFlowAnalyzer::analyze(const std::string& binary_hash, progress_fn on_progress)
{
    m_cancelled = false;
    result_t result;

    auto send_nodes = find_send_nodes(binary_hash);
    auto recv_nodes = find_recv_nodes(binary_hash);

    for (auto* n : send_nodes) result.send_functions.push_back(n->name);
    for (auto* n : recv_nodes) result.recv_functions.push_back(n->name);

    if (on_progress)
        on_progress(10, 100, "Found " + std::to_string(send_nodes.size()) + " send, " +
                    std::to_string(recv_nodes.size()) + " recv functions");


    auto& entries = entry_point_names();
    auto all_nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::vector<graph_node_t*> entry_nodes;
    for (auto* n : all_nodes)
        if (entries.count(n->name)) entry_nodes.push_back(n);


    std::unordered_set<int> send_ids;
    for (auto* n : send_nodes) send_ids.insert(n->id);

    for (auto* entry : entry_nodes)
    {
        if (m_cancelled) break;
        auto paths = bfs_find_paths(entry->id, send_ids, binary_hash);
        for (auto& fp : paths)
        {
            if (m_cancelled) break;
            fp.source_name = entry->name;

            auto* target = m_store.get_node(fp.target_id);
            if (target)
            {
                fp.target_name = target->name;
                auto& apis = send_apis();
                for (auto& a : target->network_apis)
                    if (apis.count(a)) { fp.api_name = a; break; }
            }
            result.send_paths.push_back(fp);

            if (!m_store.has_edge(entry->id, fp.target_id, edge_type_t::NETWORK_SEND))
            {
                graph_edge_t edge;
                edge.module_id = binary_hash;
                edge.binary_hash = edge.module_id;
                edge.source_id = entry->id;
                edge.target_id = fp.target_id;
                edge.edge_type = edge_type_t::NETWORK_SEND;
                edge.weight = 1.0 / fp.hop_count;
                m_store.add_edge(edge);
                ++result.send_edges_created;
            }
            else
                ++result.send_edges_existing;
        }
    }

    if (on_progress) on_progress(60, 100, "Analyzing recv flow...");


    for (auto* recv : recv_nodes)
    {
        if (m_cancelled) break;
        auto callers = m_store.get_callers(binary_hash, recv->id);
        for (auto* caller : callers)
        {
            if (m_cancelled) break;

            flow_path_t fp;
            fp.source_id = recv->id;
            fp.target_id = caller->id;
            fp.path = {recv->id, caller->id};
            fp.source_name = recv->name;
            fp.target_name = caller->name;
            fp.hop_count = 1;
            auto& apis = recv_apis();
            for (auto& a : recv->network_apis)
                if (apis.count(a)) { fp.api_name = a; break; }
            result.recv_paths.push_back(fp);

            if (!m_store.has_edge(recv->id, caller->id, edge_type_t::NETWORK_RECV))
            {
                graph_edge_t edge;
                edge.module_id = binary_hash;
                edge.binary_hash = edge.module_id;
                edge.source_id = recv->id;
                edge.target_id = caller->id;
                edge.edge_type = edge_type_t::NETWORK_RECV;
                edge.weight = 1.0;
                m_store.add_edge(edge);
                ++result.recv_edges_created;
            }
            else
                ++result.recv_edges_existing;


            auto callers2 = m_store.get_callers(binary_hash, caller->id);
            for (auto* caller2 : callers2)
            {
                if (m_cancelled) break;
                flow_path_t fp2;
                fp2.source_id = recv->id;
                fp2.target_id = caller2->id;
                fp2.path = {recv->id, caller->id, caller2->id};
                fp2.source_name = recv->name;
                fp2.target_name = caller2->name;
                fp2.api_name = fp.api_name;
                fp2.hop_count = 2;
                result.recv_paths.push_back(fp2);
            }
        }
    }

    if (on_progress) on_progress(100, 100, "Complete");
    return result;
}

std::vector<NetworkFlowAnalyzer::flow_path_t>
NetworkFlowAnalyzer::bfs_find_paths(int source_id, const std::unordered_set<int>& targets,
                                     const std::string& binary_hash)
{
    std::vector<flow_path_t> found;
    if (targets.empty()) return found;


    std::deque<std::pair<int, std::vector<int>>> queue;
    std::unordered_set<int> visited;
    queue.push_back({source_id, {source_id}});
    visited.insert(source_id);

    while (!queue.empty() && !m_cancelled)
    {
        auto [current, path] = queue.front();
        queue.pop_front();

        if (static_cast<int>(path.size()) > MAX_PATH_LENGTH) continue;

        if (current != source_id && targets.count(current))
        {
            flow_path_t fp;
            fp.source_id = source_id;
            fp.target_id = current;
            fp.path = path;
            fp.hop_count = static_cast<int>(path.size()) - 1;
            found.push_back(fp);
            continue;
        }

        auto edges = m_store.get_edges_from(current);
        for (auto* e : edges)
        {
            if (e->edge_type != edge_type_t::CALLS) continue;
            if (visited.count(e->target_id)) continue;
            visited.insert(e->target_id);
            auto new_path = path;
            new_path.push_back(e->target_id);
            queue.push_back({e->target_id, new_path});
        }
    }

    return found;
}


QueryEngine::QueryEngine(GraphStore& store) : m_store(store) {}

std::string QueryEngine::node_display_name(const graph_node_t* n) const
{
    if (!n) return "unknown";
    if (!n->name.empty()) return n->name;
    if (n->address != BADADDR)
    {
        char buf[32];
        qsnprintf(buf, sizeof(buf), "sub_%llx", (unsigned long long)n->address);
        return buf;
    }
    return "node_" + std::to_string(n->id);
}

nlohmann::json QueryEngine::get_semantic_analysis(const std::string& binary_hash, ea_t address)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node)
    {
        return {
            {"name", "unknown"}, {"address", address},
            {"has_semantic_analysis", false}, {"has_structure_data", false},
            {"message", "Function not found in graph."}
        };
    }

    auto callers = m_store.get_callers(binary_hash, node->id);
    auto callees = m_store.get_callees(binary_hash, node->id);
    bool has_semantic = !node->llm_summary.empty();
    bool has_structure = !node->raw_code.empty() || !callers.empty() || !callees.empty();

    nlohmann::json j;
    j["name"] = node_display_name(node);
    j["address"] = node->address;
    j["has_semantic_analysis"] = has_semantic;
    j["has_structure_data"] = has_structure;
    j["summary"] = has_semantic ? node->llm_summary : "(Analysis pending - structure data available)";
    j["security_flags"] = node->security_flags;
    j["risk_level"] = node->risk_level;
    j["activity_profile"] = node->activity_profile;
    j["confidence"] = node->confidence;

    j["callers"] = nlohmann::json::array();
    for (auto* c : callers)
        j["callers"].push_back(node_display_name(c));

    j["callees"] = nlohmann::json::array();
    for (auto* c : callees)
        j["callees"].push_back(node_display_name(c));

    if (!node->raw_code.empty())
    {
        std::string truncated = node->raw_code;
        if (truncated.size() > 2000) truncated = truncated.substr(0, 2000) + "\n... (truncated)";
        j["raw_code"] = truncated;
    }

    if (node->community_id >= 0)
    {
        auto communities = m_store.get_communities(binary_hash);
        for (auto& comm : communities)
        {
            if (comm.id == node->community_id)
            {
                j["community"] = {{"id", comm.id}, {"label", comm.label},
                                  {"purpose", comm.purpose}, {"size", comm.member_ids.size()}};
                break;
            }
        }
    }

    return j;
}

nlohmann::json QueryEngine::search_semantic(const std::string& binary_hash,
                                             const std::string& query, int limit)
{
    auto& vs = get_vector_store();
    nlohmann::json j = nlohmann::json::array();


    auto enrich_entry = [](nlohmann::json& entry, const graph_node_t* n) {
        if (!n->urls.empty())           entry["urls"] = n->urls;
        if (!n->ip_addresses.empty())   entry["ip_addresses"] = n->ip_addresses;
        if (!n->file_paths.empty())     entry["file_paths"] = n->file_paths;
        if (!n->domains.empty())        entry["domains"] = n->domains;
        if (!n->registry_keys.empty())  entry["registry_keys"] = n->registry_keys;
        if (!n->network_apis.empty())   entry["network_apis"] = n->network_apis;
        if (!n->crypto_apis.empty())    entry["crypto_apis"] = n->crypto_apis;
        if (!n->file_io_apis.empty())   entry["file_io_apis"] = n->file_io_apis;
        if (!n->process_apis.empty())   entry["process_apis"] = n->process_apis;
        if (!n->activity_profile.empty()) entry["activity_profile"] = n->activity_profile;
    };


    if (vs.size() > 0)
    {
        std::vector<float> query_vec;


        EmbeddingClient ec;
        if (ec.is_available())
        {
            query_vec = ec.embed_single(query);
        }
        else
        {
            auto& lv = get_local_vectorizer();
            if (lv.is_built())
                query_vec = lv.vectorize(query);
        }

        if (!query_vec.empty() && static_cast<int>(query_vec.size()) == vs.dimensions())
        {
            auto hits = vs.search(query_vec, limit);
            for (auto& hit : hits)
            {
                auto* n = m_store.get_node(hit.node_id);
                if (!n || n->binary_hash != binary_hash) continue;

                nlohmann::json entry;
                entry["function_name"] = node_display_name(n);
                entry["address"] = n->address;
                std::string summary = n->llm_summary;
                if (summary.size() > 200) summary = summary.substr(0, 200) + "...";
                entry["summary"] = summary;
                entry["security_flags"] = n->security_flags;
                entry["risk_level"] = n->risk_level;
                entry["similarity_score"] = hit.score;
                enrich_entry(entry, n);
                j.push_back(entry);
            }
            if (!j.empty()) return j;
        }
    }


    auto results = m_store.search_nodes(binary_hash, query, limit);
    for (auto* n : results)
    {
        nlohmann::json entry;
        entry["function_name"] = node_display_name(n);
        entry["address"] = n->address;
        std::string summary = n->llm_summary;
        if (summary.size() > 200) summary = summary.substr(0, 200) + "...";
        entry["summary"] = summary;
        entry["security_flags"] = n->security_flags;
        entry["risk_level"] = n->risk_level;
        enrich_entry(entry, n);
        j.push_back(entry);
    }
    return j;
}

nlohmann::json QueryEngine::get_similar_functions(const std::string& binary_hash,
                                                   ea_t address, int limit)
{
    auto* source = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!source) return nlohmann::json::array();

    nlohmann::json j = nlohmann::json::array();


    auto& vs = get_vector_store();
    if (vs.size() > 0 && vs.has(source->id))
    {
        std::string src_text = build_embedding_text(*source);
        std::vector<float> src_vec;

        EmbeddingClient ec;
        if (ec.is_available())
            src_vec = ec.embed_single(src_text);
        else
        {
            auto& lv = get_local_vectorizer();
            if (lv.is_built())
                src_vec = lv.vectorize(src_text);
        }

        if (!src_vec.empty() && static_cast<int>(src_vec.size()) == vs.dimensions())
        {
            auto hits = vs.search(src_vec, limit * 3);
            for (auto& hit : hits)
            {
                if (static_cast<int>(j.size()) >= limit) break;
                if (hit.node_id == source->id) continue;

                auto* n = m_store.get_node(hit.node_id);
                if (!n || n->binary_hash != binary_hash) continue;
                if (n->node_type != node_type_t::FUNCTION) continue;

                j.push_back({
                    {"function_name", node_display_name(n)},
                    {"address", n->address},
                    {"similarity", hit.score},
                    {"reason", "EMBEDDING_SIMILARITY"}
                });
            }
            if (!j.empty()) return j;
        }
    }


    std::set<int> seen = {source->id};

    auto callers = m_store.get_callers(binary_hash, source->id);
    for (auto* caller : callers)
    {
        if (static_cast<int>(j.size()) >= limit) break;
        auto siblings = m_store.get_callees(binary_hash, caller->id);
        for (auto* sibling : siblings)
        {
            if (static_cast<int>(j.size()) >= limit) break;
            if (seen.count(sibling->id)) continue;
            seen.insert(sibling->id);
            j.push_back({
                {"function_name", node_display_name(sibling)},
                {"address", sibling->address},
                {"similarity", 0.7}, {"reason", "SHARED_CALLERS"}
            });
        }
    }

    auto callees = m_store.get_callees(binary_hash, source->id);
    for (auto* callee : callees)
    {
        if (static_cast<int>(j.size()) >= limit) break;
        auto sibling_callers = m_store.get_callers(binary_hash, callee->id);
        for (auto* sibling : sibling_callers)
        {
            if (static_cast<int>(j.size()) >= limit) break;
            if (seen.count(sibling->id)) continue;
            seen.insert(sibling->id);
            j.push_back({
                {"function_name", node_display_name(sibling)},
                {"address", sibling->address},
                {"similarity", 0.6}, {"reason", "SHARED_CALLEES"}
            });
        }
    }

    return j;
}

nlohmann::json QueryEngine::get_call_context(const std::string& binary_hash,
                                              ea_t address, int depth)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node) return {{"error", "Function not found"}};

    nlohmann::json j;
    j["function"] = node_display_name(node);
    j["address"] = node->address;


    std::function<nlohmann::json(int, int, bool)> build_tree =
        [&](int nid, int max_depth, bool is_callers) -> nlohmann::json
    {
        nlohmann::json arr = nlohmann::json::array();
        if (max_depth <= 0) return arr;

        auto nodes = is_callers ? m_store.get_callers(binary_hash, nid)
                                : m_store.get_callees(binary_hash, nid);
        for (auto* n : nodes)
        {
            nlohmann::json entry;
            entry["name"] = node_display_name(n);
            entry["address"] = n->address;
            if (max_depth > 1)
                entry[is_callers ? "callers" : "callees"] = build_tree(n->id, max_depth - 1, is_callers);
            arr.push_back(entry);
        }
        return arr;
    };

    j["callers"] = build_tree(node->id, depth, true);
    j["callees"] = build_tree(node->id, depth, false);

    return j;
}

nlohmann::json QueryEngine::get_taint_paths(const std::string& binary_hash, ea_t address)
{
    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node) return {{"error", "Function not found"}};


    auto edges_from = m_store.get_edges_from(node->id);
    auto edges_to = m_store.get_edges_to(node->id);

    bool has_taint_edges = false;
    auto has_taint_edge = [](const graph_edge_t* edge) {
        return edge != nullptr
            && (edge->edge_type == edge_type_t::TAINT_FLOWS_TO
                || edge->edge_type == edge_type_t::VULNERABLE_VIA);
    };

    for (auto* edge : edges_from)
    {
        if (has_taint_edge(edge))
        {
            has_taint_edges = true;
            break;
        }
    }
    if (!has_taint_edges)
    {
        for (auto* edge : edges_to)
        {
            if (has_taint_edge(edge))
            {
                has_taint_edges = true;
                break;
            }
        }
    }

    if (!has_taint_edges)
    {
        TaintAnalyzer analyzer(m_store);
        analyzer.find_taint_paths(binary_hash, 100, true);
        save_graph(binary_hash);
        edges_from = m_store.get_edges_from(node->id);
        edges_to = m_store.get_edges_to(node->id);
    }

    nlohmann::json j;
    j["function"] = node_display_name(node);
    j["address"] = node->address;

    nlohmann::json taint_from = nlohmann::json::array();
    nlohmann::json taint_to = nlohmann::json::array();

    for (auto* e : edges_from)
    {
        if (e->edge_type == edge_type_t::TAINT_FLOWS_TO || e->edge_type == edge_type_t::VULNERABLE_VIA)
        {
            auto* target = m_store.get_node(e->target_id);
            taint_from.push_back({
                {"target", node_display_name(target)},
                {"type", edge_type_str(e->edge_type)}
            });
        }
    }

    for (auto* e : edges_to)
    {
        if (e->edge_type == edge_type_t::TAINT_FLOWS_TO || e->edge_type == edge_type_t::VULNERABLE_VIA)
        {
            auto* source = m_store.get_node(e->source_id);
            taint_to.push_back({
                {"source", node_display_name(source)},
                {"type", edge_type_str(e->edge_type)}
            });
        }
    }

    j["taint_flows_to"] = taint_from;
    j["taint_flows_from"] = taint_to;
    j["is_taint_source"] = !taint_from.empty() && taint_to.empty();
    j["is_taint_sink"] = !taint_to.empty() && taint_from.empty();

    return j;
}

nlohmann::json QueryEngine::get_community_info(const std::string& binary_hash, ea_t address)
{
    if (!m_store.communities_exist(binary_hash))
    {
        CommunityDetector detector(m_store);
        detector.detect(binary_hash);
        save_graph(binary_hash);
    }

    auto* node = m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, address);
    if (!node || node->community_id < 0)
        return {{"error", "Function not in a community"}};

    auto communities = m_store.get_communities(binary_hash);
    for (auto& comm : communities)
    {
        if (comm.id != node->community_id) continue;

        nlohmann::json j;
        j["community_id"] = comm.id;
        j["label"] = comm.label;
        j["purpose"] = comm.purpose;
        j["size"] = comm.member_ids.size();

        nlohmann::json members = nlohmann::json::array();
        for (int mid : comm.member_ids)
        {
            auto* m = m_store.get_node(mid);
            if (m) members.push_back({{"name", node_display_name(m)}, {"address", m->address}});
        }
        j["members"] = members;
        return j;
    }

    return {{"error", "Community not found"}};
}


nlohmann::json QueryEngine::get_security_analysis(const std::string& binary_hash, int limit)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);

    nlohmann::json j;
    j["total_functions"] = nodes.size();

    int critical = 0, high = 0, medium = 0, low = 0;
    nlohmann::json risky_funcs = nlohmann::json::array();

    std::map<std::string, int> flag_counts;

    for (auto* n : nodes)
    {
        if (n->risk_level == "CRITICAL") ++critical;
        else if (n->risk_level == "HIGH") ++high;
        else if (n->risk_level == "MEDIUM") ++medium;
        else if (n->risk_level == "LOW") ++low;

        for (auto& f : n->security_flags)
            ++flag_counts[f];

        if ((n->risk_level == "CRITICAL" || n->risk_level == "HIGH")
            && static_cast<int>(risky_funcs.size()) < limit)
        {
            risky_funcs.push_back({
                {"name", node_display_name(n)},
                {"address", n->address},
                {"risk_level", n->risk_level},
                {"security_flags", n->security_flags},
                {"activity_profile", n->activity_profile}
            });
        }
    }

    j["risk_summary"] = {
        {"critical", critical}, {"high", high}, {"medium", medium}, {"low", low}
    };
    j["high_risk_functions"] = risky_funcs;

    nlohmann::json flags_j = nlohmann::json::object();
    for (auto& [flag, count] : flag_counts)
        flags_j[flag] = count;
    j["security_flag_distribution"] = flags_j;

    return j;
}

nlohmann::json QueryEngine::get_activity_analysis(const std::string& binary_hash,
                                                    const std::string& activity_filter)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);

    std::map<std::string, std::vector<nlohmann::json>> by_activity;
    for (auto* n : nodes)
    {
        if (n->activity_profile.empty()) continue;

        std::istringstream iss(n->activity_profile);
        std::string token;
        while (std::getline(iss, token, ','))
        {
            if (!activity_filter.empty() && token != activity_filter) continue;
            nlohmann::json entry;
            entry["name"] = node_display_name(n);
            entry["address"] = n->address;
            entry["risk_level"] = n->risk_level;
            by_activity[token].push_back(entry);
        }
    }

    nlohmann::json j;
    j["total_functions_with_activity"] = 0;
    nlohmann::json activities = nlohmann::json::object();
    for (auto& [activity, funcs] : by_activity)
    {
        activities[activity] = {
            {"count", funcs.size()},
            {"functions", funcs}
        };
        j["total_functions_with_activity"] =
            j["total_functions_with_activity"].get<int>() + static_cast<int>(funcs.size());
    }
    j["activities"] = activities;
    return j;
}

nlohmann::json QueryEngine::get_all_communities(const std::string& binary_hash)
{
    if (!m_store.communities_exist(binary_hash))
    {
        CommunityDetector detector(m_store);
        detector.detect(binary_hash);
        save_graph(binary_hash);
    }

    auto communities = m_store.get_communities(binary_hash);

    nlohmann::json j;
    j["total_communities"] = communities.size();

    nlohmann::json comms = nlohmann::json::array();
    for (auto& comm : communities)
    {
        nlohmann::json cj;
        cj["id"] = comm.id;
        cj["label"] = comm.label;
        cj["purpose"] = comm.purpose;
        cj["size"] = comm.member_ids.size();

        nlohmann::json members = nlohmann::json::array();
        for (int mid : comm.member_ids)
        {
            auto* m = m_store.get_node(mid);
            if (m)
                members.push_back({{"name", node_display_name(m)}, {"address", m->address}});
        }
        cj["members"] = members;
        comms.push_back(cj);
    }
    j["communities"] = comms;
    return j;
}


void initialize(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;
    auto& store = GraphStore::instance();

    std::string path = store.get_graph_path(binary_hash);
    store.load_from_file(path);

    load_vectors(binary_hash);

    msg("[AiDA RAG] Loaded graph for %s\n", binary_hash.c_str());
    auto stats = store.get_stats(binary_hash);
    auto& vs = get_vector_store();
    msg("[AiDA RAG] Nodes: %d, Edges: %d, Communities: %d, Vectors: %zu (%d dims)\n",
        stats.nodes, stats.edges, stats.communities,
        vs.size(), vs.dimensions());
}

void save_graph(const std::string& binary_hash)
{
    if (binary_hash.empty()) return;
    auto& store = GraphStore::instance();
    std::string path = store.get_graph_path(binary_hash);
    int flushed = store.save_incremental(binary_hash, path);
    if (flushed > 0)
    {
        aida_db::AnalysisDB::instance().mark_binary_capabilities(
            binary_hash,
            store.get_stats(binary_hash).nodes > 0,
            get_vector_store().size() > 0);
        msg("[AiDA RAG] Graph saved to %s\n", path.c_str());
        return;
    }
    if (store.save_to_file(path, binary_hash))
    {
        aida_db::AnalysisDB::instance().mark_binary_capabilities(
            binary_hash,
            store.get_stats(binary_hash).nodes > 0,
            get_vector_store().size() > 0);
        msg("[AiDA RAG] Graph saved to %s\n", path.c_str());
    }
}

void load_graph(const std::string& binary_hash)
{
    initialize(binary_hash);
}

// ===========================================================================
// Slice H5 - cursor overloads
// ===========================================================================
nlohmann::json QueryEngine::get_security_analysis(const std::string& binary_hash, int limit,
                                                  const query_cursor_t& in_cursor,
                                                  query_cursor_t& out_cursor, bool& out_has_more)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);

    std::unordered_set<int> seen(in_cursor.seen_node_ids.begin(), in_cursor.seen_node_ids.end());
    uint64_t max_updated = in_cursor.since_ms;

    nlohmann::json j;
    j["total_functions"] = nodes.size();

    int critical = 0, high = 0, medium = 0, low = 0;
    nlohmann::json risky_funcs = nlohmann::json::array();
    std::map<std::string, int> flag_counts;

    out_cursor = in_cursor;
    int eligible = 0;
    for (auto* n : nodes)
    {
        if (n->updated_at <= in_cursor.since_ms) continue;
        if (seen.count(n->id)) continue;

        if (n->risk_level == "CRITICAL") ++critical;
        else if (n->risk_level == "HIGH") ++high;
        else if (n->risk_level == "MEDIUM") ++medium;
        else if (n->risk_level == "LOW") ++low;
        for (auto& f : n->security_flags) ++flag_counts[f];

        if (n->risk_level == "CRITICAL" || n->risk_level == "HIGH")
        {
            ++eligible;
            if (static_cast<int>(risky_funcs.size()) < limit)
            {
                risky_funcs.push_back({
                    {"name", node_display_name(n)},
                    {"address", n->address},
                    {"risk_level", n->risk_level},
                    {"security_flags", n->security_flags},
                    {"activity_profile", n->activity_profile},
                    {"node_id", n->id},
                    {"updated_at", n->updated_at}
                });
                out_cursor.seen_node_ids.push_back(n->id);
                if (n->updated_at > max_updated) max_updated = n->updated_at;
            }
        }
    }
    out_cursor.since_ms = max_updated;
    out_has_more = (eligible > limit);

    j["risk_summary"] = {
        {"critical", critical}, {"high", high}, {"medium", medium}, {"low", low}
    };
    j["high_risk_functions"] = risky_funcs;
    nlohmann::json flags_j = nlohmann::json::object();
    for (auto& [flag, count] : flag_counts) flags_j[flag] = count;
    j["security_flag_distribution"] = flags_j;
    return j;
}

nlohmann::json QueryEngine::get_activity_analysis(const std::string& binary_hash,
                                                  const std::string& activity_filter,
                                                  const query_cursor_t& in_cursor,
                                                  query_cursor_t& out_cursor, bool& out_has_more)
{
    auto nodes = m_store.get_nodes_by_type(binary_hash, node_type_t::FUNCTION);
    std::unordered_set<int> seen(in_cursor.seen_node_ids.begin(), in_cursor.seen_node_ids.end());
    uint64_t max_updated = in_cursor.since_ms;

    std::map<std::string, std::vector<nlohmann::json>> by_activity;
    out_cursor = in_cursor;
    out_has_more = false;
    for (auto* n : nodes)
    {
        if (n->activity_profile.empty()) continue;
        if (n->updated_at <= in_cursor.since_ms) continue;
        if (seen.count(n->id)) continue;

        std::istringstream iss(n->activity_profile);
        std::string token;
        bool emitted = false;
        while (std::getline(iss, token, ','))
        {
            if (!activity_filter.empty() && token != activity_filter) continue;
            nlohmann::json entry;
            entry["name"] = node_display_name(n);
            entry["address"] = n->address;
            entry["risk_level"] = n->risk_level;
            entry["node_id"] = n->id;
            entry["updated_at"] = n->updated_at;
            by_activity[token].push_back(entry);
            emitted = true;
        }
        if (emitted)
        {
            out_cursor.seen_node_ids.push_back(n->id);
            if (n->updated_at > max_updated) max_updated = n->updated_at;
        }
    }
    out_cursor.since_ms = max_updated;

    nlohmann::json j;
    int total = 0;
    nlohmann::json activities = nlohmann::json::object();
    for (auto& [activity, funcs] : by_activity)
    {
        activities[activity] = {{"count", funcs.size()}, {"functions", funcs}};
        total += static_cast<int>(funcs.size());
    }
    j["total_functions_with_activity"] = total;
    j["activities"] = activities;
    return j;
}

nlohmann::json QueryEngine::search_semantic(const std::string& binary_hash,
                                            const std::string& query, int limit,
                                            const query_cursor_t& in_cursor,
                                            query_cursor_t& out_cursor, bool& out_has_more)
{
    // Reuse non-cursor implementation, then filter by cursor.
    nlohmann::json full = search_semantic(binary_hash, query, limit);
    std::unordered_set<int> seen(in_cursor.seen_node_ids.begin(), in_cursor.seen_node_ids.end());
    uint64_t max_updated = in_cursor.since_ms;

    nlohmann::json out = nlohmann::json::array();
    out_cursor = in_cursor;
    if (!full.is_array()) { out_has_more = false; return out; }
    for (auto& entry : full)
    {
        // The base search_semantic doesn't populate node_id/updated_at; derive
        // from the GraphStore via address lookup so cursor logic still works.
        ea_t addr = BADADDR;
        if (entry.contains("address") && entry["address"].is_number())
            addr = entry["address"].get<ea_t>();
        auto* node = (addr == BADADDR) ? nullptr
                       : m_store.get_node_by_address(binary_hash, node_type_t::FUNCTION, addr);
        if (node)
        {
            if (node->updated_at <= in_cursor.since_ms) continue;
            if (seen.count(node->id)) continue;
            entry["node_id"] = node->id;
            entry["updated_at"] = node->updated_at;
            out_cursor.seen_node_ids.push_back(node->id);
            if (node->updated_at > max_updated) max_updated = node->updated_at;
        }
        out.push_back(entry);
    }
    out_cursor.since_ms = max_updated;
    out_has_more = (static_cast<int>(out.size()) == limit);
    return out;
}

// ===========================================================================
// Slice H4 - extract_externally_reachable_entries
// ===========================================================================
static const char* g_b64chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::string& in)
{
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) { out.push_back(g_b64chars[(val >> valb) & 0x3F]); valb -= 6; }
    }
    if (valb > -6) out.push_back(g_b64chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static bool base64_decode(const std::string& in, std::string& out)
{
    static const int8_t T_init = -1;
    static int8_t T[256];
    static bool inited = false;
    if (!inited)
    {
        for (int i = 0; i < 256; ++i) T[i] = T_init;
        for (int i = 0; i < 64; ++i) T[(unsigned char)g_b64chars[i]] = i;
        inited = true;
    }
    int val = 0, valb = -8;
    out.clear();
    for (unsigned char c : in)
    {
        if (T[c] < 0) { if (c == '=') break; else continue; }
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) { out.push_back(char((val >> valb) & 0xFF)); valb -= 8; }
    }
    return true;
}

std::string encode_cursor(const query_cursor_t& c)
{
    if (c.since_ms == 0 && c.seen_node_ids.empty()) return {};
    nlohmann::json j;
    j["since_ms"] = c.since_ms;
    j["seen_node_ids"] = c.seen_node_ids;
    return base64_encode(j.dump());
}

bool decode_cursor(const std::string& encoded, query_cursor_t& out)
{
    out = {};
    if (encoded.empty()) return false;
    std::string raw;
    if (!base64_decode(encoded, raw)) return false;
    try
    {
        auto j = nlohmann::json::parse(raw);
        out.since_ms = j.value("since_ms", uint64_t(0));
        out.seen_node_ids = j.value("seen_node_ids", std::vector<int>{});
        return true;
    }
    catch (...) { return false; }
}

// Driver dispatch slot count (IRP_MJ_MAXIMUM_FUNCTION + 1 = 28).
static constexpr int IRP_MAJOR_FUNCTION_SLOTS = 28;

static std::string name_for_ea(ea_t ea)
{
    qstring q;
    get_ea_name(&q, ea);
    return std::string(q.c_str());
}

static std::string func_name_for_ea(ea_t ea)
{
    qstring q;
    get_func_name(&q, ea);
    if (!q.empty()) return std::string(q.c_str());
    return name_for_ea(ea);
}

static std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static bool filter_allows_api(const std::string& api, const std::vector<std::string>& filters)
{
    if (filters.empty()) return true;
    std::string low = lower_copy(api);
    for (const auto& f : filters)
    {
        std::string lf = lower_copy(f);
        if (low == lf || low.find(lf) != std::string::npos)
            return true;
    }
    return false;
}

static bool is_function_start_ea(ea_t ea)
{
    if (ea == BADADDR) return false;
    func_t* pfn = get_func(ea);
    return pfn != nullptr && pfn->start_ea == ea;
}

static nlohmann::json handler_record_json(uint64_t index, ea_t ea, const std::string& name,
                                          bool include_code, size_t max_code_len)
{
    nlohmann::json h;
    h["index"] = index;
    h["ea"] = ea;
    h["name"] = name;
    if (include_code && is_function_start_ea(ea))
    {
        auto code = ida_utils::get_function_code(ea, max_code_len, false);
        h["code"] = code.second;
    }
    return h;
}

struct binary_capability_index_ctx_t
{
    nlohmann::json* out = nullptr;
    std::string module;
    std::vector<std::string> filters;
    size_t max_callsites = 64;
};

static int idaapi binary_capability_import_cb(ea_t ea, const char* name, uval_t ord, void* param)
{
    auto* ctx = static_cast<binary_capability_index_ctx_t*>(param);
    if (ctx == nullptr || ctx->out == nullptr) return 0;

    std::string api = name != nullptr ? std::string(name) : std::string("ord_") + std::to_string(static_cast<uint64_t>(ord));
    if (!filter_allows_api(api, ctx->filters)) return 1;

    nlohmann::json entry;
    entry["module"] = ctx->module;
    entry["callsite_count"] = 0;
    entry["callsites"] = nlohmann::json::array();

    int count = 0;
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to())
    {
        ++count;
        if (entry["callsites"].size() >= ctx->max_callsites)
            continue;
        func_t* pfn = get_func(xb.from);
        nlohmann::json cs;
        cs["ea"] = xb.from;
        cs["func_name"] = pfn ? func_name_for_ea(pfn->start_ea) : std::string();
        cs["func_ea"] = pfn ? pfn->start_ea : BADADDR;
        entry["callsites"].push_back(std::move(cs));
    }
    entry["callsite_count"] = count;

    nlohmann::json& root = *ctx->out;
    if (root.contains(api))
    {
        auto& existing = root[api];
        existing["callsite_count"] = existing.value("callsite_count", 0) + count;
        if (existing.value("module", std::string()).find(ctx->module) == std::string::npos)
            existing["module"] = existing.value("module", std::string()) + "," + ctx->module;
        for (const auto& cs : entry["callsites"])
        {
            if (existing["callsites"].size() < ctx->max_callsites)
                existing["callsites"].push_back(cs);
        }
    }
    else
    {
        root[api] = std::move(entry);
    }
    return 1;
}

std::vector<external_entry_t> extract_externally_reachable_entries()
{
    std::vector<external_entry_t> out;
    std::unordered_set<ea_t> seen;
    auto add = [&](ea_t ea, std::string name, const char* category, const char* source)
    {
        if (ea == BADADDR) return;
        if (!seen.insert(ea).second) return;
        out.push_back({ea, std::move(name), category, source});
    };

    auto name_of = [](ea_t ea) -> std::string {
        qstring q; get_ea_name(&q, ea); return std::string(q.c_str());
    };

    // 1. PE exports via entry.hpp.
    {
        size_t qty = get_entry_qty();
        for (size_t i = 0; i < qty; ++i)
        {
            uval_t ord = get_entry_ordinal(i);
            ea_t ea = get_entry(ord);
            qstring nm; get_entry_name(&nm, ord);
            std::string nstr = nm.c_str();
            if (nstr.empty()) nstr = name_of(ea);
            add(ea, nstr, "pe_export", "entry.hpp/get_entry");
        }
    }

    // Walk all functions once to bucket by name pattern (RPC NDR, COM
    // IDispatch surrogate names, WinRT activation factories, service handlers,
    // WSK callbacks, driver dispatch).
    const std::regex re_rpc_ndr(R"(^Ndr(64)?\w*(Client|Server)Call\w*)");
    const std::regex re_winrt(R"(^DllGetActivationFactory$|ActivationFactoryFor|GetActivationFactory)");
    const std::regex re_service(R"(ServiceMain$|ServiceHandlerEx?$|ServiceCtrlHandlerEx?$)");
    const std::regex re_wsk(R"(^Wsk\w+Event)");
    const std::regex re_idispatch(R"(IDispatch::Invoke|::Invoke$|IDispatch_Invoke)");

    for (size_t i = 0, n = get_func_qty(); i < n; ++i)
    {
        func_t* pfn = getn_func(i);
        if (!pfn) continue;
        std::string nm = name_of(pfn->start_ea);
        if (nm.empty()) continue;
        if (std::regex_search(nm, re_rpc_ndr))
            add(pfn->start_ea, nm, "rpc_ndr", "name pattern Ndr*ClientCall*/Ndr*ServerCall*");
        else if (std::regex_search(nm, re_winrt))
            add(pfn->start_ea, nm, "winrt_factory", "name pattern DllGetActivationFactory/ActivationFactoryFor");
        else if (std::regex_search(nm, re_service))
            add(pfn->start_ea, nm, "service_handler", "name pattern ServiceMain/ServiceHandlerEx");
        else if (std::regex_search(nm, re_wsk))
            add(pfn->start_ea, nm, "wsk_callback", "name pattern Wsk*Event");
        else if (std::regex_search(nm, re_idispatch))
            add(pfn->start_ea, nm, "com_idispatch", "name pattern IDispatch::Invoke");
    }

    auto add_registration_callers = [&](const std::vector<std::string>& apis,
                                        const char* category,
                                        const char* source)
    {
        nlohmann::json caps = build_binary_capability_index(apis, 256);
        if (!caps.contains("imports") || !caps["imports"].is_object()) return;
        for (auto it = caps["imports"].begin(); it != caps["imports"].end(); ++it)
        {
            const auto& entry = it.value();
            if (!entry.contains("callsites") || !entry["callsites"].is_array()) continue;
            for (const auto& cs : entry["callsites"])
            {
                if (!cs.contains("func_ea") || !cs["func_ea"].is_number()) continue;
                ea_t fea = cs["func_ea"].get<ea_t>();
                if (fea == BADADDR) continue;
                add(fea, func_name_for_ea(fea), category, source);
            }
        }
    };

    add_registration_callers({"RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIfEx",
                              "NdrServerCall", "Ndr64ServerCall"},
                             "rpc_ndr", "RPC/NDR registration import caller");
    add_registration_callers({"CoRegisterClassObject", "DllGetClassObject", "IDispatch"},
                             "com_idispatch", "COM registration import caller");
    add_registration_callers({"StartServiceCtrlDispatcher", "RegisterServiceCtrlHandler",
                              "RegisterServiceCtrlHandlerEx"},
                             "service_handler", "service-control registration import caller");
    add_registration_callers({"WskRegister", "WskCaptureProviderNPI"},
                             "wsk_callback", "WSK registration import caller");

    // 2. Driver dispatch table: scan for "mov [reg+offset], imm" style stores
    //    targeting DriverObject->MajorFunction by walking xrefs from data
    //    segments to known functions. We approximate via DriverEntry: find the
    //    entry symbol and harvest writes within it that reference functions.
    {
        ea_t drv_entry = get_name_ea(BADADDR, "DriverEntry");
        if (drv_entry == BADADDR) drv_entry = get_name_ea(BADADDR, "GsDriverEntry");
        if (drv_entry != BADADDR)
        {
            func_t* pfn = get_func(drv_entry);
            if (pfn)
            {
                // Walk function code for code refs to other functions; capture
                // any code ref whose target is itself a function (heuristic).
                ea_t ea = pfn->start_ea;
                int captured = 0;
                while (ea < pfn->end_ea && ea != BADADDR && captured < IRP_MAJOR_FUNCTION_SLOTS * 2)
                {
                    xrefblk_t xb;
                    for (bool ok = xb.first_from(ea, XREF_CODE | XREF_NOFLOW); ok; ok = xb.next_from())
                    {
                        if (xb.to == BADADDR) continue;
                        func_t* tgt = get_func(xb.to);
                        if (tgt && tgt->start_ea == xb.to)
                        {
                            insn_t insn;
                            if (decode_insn(&insn, ea) > 0 && is_call_insn(insn))
                                continue;
                            add(xb.to, name_of(xb.to), "driver_dispatch", "DriverEntry-resident function pointer write");
                            ++captured;
                        }
                    }
                    ea = next_head(ea, pfn->end_ea);
                }
            }
        }
    }

    return out;
}

nlohmann::json build_binary_capability_index(const std::vector<std::string>& filter_apis,
                                             size_t max_callsites_per_api)
{
    nlohmann::json j;
    j["imports"] = nlohmann::json::object();
    j["filter_apis"] = filter_apis;

    uint qty = get_import_module_qty();
    for (uint i = 0; i < qty; ++i)
    {
        qstring mod;
        if (!get_import_module_name(&mod, static_cast<int>(i)))
            continue;
        binary_capability_index_ctx_t ctx;
        ctx.out = &j["imports"];
        ctx.module = mod.c_str();
        ctx.filters = filter_apis;
        ctx.max_callsites = max_callsites_per_api;
        enum_import_names(static_cast<int>(i), binary_capability_import_cb, &ctx);
    }

    j["api_count"] = j["imports"].size();
    return j;
}

struct dispatch_ctree_visitor_t : public ctree_visitor_t
{
    nlohmann::json* tables = nullptr;
    ea_t func_ea = BADADDR;
    std::string func_name;
    bool include_code = false;
    size_t max_code_len = 6000;
    std::vector<nlohmann::json> vtable_handlers;
    std::set<std::pair<ea_t, uint64_t>> vtable_seen;

    dispatch_ctree_visitor_t(nlohmann::json* out, ea_t ea, std::string name,
                             bool code, size_t max_len)
        : ctree_visitor_t(CV_PARENTS),
          tables(out),
          func_ea(ea),
          func_name(std::move(name)),
          include_code(code),
          max_code_len(max_len)
    {
    }

    int idaapi visit_insn(cinsn_t* insn) override
    {
        if (insn == nullptr || insn->op != cit_switch || insn->cswitch == nullptr || tables == nullptr)
            return 0;

        nlohmann::json t;
        t["type"] = "switch";
        t["base_ea"] = insn->ea;
        t["function_ea"] = func_ea;
        t["function_name"] = func_name;
        t["handlers"] = nlohmann::json::array();

        int idx = 0;
        for (const auto& cc : insn->cswitch->cases)
        {
            uint64_t index = cc.values.empty() ? uint64_t(-1) : cc.values[0];
            std::string name = cc.values.empty()
                ? std::string("case_default")
                : std::string("case_") + std::to_string(index);
            auto h = handler_record_json(index, cc.ea != BADADDR ? cc.ea : insn->ea,
                                         name, include_code, max_code_len);
            h["case_values"] = nlohmann::json::array();
            for (uint64_t v : cc.values)
                h["case_values"].push_back(v);
            h["ordinal"] = idx++;
            t["handlers"].push_back(std::move(h));
        }
        t["size"] = t["handlers"].size();
        tables->push_back(std::move(t));
        return 0;
    }

    int idaapi visit_expr(cexpr_t* expr) override
    {
        if (expr == nullptr || expr->op != cot_memptr)
            return 0;
        if (!expr->is_call_object_of(parent_item()))
            return 0;
        auto key = std::make_pair(expr->ea, static_cast<uint64_t>(expr->m));
        if (!vtable_seen.insert(key).second)
            return 0;
        uint64_t index = expr->ptrsize > 0 ? static_cast<uint64_t>(expr->m / expr->ptrsize)
                                           : static_cast<uint64_t>(expr->m);
        auto h = handler_record_json(index, expr->ea, std::string("vtable_slot_") + std::to_string(index),
                                     include_code, max_code_len);
        h["offset"] = static_cast<uint64_t>(expr->m);
        vtable_handlers.push_back(std::move(h));
        return 0;
    }
};

static void append_fn_array_table(nlohmann::json& tables, ea_t base, const std::vector<ea_t>& handlers,
                                  bool include_code, size_t max_code_len)
{
    if (handlers.size() < 2) return;
    nlohmann::json t;
    t["type"] = "fn_array";
    t["base_ea"] = base;
    t["size"] = handlers.size();
    t["handlers"] = nlohmann::json::array();
    for (size_t i = 0; i < handlers.size(); ++i)
    {
        ea_t target = handlers[i];
        t["handlers"].push_back(handler_record_json(
            static_cast<uint64_t>(i),
            target,
            func_name_for_ea(target),
            include_code,
            max_code_len));
    }
    tables.push_back(std::move(t));
}

nlohmann::json extract_dispatch_tables(bool include_handler_code,
                                       size_t max_handler_code_len)
{
    nlohmann::json result;
    result["tables"] = nlohmann::json::array();

    if (init_hexrays_plugin())
    {
        for (size_t i = 0, n = get_func_qty(); i < n; ++i)
        {
            func_t* pfn = getn_func(i);
            if (pfn == nullptr || !ida_utils::is_safely_decompilable(pfn))
                continue;
            hexrays_failure_t hf;
            cfuncptr_t cf = decompile_func(pfn, &hf, DECOMP_NO_WAIT | DECOMP_WARNINGS);
            if (cf == nullptr)
                continue;
            dispatch_ctree_visitor_t vis(&result["tables"], pfn->start_ea,
                                         func_name_for_ea(pfn->start_ea),
                                         include_handler_code,
                                         max_handler_code_len);
            vis.apply_to(&cf->body, nullptr);
            if (!vis.vtable_handlers.empty())
            {
                nlohmann::json t;
                t["type"] = "vtable";
                t["base_ea"] = pfn->start_ea;
                t["function_ea"] = pfn->start_ea;
                t["function_name"] = func_name_for_ea(pfn->start_ea);
                t["size"] = vis.vtable_handlers.size();
                t["handlers"] = std::move(vis.vtable_handlers);
                result["tables"].push_back(std::move(t));
            }
        }
    }

    const int ptr_size = inf_is_64bit() ? 8 : 4;
    for (int si = 0, sn = get_segm_qty(); si < sn; ++si)
    {
        segment_t* seg = getnseg(si);
        if (seg == nullptr || seg->type == SEG_XTRN || (seg->perm & SEGPERM_EXEC) != 0)
            continue;

        std::vector<ea_t> current;
        ea_t current_base = BADADDR;
        for (ea_t ea = seg->start_ea; ea != BADADDR && ea + ptr_size <= seg->end_ea; ea += ptr_size)
        {
            flags64_t f = get_flags(ea);
            ea_t target = BADADDR;
            if (has_value(f))
                target = ptr_size == 8 ? static_cast<ea_t>(get_qword(ea))
                                       : static_cast<ea_t>(get_dword(ea));

            if (is_function_start_ea(target))
            {
                if (current.empty())
                    current_base = ea;
                current.push_back(target);
                continue;
            }

            append_fn_array_table(result["tables"], current_base, current,
                                  include_handler_code, max_handler_code_len);
            current.clear();
            current_base = BADADDR;
        }
        append_fn_array_table(result["tables"], current_base, current,
                              include_handler_code, max_handler_code_len);
    }

    result["table_count"] = result["tables"].size();
    return result;
}

}
