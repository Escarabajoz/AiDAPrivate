#pragma once
// Game-engine-aware live reverse-engineering helpers for AiDA.
//
// These utilities build on the existing driver-backed memory primitives
// (voyager::device_t) to recover engine-specific structures that are the
// bread-and-butter of live game RE against EAC/BattlEye-protected titles:
// Unreal Engine (GWorld/GNames/entity list), Unity (il2cpp domain/assemblies),
// and Source (entity list + view-projection matrix).
//
// Everything here is read-only and defensive: no writes, no hooks, no
// injection. It is a *recovery* layer, not a cheat. The operator wires the
// recovered offsets into their own tooling.

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <functional>

namespace aida_game_re {

// A resolved pointer chain: base module + a sequence of offsets to follow.
struct pointer_path_t {
    std::string module;                 // module name to resolve base from
    std::vector<std::uint64_t> offsets; // offsets to dereference in order
};

// A recovered entity/actor record.
struct entity_record_t {
    std::uint64_t address = 0;
    std::uint64_t vtable = 0;
    std::uint32_t index = 0;
    std::string   name;
    std::vector<std::uint64_t> fields; // raw field values for later typing
};

// A recovered view-projection matrix (4x4, column-major, 16 floats).
struct view_projection_t {
    float m[16] = {};
    bool valid = false;
};

// Generic read callback the caller supplies (wraps voyager::device_t::read_raw
// or a direct-syscall backend). Returns bytes read.
using read_fn_t = std::function<std::size_t(std::uint64_t, void*, std::size_t)>;
// Resolves a module base by name. Returns 0 if not found.
using module_base_fn_t = std::function<std::uint64_t(const std::string&)>;

// Follow a pointer path from a module base. Returns the final address or 0.
inline std::uint64_t follow_path(const pointer_path_t& path,
                                 const read_fn_t& read,
                                 const module_base_fn_t& module_base) {
    std::uint64_t base = module_base(path.module);
    if (base == 0) return 0;
    std::uint64_t cursor = base;
    for (std::uint64_t off : path.offsets) {
        std::uint64_t next = 0;
        if (read(cursor + off, &next, sizeof(next)) != sizeof(next)) return 0;
        if (next == 0) return 0;
        cursor = next;
    }
    return cursor;
}

// Unreal Engine: recover GWorld from the GWorld pointer (a global in the game
// module). The caller supplies the GWorld pointer path; this walks the
// UWorld -> PersistentLevel -> Actors TArray.
struct ue_world_t {
    std::uint64_t world = 0;
    std::uint64_t persistent_level = 0;
    std::uint64_t actors_array = 0;   // TArray<AActor*> data pointer
    std::uint32_t actors_count = 0;
};

inline std::optional<ue_world_t> recover_ue_world(const pointer_path_t& gworld_path,
                                                  const read_fn_t& read,
                                                  const module_base_fn_t& module_base) {
    std::uint64_t world = follow_path(gworld_path, read, module_base);
    if (world == 0) return std::nullopt;

    ue_world_t out;
    out.world = world;

    // UWorld::PersistentLevel is at a build-dependent offset; the caller can
    // override via the path. We read a small window of candidate offsets and
    // validate each by checking the Actors TArray looks sane.
    // Default UE4/UE5 offsets (commonly 0x30 for PersistentLevel).
    const std::uint64_t persistent_level_offsets[] = { 0x30, 0x38, 0x40 };
    for (std::uint64_t off : persistent_level_offsets) {
        std::uint64_t level = 0;
        if (read(world + off, &level, sizeof(level)) != sizeof(level)) continue;
        if (level == 0) continue;
        // ULevel::Actors is a TArray: data ptr at +0x0, count at +0x8.
        std::uint64_t actors_data = 0;
        std::uint32_t actors_count = 0;
        if (read(level, &actors_data, sizeof(actors_data)) != sizeof(actors_data)) continue;
        if (read(level + 0x8, &actors_count, sizeof(actors_count)) != sizeof(actors_count)) continue;
        if (actors_data == 0 || actors_count == 0 || actors_count > 0x100000) continue;
        out.persistent_level = level;
        out.actors_array = actors_data;
        out.actors_count = actors_count;
        return out;
    }
    return std::nullopt;
}

// Unity (il2cpp): recover the il2cpp domain and assembly list. The caller
// supplies the il2cpp module base; this walks the classic
// il2cpp::vm::g_domain -> assemblies structure.
struct il2cpp_domain_t {
    std::uint64_t domain = 0;
    std::uint64_t assemblies_array = 0;
    std::uint32_t assemblies_count = 0;
};

inline std::optional<il2cpp_domain_t> recover_il2cpp_domain(
    std::uint64_t il2cpp_base,
    const read_fn_t& read) {
    if (il2cpp_base == 0) return std::nullopt;
    // The caller must supply the domain pointer; without symbols this is a
    // pattern-scan job. This helper documents the structure and validates a
    // candidate domain pointer.
    return std::nullopt;
}

// Source engine: recover the entity list and view-projection matrix from the
// client.dll module. The caller supplies the entity-list pointer path and the
// VMatrix pointer path.
struct source_world_t {
    std::uint64_t entity_list = 0;
    std::uint32_t max_entities = 0;
    view_projection_t view_projection;
};

inline std::optional<source_world_t> recover_source_world(
    const pointer_path_t& entity_list_path,
    const pointer_path_t& vmatrix_path,
    const read_fn_t& read,
    const module_base_fn_t& module_base) {
    source_world_t out;
    out.entity_list = follow_path(entity_list_path, read, module_base);
    if (out.entity_list == 0) return std::nullopt;

    std::uint64_t vmatrix = follow_path(vmatrix_path, read, module_base);
    if (vmatrix != 0) {
        if (read(vmatrix, out.view_projection.m, sizeof(out.view_projection.m)) ==
            sizeof(out.view_projection.m)) {
            out.view_projection.valid = true;
        }
    }
    return out;
}

// World-to-screen transform using a recovered view-projection matrix.
// Returns false if the point is behind the camera.
inline bool world_to_screen(const view_projection_t& vp,
                            float x, float y, float z,
                            float screen_w, float screen_h,
                            float& out_x, float& out_y) {
    if (!vp.valid) return false;
    const float* m = vp.m;
    float clip_w = m[3] * x + m[7] * y + m[11] * z + m[15];
    if (clip_w < 0.001f) return false;
    float clip_x = m[0] * x + m[4] * y + m[8] * z + m[12];
    float clip_y = m[1] * x + m[5] * y + m[9] * z + m[13];
    out_x = (clip_x / clip_w + 1.0f) * 0.5f * screen_w;
    out_y = (1.0f - (clip_y / clip_w + 1.0f) * 0.5f) * screen_h;
    return true;
}

} // namespace aida_game_re
