#pragma once
#include "MetalBridgeLoader.h"
#include <algorithm>
#include <limits>
#include <map>
#include <span>
#include <string_view>
#include <vector>

namespace mb {
using Bytes = std::span<const uint8_t>;
inline void require(bool condition, const char *message) {
    if (!condition)
        throw message;
}
inline Bytes slice(Bytes b, size_t off, size_t n) {
    require(off <= b.size() && n <= b.size() - off, "truncated PE structure");
    return b.subspan(off, n);
}
inline uint16_t u16(Bytes b, size_t i) {
    auto s = slice(b, i, 2);
    return uint16_t(s[0]) | uint16_t(s[1]) << 8;
}
inline uint32_t u32(Bytes b, size_t i) { return uint32_t(u16(b, i)) | uint32_t(u16(b, i + 2)) << 16; }
inline uint64_t u64(Bytes b, size_t i) { return uint64_t(u32(b, i)) | uint64_t(u32(b, i + 4)) << 32; }
struct Section {
    uint32_t rva, size, raw, rawSize, flags;
};
struct Directory {
    uint32_t rva, size;
};
struct Image {
    Bytes file;
    MBImageInfo info{};
    Directory dirs[16]{};
    std::vector<Section> sections;
    explicit Image(Bytes input);
    Bytes at(uint32_t rva, size_t size) const;
    std::string_view name(uint32_t rva) const;
    size_t executableBytes(uint32_t rva) const;
};
using ScalarImport = uint64_t (*)();
struct ImportBinding {
    uintptr_t address;
    ScalarImport scalar;
    void (*setValue)(uint32_t) = nullptr;
};
void *currentTeb();
uint64_t getLastError();
void setLastError(uint32_t value);
using Bindings = std::map<uint32_t, ImportBinding>;
Bindings nativeImports(const Image &image);
} // namespace mb
