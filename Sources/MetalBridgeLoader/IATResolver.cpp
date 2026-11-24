#include "PEImage.hpp"
#include <chrono>
#include <unistd.h>
#ifdef __APPLE__
#include "NativeShims.h"
#endif

namespace {
uint32_t add(uint32_t start, uint64_t offset) {
    mb::require(offset <= UINT32_MAX - start, "RVA overflow");
    return start + static_cast<uint32_t>(offset);
}
uint64_t processId() { return static_cast<uint64_t>(getpid()); }
uint64_t tickCount() {
#ifdef __APPLE__
    return mb_tick_count();
#else
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
#endif
}
bool equalDll(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ch = a[i];
        if (ch >= 'A' && ch <= 'Z')
            ch = char(ch - 'A' + 'a');
        if (ch != b[i])
            return false;
    }
    return true;
}
mb::ImportBinding bind(std::string_view dll, std::string_view symbol) {
    if (equalDll(dll, "kernel32.dll") || equalDll(dll, "kernelbase.dll")) {
        if (symbol == "GetCurrentProcessId")
            return {reinterpret_cast<uintptr_t>(processId), processId};
        if (symbol == "GetTickCount64")
            return {reinterpret_cast<uintptr_t>(tickCount), tickCount};
        if (symbol == "GetLastError")
            return {reinterpret_cast<uintptr_t>(mb::getLastError), mb::getLastError};
        if (symbol == "SetLastError")
            return {reinterpret_cast<uintptr_t>(mb::setLastError), nullptr, mb::setLastError};
    }
#ifdef __APPLE__
    if (equalDll(dll, "ntdll.dll")) {
        uintptr_t address = mb_nt_address(symbol.data());
        if (address)
            return {address, nullptr};
    }
#endif
    throw "unimplemented Windows import requires Wine DLL fallback";
}
MBDirectoryInfo directories(const mb::Image &im, mb::Bindings *bindings = nullptr) {
    MBDirectoryInfo info{};
    auto imports = im.dirs[1];
    if (imports.size) {
        auto table = im.at(imports.rva, imports.size);
        bool terminated = false;
        uint32_t budget = 1 << 20;
        for (size_t i = 0; i + 20 <= table.size(); i += 20) {
            auto d = table.subspan(i, 20);
            if (std::all_of(d.begin(), d.end(), [](auto v) { return v == 0; })) {
                terminated = true;
                break;
            }
            mb::require(++info.import_modules <= 4096, "excessive import modules");
            auto dll = im.name(mb::u32(d, 12));
            const uint32_t first = mb::u32(d, 16), original = mb::u32(d, 0);
            mb::require(first, "missing IAT");
            unsigned width = im.info.magic == 0x20b ? 8 : 4;
            for (size_t j = 0;; j += width) {
                mb::require(budget-- != 0, "excessive import table");
                auto slot = im.at(add(original ? original : first, j), width);
                auto value = width == 8 ? mb::u64(slot, 0) : mb::u32(slot, 0);
                if (!value)
                    break;
                if (value & (uint64_t(1) << (width * 8 - 1))) {
                    ++info.import_ordinals;
                    mb::require(!bindings, "ordinal import requires Wine DLL fallback");
                } else {
                    mb::require(value <= UINT32_MAX - 2, "invalid import RVA");
                    im.at(uint32_t(value), 2);
                    auto symbol = im.name(uint32_t(value) + 2);
                    if (bindings) {
                        auto rva = add(first, j);
                        im.at(rva, width);
                        mb::require(!(rva % width) && !im.executableBytes(rva) &&
                                        !im.executableBytes(add(rva, width - 1)),
                                    "unsupported native IAT layout");
                        mb::require(bindings->emplace(rva, bind(dll, symbol)).second,
                                    "duplicate IAT slot");
                    }
                    ++info.import_names;
                }
            }
        }
        mb::require(terminated, "unterminated import directory");
    }
    auto exports = im.dirs[0];
    if (exports.size) {
        auto d = im.at(exports.rva, exports.size);
        info.export_slots = mb::u32(d, 20);
        auto names = mb::u32(d, 24);
        mb::require(info.export_slots <= (1 << 20) && names <= (1 << 20), "excessive export table");
        if (info.export_slots)
            im.at(mb::u32(d, 28), 4ull * info.export_slots);
        if (names) {
            auto strings = im.at(mb::u32(d, 32), 4ull * names);
            auto ordinals = im.at(mb::u32(d, 36), 2ull * names);
            for (size_t i = 0; i < names; ++i) {
                im.name(mb::u32(strings, 4 * i));
                mb::require(mb::u16(ordinals, 2 * i) < info.export_slots, "invalid export ordinal");
            }
        }
    }
    auto relocs = im.dirs[5];
    if (relocs.size) {
        auto table = im.at(relocs.rva, relocs.size);
        for (size_t i = 0; i < table.size();) {
            auto page = mb::u32(table, i), length = mb::u32(table, i + 4);
            mb::require(!(page % 4096) && length >= 8 && !(length % 2), "invalid relocation block");
            auto entries = mb::slice(table, i + 8, length - 8);
            for (size_t j = 0; j < entries.size(); j += 2) {
                auto item = mb::u16(entries, j);
                if (!(item >> 12))
                    continue;
                auto target = add(page, item & 0xfff);
                mb::require(target < im.info.image_size, "invalid relocation target");
                if (bindings)
                    mb::require((item >> 12) == 10 && uint64_t(target) + 8 <= im.info.image_size &&
                                    !im.executableBytes(target) && !im.executableBytes(add(target, 7)),
                                "unsupported native base relocation");
                ++info.relocations;
                if ((item >> 12) == 4 && im.info.machine == 0x14c) {
                    mb::slice(entries, j + 2, 2);
                    j += 2; // HIGHADJ has a signed addend
                }
            }
            i += length;
        }
    }
    return info;
}
} // namespace
mb::Bindings mb::nativeImports(const Image &image) {
    Bindings bindings;
    directories(image, &bindings);
    return bindings;
}
const char *mb_directories(const uint8_t *file, size_t length, MBDirectoryInfo *out) {
    if (!file || !out)
        return "missing image";
    try {
        *out = directories(mb::Image({file, length}));
        return nullptr;
    } catch (const char *why) {
        return why;
    } catch (...) {
        return "unable to inspect directories";
    }
}
