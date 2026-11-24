#include "PEImage.hpp"
#include <array>

namespace mb {
void checkNativeMachine(const MBImageInfo &info) {
    if (info.machine == 0x8664 || info.machine == 0x14c)
        throw "x86 translation requires the Wine 11/FEX backend";
    require(info.machine == 0xaa64 && info.magic == 0x20b, "requires an ARM64 PE32+ image");
    require((info.characteristics & 0x2002) == 2, "requires an executable image");
}
} // namespace mb

const char *mb_fex_validate(uint16_t guest, const uint8_t *dll, size_t length) {
    if (!dll)
        return "missing FEX CPU module";
    try {
        mb::require(guest == 0x14c || guest == 0x8664, "invalid FEX guest architecture");
        mb::Image module({dll, length});
        mb::require(module.info.magic == 0x20b && (module.info.characteristics & 0x2000),
                    "FEX CPU module must be a PE32+ DLL");
        // The linked ARM64EC module carries an AMD64 COFF tag by design.
        mb::require(guest == 0x14c ? module.info.machine == 0xaa64
                                   : (module.info.machine == 0x8664 || module.info.machine == 0xa641),
                    "wrong FEX module architecture");
        const std::array<std::string_view, 4> required =
            guest == 0x14c ? std::array<std::string_view, 4>{"BTCpuProcessInit", "BTCpuThreadInit",
                                                             "BTCpuSimulate", "BTCpuGetContext"}
                           : std::array<std::string_view, 4>{"ProcessInit", "ThreadInit",
                                                             "BeginSimulation", "ExitToX64"};
        auto exports = module.dirs[0];
        auto d = module.at(exports.rva, exports.size);
        auto slots = mb::u32(d, 20), count = mb::u32(d, 24);
        mb::require(count <= 65536 && slots <= 65536, "oversized FEX export table");
        auto functions = module.at(mb::u32(d, 28), size_t(slots) * 4);
        auto names = module.at(mb::u32(d, 32), size_t(count) * 4);
        auto ordinals = module.at(mb::u32(d, 36), size_t(count) * 2);
        unsigned found = 0;
        for (size_t i = 0; i < count; ++i) {
            auto name = module.name(mb::u32(names, 4 * i));
            auto match = std::find(required.begin(), required.end(), name);
            if (match == required.end())
                continue;
            auto ordinal = mb::u16(ordinals, 2 * i);
            mb::require(ordinal < slots && module.executableBytes(mb::u32(functions, 4 * ordinal)),
                        "invalid FEX entry point");
            found |= 1u << (match - required.begin());
        }
        mb::require(found == 15, "missing required Wine/FEX CPU interface");
        return nullptr;
    } catch (const char *why) {
        return why;
    } catch (...) {
        return "unable to inspect FEX CPU module";
    }
}
