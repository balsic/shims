#include "MappedImage.hpp"
#include "PEImage.hpp"
#include <array>
#include <cstring>
#include <mutex>
#if defined(__APPLE__) && defined(__aarch64__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace mb {
void checkNativeMachine(const MBImageInfo &);
void *currentTeb();
// The initial ABI admits leaf functions with defined scalar results only.
// No register other than a previously defined volatile register may be read.
struct Entry {
    Bytes code;
    uint32_t rva;
    uint32_t targetSlot = 0;
    uint32_t argument = 0;
    bool callback = false;
};
Entry entry(const Image &im, const Bindings &bindings, uint32_t rva, bool callback) {
    require(rva && !(rva % 4), "invalid ARM64 entry point");
    auto code = im.at(rva, std::min(size_t(1024), im.executableBytes(rva)));
    // Standard ARM64 import tail thunk: ADRP Xn, page; LDR Xm, [Xn,#off]; BR Xm.
    size_t start = 0;
    if (callback && code.size() >= 16 && (u32(code, 0) & 0xffe0001f) == 0x52800000)
        start = 4;
    if (code.size() >= start + 12) {
        auto adrp = u32(code, start), load = u32(code, start + 4), branch = u32(code, start + 8);
        if ((adrp & 0x9f000000) == 0x90000000 && (load & 0xffc00000) == 0xf9400000 &&
            (branch & 0xfffffc1f) == 0xd61f0000 && (adrp & 31) == ((load >> 5) & 31) &&
            (load & 31) == ((branch >> 5) & 31) && (adrp & 31) < 18 && (load & 31) < 18) {
            int64_t pages = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2);
            if (pages & (1 << 20))
                pages -= 1 << 21;
            int64_t slot =
                int64_t((rva + start) & ~uint64_t(4095)) + pages * 4096 + ((load >> 10) & 4095) * 8;
            require(slot > 0 && slot <= UINT32_MAX && bindings.contains(uint32_t(slot)),
                    "entry thunk does not reference a native IAT slot");
            const auto binding = bindings.at(uint32_t(slot));
            require(!start || ((adrp & 31) != 0 && (load & 31) != 0), "thunk overwrites its argument");
            require(start ? binding.setValue != nullptr : binding.scalar != nullptr,
                    "entry thunk requires a Windows call frame");
            return {code.first(start + 12), rva, uint32_t(slot),
                    start ? (u32(code, 0) >> 5) & 0xffff : 0, callback};
        }
    }
    std::array<bool, 16> defined{};
    for (size_t offset = 0; offset + 4 <= code.size(); offset += 4) {
        auto op = u32(code, offset);
        if (op == 0xd65f03c0) {
            require(callback || defined[0], "entry returns an undefined result");
            return {code.first(offset + 4), rva, 0, 0, callback};
        }
        if (op == 0xd503201f || op == 0xd503245f)
            continue; // NOP, BTI c
        const unsigned rd = op & 31, rn = (op >> 5) & 31;
        require(rd < 16, "entry uses a reserved or nonvolatile register");
        auto kind = op & 0x7f800000;
        if ((op & ~31u) == 0xf9402240 || (op & ~31u) == 0xf9402640) {
            // LDR Xd,[X18,#0x40/0x48]: lower CLIENT_ID reads through the shadow TEB.
        } else if (kind == 0x52800000 || kind == 0x12800000 || kind == 0x72800000) {
            require((op >> 31) || ((op >> 21) & 3) < 2, "invalid wide move");
            if (kind == 0x72800000)
                require(defined[rd], "MOVK reads undefined register");
        } else if ((op & 0x3f800000) == 0x11000000) {
            require(rn < 16 && defined[rn], "arithmetic reads undefined register");
        } else
            throw "instruction requires a full Windows execution backend";
        defined[rd] = true;
    }
    throw "entry exceeds the native leaf contract";
}
std::vector<Entry> plan(const Image &image, const Bindings &bindings) {
    checkNativeMachine(image.info);
    require(image.info.image_size <= 256 * 1024 * 1024, "native image exceeds mapping limit");
    for (unsigned i : {10u, 11u, 13u, 14u})
        require(!image.dirs[i].rva && !image.dirs[i].size, "image requires Windows runtime services");
    std::vector<Entry> result;
    auto tls = image.dirs[9];
    if (tls.rva || tls.size) {
        require(tls.size >= 40, "invalid TLS directory");
        auto data = image.at(tls.rva, 40);
        require(u64(data, 0) == u64(data, 8) && !u32(data, 32), "static TLS storage requires Wine");
        auto asRva = [&](uint64_t va) {
            require(va >= image.info.preferred_base &&
                        va - image.info.preferred_base < image.info.image_size,
                    "TLS address outside image");
            return uint32_t(va - image.info.preferred_base);
        };
        if (auto index = u64(data, 16))
            require(u32(image.at(asRva(index), 4), 0) == 0, "nonzero TLS slot requires Wine");
        require(u64(data, 24), "TLS directory has no callback list");
        uint64_t list = asRva(u64(data, 24));
        for (;;) {
            require(result.size() < 128 && list <= UINT32_MAX, "unterminated TLS callback list");
            auto va = u64(image.at(uint32_t(list), 8), 0);
            if (!va)
                break;
            result.push_back(entry(image, bindings, asRva(va), true));
            list += 8;
        }
    }
    result.push_back(entry(image, bindings, image.info.entry_rva, false));
    return result;
}
} // namespace mb
const char *mb_native_probe(const uint8_t *file, size_t length) {
    if (!file)
        return "missing image";
    try {
        mb::Image image({file, length});
        mb::checkNativeMachine(image.info);
        mb::plan(image, mb::nativeImports(image));
        return nullptr;
    } catch (const char *why) {
        return why;
    } catch (...) {
        return "unable to prepare native image";
    }
}
#if defined(__APPLE__) && defined(__aarch64__)
namespace {
int32_t execute(const mb::MappedImage &mapped, const mb::Entry &plan, const mb::Bindings &bindings) {
    auto source = mapped.bytes(plan.rva, plan.code.size());
    mb::require(std::equal(source.begin(), source.end(), plan.code.begin()),
                "relocated entry is unsupported");
    if (plan.targetSlot) {
        auto binding = bindings.at(plan.targetSlot);
        auto slot = mapped.bytes(plan.targetSlot, sizeof(uintptr_t));
        mb::require(mb::u64(slot, 0) == binding.address, "invalid native binding");
        if (binding.setValue) {
            binding.setValue(plan.argument);
            return 0;
        }
        return static_cast<int32_t>(binding.scalar());
    }
    auto teb = static_cast<const uint8_t *>(mb::currentTeb());
    mb::require(teb, "cannot allocate thread environment");
    std::vector<uint32_t> instructions;
    for (size_t offset = 0; offset < source.size(); offset += 4) {
        auto op = mb::u32(source, offset);
        if ((op & ~31u) == 0xf9402240 || (op & ~31u) == 0xf9402640) {
            const auto value = mb::u64({teb, 0x1800}, ((op >> 10) & 4095) * 8);
            for (unsigned i = 0; i < 4; ++i)
                instructions.push_back((i ? 0xf2800000u : 0xd2800000u) | (i << 21) |
                                       (uint32_t((value >> (16 * i)) & 0xffff) << 5) | (op & 31));
        } else
            instructions.push_back(op);
    }
    mb::require(pthread_jit_write_protect_supported_np(), "JIT write protection unavailable");
    static std::mutex jitLock;
    std::lock_guard guard(jitLock);
    static const auto size = static_cast<size_t>(getpagesize());
    static void *memory =
        mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    mb::require(memory != MAP_FAILED, "MAP_JIT failed; check host code-signing entitlements");
    const size_t length = instructions.size() * sizeof(uint32_t);
    mb::require(length <= size, "translated entry exceeds JIT page");
    pthread_jit_write_protect_np(0);
    std::memcpy(memory, instructions.data(), length);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(memory, length);
    if (plan.callback) {
        using TLSCallback = void(__attribute__((ms_abi)) *)(const void *, uint32_t, void *);
        reinterpret_cast<TLSCallback>(memory)(mapped.bytes(0, 1).data(), 1, nullptr);
        return 0;
    }
    return reinterpret_cast<int32_t (*)()>(memory)();
}
} // namespace
#endif
const char *mb_native_run(const uint8_t *file, size_t length, int32_t *status) {
    if (!file || !length || !status)
        return "missing image or result";
#if defined(__APPLE__) && defined(__aarch64__)
    try {
        const auto image = mb::Image({file, length});
        const auto bindings = mb::nativeImports(image);
        const auto steps = mb::plan(image, bindings);
        mb::MappedImage mapped(image, bindings);
        mb::require(mb::currentTeb(), "cannot allocate thread environment");
        mb::setLastError(0);
        for (const auto &step : steps)
            *status = execute(mapped, step, bindings);
        return nullptr;
    } catch (const char *why) {
        return why;
    } catch (...) {
        return "native image preparation failed";
    }
#else
    return "native execution requires Apple Silicon macOS";
#endif
}
