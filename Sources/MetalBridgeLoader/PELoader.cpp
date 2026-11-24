#include "MappedImage.hpp"
#include "PEImage.hpp"
#include <cstdlib>
#include <cstring>
#include <new>

namespace mb {
Image::Image(Bytes input) : file(input) {
    require(u16(file, 0) == 0x5a4d, "missing DOS signature");
    const size_t nt = u32(file, 0x3c);
    require(nt >= 64 && u32(file, nt) == 0x4550, "missing PE signature");
    const auto coff = slice(file, nt + 4, 20);
    info.machine = u16(coff, 0);
    info.sections = u16(coff, 2);
    info.characteristics = u16(coff, 18);
    require(info.sections && info.sections <= 96, "invalid section count");
    auto opt = slice(file, nt + 24, u16(coff, 16));
    info.magic = u16(opt, 0);
    const bool wide = info.magic == 0x20b;
    require(wide || info.magic == 0x10b, "unsupported optional header");
    info.entry_rva = u32(opt, 16);
    info.preferred_base = wide ? u64(opt, 24) : u32(opt, 28);
    info.image_size = u32(opt, 56);
    info.headers_size = u32(opt, 60);
    const size_t directoryOffset = wide ? 112 : 96;
    const size_t count = u32(opt, directoryOffset - 4);
    require(count <= 16, "unsupported directory count");
    for (size_t i = 0; i < count; ++i) {
        dirs[i] = {u32(opt, directoryOffset + i * 8), u32(opt, directoryOffset + i * 8 + 4)};
        const auto [start, size] = dirs[i];
        if (!size)
            continue;
        require(start != 0, "invalid directory address");
        if (i == 4)
            slice(file, start, size); // certificate directory uses file offsets
        else
            require(uint64_t(start) + size <= info.image_size, "directory exceeds image");
    }
    const size_t tableOffset = nt + 24 + opt.size();
    const auto table = slice(file, tableOffset, 40 * info.sections);
    require(info.headers_size >= tableOffset + table.size() && info.headers_size <= file.size() &&
                info.headers_size <= info.image_size,
            "invalid header size");
    for (size_t i = 0; i < table.size(); i += 40) {
        Section s{u32(table, i + 12), u32(table, i + 8), u32(table, i + 20), u32(table, i + 16),
                  u32(table, i + 36)};
        const uint64_t end = uint64_t(s.rva) + std::max(s.size, s.rawSize);
        require(s.rva >= info.headers_size && end <= info.image_size, "invalid section extent");
        if (s.rawSize) {
            require(s.raw >= info.headers_size, "section overlaps headers");
            slice(file, s.raw, s.rawSize);
        }
        for (const auto &prior : sections) {
            require(end <= prior.rva ||
                        s.rva >= uint64_t(prior.rva) + std::max(prior.rawSize, prior.size),
                    "overlapping virtual sections");
        }
        sections.push_back(s);
    }
    require(!info.entry_rva || executableBytes(info.entry_rva), "invalid entry point");
}
Bytes Image::at(uint32_t rva, size_t length) const {
    if (rva < info.headers_size)
        return slice(file.first(info.headers_size), rva, length);
    for (const auto &s : sections) {
        if (rva >= s.rva && rva - s.rva < s.rawSize)
            return slice(slice(file, s.raw, s.rawSize), rva - s.rva, length);
    }
    throw "RVA has no file backing";
}
size_t Image::executableBytes(uint32_t rva) const {
    for (auto &s : sections)
        if ((s.flags & 0x20000000) && rva >= s.rva && rva - s.rva < s.rawSize)
            return s.rawSize - (rva - s.rva);
    return 0;
}
std::string_view Image::name(uint32_t rva) const {
    auto ptr = at(rva, 1).data();
    size_t limit = 0;
    if (rva < info.headers_size)
        limit = info.headers_size - rva;
    for (auto &s : sections)
        if (rva >= s.rva && rva - s.rva < s.rawSize)
            limit = s.rawSize - (rva - s.rva);
    auto end = static_cast<const uint8_t *>(std::memchr(ptr, 0, std::min(limit, size_t(4096))));
    require(end && end != ptr, "invalid import name");
    return {reinterpret_cast<const char *>(ptr), size_t(end - ptr)};
}

// RT_ICON resources contain standalone PNGs or icon DIBs. Prefer pixel area
// first, then color depth. Copy only the winning resource into the ICO.
std::vector<uint8_t> icon(const Image &im) {
    auto d = im.dirs[2];
    if (!d.size)
        return {};
    auto root = im.at(d.rva, d.size);
    size_t budget = 65536;
    auto entries = [&](uint32_t offset) {
        size_t n = size_t(u16(root, offset + 12ull)) + u16(root, offset + 14ull);
        require(n <= budget, "resource traversal limit exceeded");
        budget -= n;
        return slice(root, offset + 16ull, n * 8);
    };
    Bytes best;
    unsigned w = 0, h = 0, depth = 0;
    auto types = entries(0);
    for (size_t t = 0; t < types.size(); t += 8) {
        if (u32(types, t) != 3)
            continue;
        const auto namesOffset = u32(types, t + 4);
        if (!(namesOffset >> 31))
            continue;
        auto names = entries(namesOffset & 0x7fffffff);
        for (size_t n = 0; n < names.size(); n += 8) {
            auto langOffset = u32(names, n + 4);
            if (!(langOffset >> 31))
                continue;
            auto langs = entries(langOffset & 0x7fffffff);
            for (size_t l = 0; l < langs.size(); l += 8) {
                auto dataOffset = u32(langs, l + 4);
                if (dataOffset >> 31)
                    continue;
                auto desc = slice(root, dataOffset, 16);
                const auto length = u32(desc, 4);
                if (length < 40 || length > 16 * 1024 * 1024)
                    continue;
                auto data = im.at(u32(desc, 0), length);
                unsigned iw, ih, bits;
                if (std::memcmp(data.data(), "\x89PNG\r\n\x1a\n", 8) == 0 &&
                    std::memcmp(data.data() + 12, "IHDR", 4) == 0) {
                    auto be = [&](size_t i) {
                        return (uint32_t(data[i]) << 24) | (uint32_t(data[i + 1]) << 16) |
                               (uint32_t(data[i + 2]) << 8) | data[i + 3];
                    };
                    iw = be(16);
                    ih = be(20);
                    constexpr unsigned channels[]{1, 0, 3, 1, 2, 0, 4};
                    bits = data[25] < 7 ? channels[data[25]] * data[24] : 0;
                } else if (u32(data, 0) >= 40 && u32(data, 0) <= length) {
                    iw = u32(data, 4);
                    ih = u32(data, 8) / 2;
                    bits = u16(data, 14);
                } else
                    continue;
                if (!iw || !ih || iw > 256 || ih > 256 || !bits)
                    continue;
                if (iw * ih > w * h || (iw * ih == w * h && bits > depth)) {
                    w = iw;
                    h = ih;
                    depth = bits;
                    best = data;
                }
            }
        }
    }
    if (best.empty())
        return {};
    std::vector<uint8_t> result(22, 0);
    result[2] = 1;
    result[4] = 1;
    result[6] = uint8_t(w);
    result[7] = uint8_t(h);
    result[10] = 1;
    result[12] = uint8_t(depth);
    result[18] = 22;
    for (int i = 0; i < 4; ++i)
        result[14 + i] = uint8_t(best.size() >> (8 * i));
    result.insert(result.end(), best.begin(), best.end());
    return result;
}
} // namespace mb

const char *mb_inspect(const uint8_t *file, size_t length, MBImageInfo *out) {
    if (!out || !file)
        return "missing image";
    try {
        *out = mb::Image({file, length}).info;
        return nullptr;
    } catch (const char *message) {
        return message;
    } catch (const std::bad_alloc &) {
        return "out of memory";
    }
}
uint8_t *mb_copy_icon(const uint8_t *file, size_t length, size_t *size) {
    if (!size)
        return nullptr;
    *size = 0;
    if (!file)
        return nullptr;
    try {
        auto ico = mb::icon(mb::Image({file, length}));
        if (ico.empty())
            return nullptr;
        auto out = static_cast<uint8_t *>(std::malloc(ico.size()));
        if (out) {
            std::memcpy(out, ico.data(), ico.size());
            *size = ico.size();
        }
        return out;
    } catch (...) {
        return nullptr;
    }
}
void mb_free(void *ptr) { std::free(ptr); }

#if defined(__APPLE__) && defined(__aarch64__)
mb::MappedImage::MappedImage(const Image &im, const Bindings &bindings) {
    require(im.info.image_size <= 256 * 1024 * 1024, "native image exceeds mapping limit");
    extent = im.info.image_size;
    auto task = mach_task_self();
    require(mach_vm_allocate(task, &base, extent, VM_FLAGS_ANYWHERE) == KERN_SUCCESS,
            "Mach image allocation failed");
    try {
        auto ptr = reinterpret_cast<uint8_t *>(base);
        std::memcpy(ptr, im.file.data(), im.info.headers_size);
        for (auto &s : im.sections) {
            if (s.rawSize)
                std::memcpy(ptr + s.rva, im.file.data() + s.raw, s.rawSize);
        }
        auto d = im.dirs[5];
        if (d.size) {
            auto blocks = im.at(d.rva, d.size);
            for (size_t off = 0; off < blocks.size();) {
                auto page = u32(blocks, off), length = u32(blocks, off + 4);
                require(length >= 8 && length % 2 == 0, "malformed relocation block");
                auto entries = slice(blocks, off + 8, length - 8);
                for (size_t j = 0; j < entries.size(); j += 2) {
                    auto item = u16(entries, j);
                    if (!(item >> 12))
                        continue;
                    uint64_t target = uint64_t(page) + (item & 0xfff);
                    require((item >> 12) == 10 && target + 8 <= extent,
                            "unsupported native base relocation");
                    auto value = u64({ptr, size_t(extent)}, target) + base - im.info.preferred_base;
                    std::memcpy(ptr + target, &value, 8);
                }
                off += length;
            }
        }
        for (auto [rva, binding] : bindings) {
            require(uint64_t(rva) + sizeof(binding.address) <= extent, "invalid IAT slot");
            std::memcpy(ptr + rva, &binding.address, sizeof(binding.address));
        }
        require(mach_vm_protect(task, base, extent, false, VM_PROT_READ) == KERN_SUCCESS,
                "cannot seal image view");
    } catch (...) {
        mach_vm_deallocate(task, base, extent);
        throw;
    }
}
mb::MappedImage::~MappedImage() { mach_vm_deallocate(mach_task_self(), base, extent); }
#endif
