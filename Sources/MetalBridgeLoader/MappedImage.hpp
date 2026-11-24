#pragma once
#include "PEImage.hpp"
#if defined(__APPLE__) && defined(__aarch64__)
#include <mach/mach.h>
#include <mach/mach_vm.h>

namespace mb {
// A private, non-executable image view. Only the admitted entry block enters
// the process's write-protected JIT page.
class MappedImage {
    mach_vm_address_t base = 0;
    mach_vm_size_t extent = 0;

  public:
    explicit MappedImage(const Image &image, const Bindings &bindings);
    MappedImage(const MappedImage &) = delete;
    MappedImage &operator=(const MappedImage &) = delete;
    ~MappedImage();
    Bytes bytes(uint32_t rva, size_t size) const {
        return slice({reinterpret_cast<const uint8_t *>(base), size_t(extent)}, rva, size);
    }
};
} // namespace mb
#endif
