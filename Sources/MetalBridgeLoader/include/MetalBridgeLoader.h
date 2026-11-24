#ifndef METAL_BRIDGE_LOADER_H
#define METAL_BRIDGE_LOADER_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint16_t machine, magic, sections, characteristics;
    uint32_t entry_rva, image_size, headers_size;
    uint64_t preferred_base;
} MBImageInfo;

// Returns NULL on success, or a static diagnostic. Input remains caller-owned.
const char *mb_inspect(const uint8_t *file, size_t length, MBImageInfo *info);
// Returns a complete single-image ICO. Release the returned data with mb_free.
uint8_t *mb_copy_icon(const uint8_t *file, size_t length, size_t *icon_length);
void mb_free(void *memory);
typedef struct {
    uint32_t import_modules, import_names, import_ordinals, export_slots, relocations;
} MBDirectoryInfo;
const char *mb_directories(const uint8_t *file, size_t length, MBDirectoryInfo *info);
// A successful probe admits only the checked native ARM64 entry contract.
const char *mb_native_probe(const uint8_t *file, size_t length);
const char *mb_native_run(const uint8_t *file, size_t length, int32_t *exit_code);
// Validate the Wine CPU module ABI used by the selected guest architecture.
const char *mb_fex_validate(uint16_t guest_machine, const uint8_t *dll, size_t length);
#ifdef __cplusplus
}
#endif
#endif
