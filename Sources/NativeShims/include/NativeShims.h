#ifndef METAL_BRIDGE_SHIMS_H
#define METAL_BRIDGE_SHIMS_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
bool mb_metal3_available(void);
bool mb_metal4_available(void);
double mb_main_display_scale(void);
unsigned mb_connected_controllers(void);
// Main-thread presentation diagnostic. Returns a static diagnostic on failure.
const char *mb_present_window(void);
uint64_t mb_tick_count(void);
// Opaque event handles. Manual reset wakes every waiter until reset.
uint64_t mb_event_create(bool manual, bool signaled);
bool mb_event_set(uint64_t handle);
bool mb_event_reset(uint64_t handle);
// 0 = signaled, 1 = timed out, -1 = invalid handle or timeout.
int mb_event_wait(uint64_t handle, int64_t relative_nanoseconds);
bool mb_event_close(uint64_t handle);
#ifdef __APPLE__
uintptr_t mb_nt_address(const char *symbol);
#endif
#ifdef __cplusplus
}
#endif
#endif
