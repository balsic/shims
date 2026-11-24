#include <array>
#include <cstdint>
#include <cstring>
#include <new>
#include <pthread.h>
#include <unistd.h>

namespace mb {
namespace {
alignas(16) std::array<uint8_t, 0x800> peb{};
struct alignas(16) ThreadBlock {
    std::array<uint8_t, 0x1800> bytes{};
    void word(size_t index, uintptr_t value) {
        std::memcpy(bytes.data() + index, &value, sizeof(value));
    }
    ThreadBlock() {
        word(0x30, reinterpret_cast<uintptr_t>(bytes.data())); // NT_TIB.Self
        word(0x40, static_cast<uintptr_t>(getpid()));          // CLIENT_ID.UniqueProcess
#ifdef __APPLE__
        uint64_t tid = 0;
        pthread_threadid_np(nullptr, &tid);
        word(0x48, tid);
#endif
        word(0x60, reinterpret_cast<uintptr_t>(peb.data()));
    }
};
pthread_key_t key;
pthread_once_t once = PTHREAD_ONCE_INIT;
int initError;
void initialize() {
    initError = pthread_key_create(&key, [](void *p) { delete static_cast<ThreadBlock *>(p); });
}
} // namespace
void *currentTeb() {
    if (pthread_once(&once, initialize) || initError)
        return nullptr;
    auto block = static_cast<ThreadBlock *>(pthread_getspecific(key));
    if (!block) {
        block = new (std::nothrow) ThreadBlock;
        if (!block || pthread_setspecific(key, block)) {
            delete block;
            return nullptr;
        }
    }
    return block->bytes.data();
}
uint64_t getLastError() {
    auto *teb = static_cast<uint8_t *>(currentTeb());
    uint32_t value = 0;
    if (teb)
        std::memcpy(&value, teb + 0x68, sizeof(value));
    return value;
}
void setLastError(uint32_t value) {
    auto *teb = static_cast<uint8_t *>(currentTeb());
    if (teb)
        std::memcpy(teb + 0x68, &value, sizeof(value));
}
} // namespace mb
