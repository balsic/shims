#include "NativeShims.h"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace {
struct Waiter {
    std::condition_variable changed;
    bool granted = false;
};
struct Event {
    const bool manual;
    bool signaled;
    std::mutex lock;
    std::list<Waiter *> waiting;
    Event(bool m, bool s) : manual(m), signaled(s) {}
    // Called with lock held. A reset after a set cannot revoke an already
    // satisfied wait, even if its thread has not been scheduled yet.
    void set() {
        signaled = manual || waiting.empty();
        while (!waiting.empty()) {
            auto *waiter = waiting.front();
            waiting.pop_front();
            waiter->granted = true;
            waiter->changed.notify_one();
            if (!manual)
                break;
        }
    }
};
std::mutex tableLock;
std::unordered_map<uint64_t, std::shared_ptr<Event>> events;
uint64_t next = 1;
std::shared_ptr<Event> lookup(uint64_t id) {
    std::lock_guard guard(tableLock);
    auto it = events.find(id);
    return it == events.end() ? nullptr : it->second;
}
} // namespace
uint64_t mb_tick_count() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
uint64_t mb_event_create(bool manual, bool initial) {
    try {
        std::lock_guard guard(tableLock);
        if (!next)
            return 0;
        events.emplace(next, std::make_shared<Event>(manual, initial));
        return next++;
    } catch (...) {
        return 0;
    }
}
bool mb_event_set(uint64_t id) {
    auto e = lookup(id);
    if (!e)
        return false;
    std::lock_guard guard(e->lock);
    e->set();
    return true;
}
bool mb_event_reset(uint64_t id) {
    auto e = lookup(id);
    if (!e)
        return false;
    std::lock_guard guard(e->lock);
    e->signaled = false;
    return true;
}
int mb_event_wait(uint64_t id, int64_t timeout) {
    auto e = lookup(id);
    if (!e || timeout < -1)
        return -1;
    std::unique_lock guard(e->lock);
    if (e->signaled) {
        if (!e->manual)
            e->signaled = false;
        return 0;
    }
    if (!timeout)
        return 1;
    Waiter waiter;
    try {
        e->waiting.push_back(&waiter);
    } catch (...) {
        return -1;
    }
    auto ready = [&] { return waiter.granted; };
    if (timeout == -1)
        waiter.changed.wait(guard, ready);
    else if (!waiter.changed.wait_for(guard, std::chrono::nanoseconds(timeout), ready)) {
        e->waiting.remove(&waiter);
        return 1;
    }
    return 0;
}
bool mb_event_close(uint64_t id) {
    std::lock_guard guard(tableLock);
    return events.erase(id) != 0;
}

#ifdef __APPLE__
#include <cstring>
#include <limits>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <string_view>
#include <sys/sysctl.h>
#include <unistd.h>

namespace {
using Status = int32_t;
constexpr Status ok = 0, invalid = static_cast<Status>(0xc000000d),
                 badHandle = static_cast<Status>(0xc0000008),
                 unsupported = static_cast<Status>(0xc00000bb),
                 noMemory = static_cast<Status>(0xc0000017), mismatch = static_cast<Status>(0xc0000004);
#define WINCALL __attribute__((ms_abi))
// Data allocations in the current process. Never pass a guest-supplied task port to Mach.
std::mutex vmLock;
std::unordered_map<uintptr_t, size_t> allocations;
Status WINCALL NtAllocateVirtualMemory(uintptr_t process, void **base, uintptr_t zeroBits,
                                       size_t *length, uint32_t type, uint32_t protection) {
    if (process != UINTPTR_MAX)
        return badHandle;
    if (!base || !length || !*length)
        return invalid;
    if (*base || zeroBits || type != 0x3000 || (protection != 2 && protection != 4))
        return unsupported;
    const auto page = static_cast<size_t>(getpagesize());
    if (*length > SIZE_MAX - page + 1)
        return invalid;
    const auto extent = (*length + page - 1) & ~(page - 1);
    mach_vm_address_t address = 0;
    if (mach_vm_allocate(mach_task_self(), &address, extent, VM_FLAGS_ANYWHERE) != KERN_SUCCESS)
        return noMemory;
    if (mach_vm_protect(mach_task_self(), address, extent, true,
                        VM_PROT_READ | (protection == 4 ? VM_PROT_WRITE : 0)) != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), address, extent);
        return unsupported;
    }
    try {
        std::lock_guard guard(vmLock);
        allocations.emplace(address, extent);
    } catch (...) {
        mach_vm_deallocate(mach_task_self(), address, extent);
        return noMemory;
    }
    *base = reinterpret_cast<void *>(address);
    *length = extent;
    return ok;
}
Status WINCALL NtFreeVirtualMemory(uintptr_t process, void **base, size_t *length, uint32_t type) {
    if (process != UINTPTR_MAX)
        return badHandle;
    if (!base || !length)
        return invalid;
    if (type != 0x8000 || *length)
        return unsupported;
    std::lock_guard guard(vmLock);
    const auto address = reinterpret_cast<uintptr_t>(*base);
    auto it = allocations.find(address);
    if (it == allocations.end())
        return invalid;
    if (mach_vm_deallocate(mach_task_self(), address, it->second) != KERN_SUCCESS)
        return invalid;
    *length = it->second;
    *base = nullptr;
    allocations.erase(it);
    return ok;
}
Status WINCALL NtCreateEvent(uint64_t *out, uint32_t, void *attributes, uint32_t type, uint8_t initial) {
    if (!out || type > 1)
        return invalid;
    if (attributes)
        return unsupported;
    *out = mb_event_create(type == 0, initial != 0);
    return *out ? ok : noMemory;
}
Status WINCALL NtSetEvent(uint64_t handle, int32_t *previous) {
    auto e = lookup(handle);
    if (!e)
        return badHandle;
    std::lock_guard guard(e->lock);
    if (previous)
        *previous = e->signaled;
    e->set();
    return ok;
}
Status WINCALL NtWaitForSingleObject(uint64_t handle, uint8_t alertable, const int64_t *timeout) {
    if (alertable)
        return unsupported;
    int64_t ns = -1;
    if (timeout) {
        if (*timeout > 0 || *timeout < -INT64_MAX / 100)
            return unsupported;
        ns = -*timeout * 100;
    }
    const auto result = mb_event_wait(handle, ns);
    return result == 0 ? ok : result == 1 ? 0x102 : badHandle;
}
Status WINCALL NtClose(uint64_t handle) { return mb_event_close(handle) ? ok : badHandle; }

struct CriticalSection {
    void *debug;
    int32_t lockCount, recursion;
    uintptr_t owner;
    pthread_mutex_t *mutex;
    uintptr_t spin;
};
static_assert(sizeof(CriticalSection) == 40);
Status WINCALL RtlInitializeCriticalSection(CriticalSection *cs) {
    if (!cs)
        return invalid;
    std::unique_ptr<pthread_mutex_t> m(new (std::nothrow) pthread_mutex_t);
    if (!m)
        return noMemory;
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr))
        return noMemory;
    auto err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (!err)
        err = pthread_mutex_init(m.get(), &attr);
    pthread_mutexattr_destroy(&attr);
    if (err)
        return noMemory;
    *cs = {nullptr, -1, 0, 0, m.release(), 0};
    return ok;
}
Status WINCALL RtlEnterCriticalSection(CriticalSection *cs) {
    if (!cs || !cs->mutex || pthread_mutex_lock(cs->mutex))
        return invalid;
    uint64_t tid = 0;
    pthread_threadid_np(nullptr, &tid);
    cs->owner = tid;
    ++cs->recursion;
    ++cs->lockCount;
    return ok;
}
Status WINCALL RtlLeaveCriticalSection(CriticalSection *cs) {
    if (!cs || !cs->mutex)
        return invalid;
    uint64_t tid = 0;
    pthread_threadid_np(nullptr, &tid);
    if (cs->owner != tid || cs->recursion <= 0)
        return invalid;
    if (--cs->recursion == 0)
        cs->owner = 0;
    --cs->lockCount;
    return pthread_mutex_unlock(cs->mutex) == 0 ? ok : invalid;
}
Status WINCALL RtlDeleteCriticalSection(CriticalSection *cs) {
    if (!cs || !cs->mutex || pthread_mutex_destroy(cs->mutex))
        return invalid;
    delete cs->mutex;
    *cs = {};
    return ok;
}
Status WINCALL NtQuerySystemInformation(uint32_t kind, void *buffer, uint32_t length,
                                        uint32_t *required) {
    if (kind != 0)
        return unsupported; // SystemBasicInformation
    struct Basic {
        uint32_t reserved, timerResolution, pageSize, pages, lowest, highest, granularity;
        uintptr_t minimum, maximum, affinity;
        uint8_t processors;
    };
    static_assert(sizeof(Basic) == 64);
    if (required)
        *required = sizeof(Basic);
    if (!buffer || length < sizeof(Basic))
        return mismatch;
    Basic b{};
    b.pageSize = getpagesize();
    uint64_t memory = 0;
    size_t size = sizeof(memory);
    if (sysctlbyname("hw.memsize", &memory, &size, nullptr, 0))
        return unsupported;
    b.pages = uint32_t(std::min<uint64_t>(memory / b.pageSize, UINT32_MAX));
    b.highest = b.pages ? b.pages - 1 : 0;
    b.granularity = 65536;
    b.timerResolution = 10000;
    b.minimum = 65536;
    b.maximum = 0x0000ffffffffffffull;
    b.processors = uint8_t(std::clamp<long>(sysconf(_SC_NPROCESSORS_ONLN), 1, 64));
    b.affinity = UINT64_MAX >> (64 - b.processors);
    std::memcpy(buffer, &b, sizeof(b));
    return ok;
}
} // namespace
uintptr_t mb_nt_address(const char *symbol) {
    if (!symbol)
        return 0;
    const std::string_view name(symbol);
#define MB_EXPORT(fn)                                                                                   \
    if (name == #fn)                                                                                    \
    return reinterpret_cast<uintptr_t>(&fn)
    MB_EXPORT(NtAllocateVirtualMemory);
    MB_EXPORT(NtFreeVirtualMemory);
    MB_EXPORT(NtCreateEvent);
    MB_EXPORT(NtSetEvent);
    MB_EXPORT(NtWaitForSingleObject);
    MB_EXPORT(NtClose);
    MB_EXPORT(NtQuerySystemInformation);
    MB_EXPORT(RtlInitializeCriticalSection);
    MB_EXPORT(RtlEnterCriticalSection);
    MB_EXPORT(RtlLeaveCriticalSection);
    MB_EXPORT(RtlDeleteCriticalSection);
#undef MB_EXPORT
    return 0;
}
#endif
