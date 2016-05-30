//---------------------------------------------------------
// For conditions of distribution and use, see
// https://github.com/preshing/cpp11-on-multicore/blob/master/LICENSE
//---------------------------------------------------------

#ifndef __CPP11OM_LWLOCK_H__
#define __CPP11OM_LWLOCK_H__

#include <cassert>
#include <atomic>
#include <random>

#include "cpp11om/sema.h"

namespace cpp11om {

//---------------------------------------------------------
// NonRecursiveLWLock
//---------------------------------------------------------
class NonRecursiveLWLock
{
private:

    std::atomic<uint32_t> m_status;
    DefaultSemaphoreType m_sema;

public:
    NonRecursiveLWLock() : m_status(0) {}
    
    bool try_lock()
    {
        return (m_status.fetch_add(1, std::memory_order_acquire) == 0);
    }


    void lock()
    {
        if (m_status.fetch_add(1, std::memory_order_acquire) > 0)  // Visit the box office
        {
            m_sema.wait();     // Enter the wait queue
        }
    }

    void unlock()
    {
        if (m_status.fetch_sub(1, std::memory_order_release) > 1)  // Visit the box office
        {
            m_sema.signal();   // Release a waiting thread from the queue
        }
    }
};



//---------------------------------------------------------
// LockGuard
//---------------------------------------------------------
template <class LockType>
class LockGuard
{
private:
    LockType& m_lock;

public:
    LockGuard(LockType& lock) : m_lock(lock)
    {
        m_lock.lock();
    }

    ~LockGuard()
    {
        m_lock.unlock();
    }
};

template <class LockType>
class TryLockGuard
{
private:
    LockType& m_lock;
    bool m_locked;
public:
    TryLockGuard(LockType& lock) : m_lock(lock), m_locked(false)
    {
        m_locked = m_lock.try_lock();
    }

    ~TryLockGuard()
    {
        if(m_locked)
          m_lock.unlock();
    }
    bool locked() const {
        return m_locked;
    }
};

}
#endif // __CPP11OM_LWLOCK_H__
