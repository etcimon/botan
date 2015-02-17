/**
* Semaphore implementation for basefilt.d
* 
* Copyright:
* (C) 2014-2015 Jack Lloyd
* (C) 2014-2015 Etienne Cimon
*
* License:
* Botan is released under the Simplified BSD License (see LICENSE.md)
*/
module botan.utils.semaphore;

import core.sync.mutex;
import core.sync.condition;

class Semaphore
{
public:
    this(int value = 0)
    {
        m_value = value;
        m_wakeups = 0;
        m_mutex = new Mutex;
        m_cond = new Condition(m_mutex);
    }
    
    void acquire()
    {
        synchronized(m_mutex) {
            --m_value;
            if(m_value < 0)
            {
                m_cond.wait();
                --m_wakeups;
            }
        }
    }
    
    void release(size_t n = 1)
    {
        for(size_t i = 0; i != n; ++i)
        {
            synchronized(m_mutex) {
            
                ++m_value;
                
                if(m_value <= 0)
                {
                    ++m_wakeups;
                    m_cond.notify();
                }
            }
        }
    }
    
private:
    int m_value;
    int m_wakeups;
    Mutex m_mutex;
    Condition m_cond;
}