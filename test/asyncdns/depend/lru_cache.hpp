#ifndef LRU_CACHE_HPP
#define LRU_CACHE_HPP

#include <vector>
#include <chrono>
#include <unordered_set>
#include <deque>
#include <functional>
#include <string>
#include <unordered_map>

//Key Value must have equal comparison
template<class Key, class Value, class Value_Hash = std::hash<Value>, class Key_Hash = std::hash<Key>> class LRUCache
{
public:
    LRUCache() = default;
    ~LRUCache() = default;
    LRUCache(double timeout, std::function<void(Value&)> close_callback = nullptr)
    {
        _timeout = timeout;
        _close_callback = close_callback; 
    }

    //LRUCache(const LRUCache<class Key, class Value> &lru) = delete;
    //LRUCache& operator =(const LRUCache<class Key, class Value> &lru) = delete;

    bool exist(const Key &key) const
    {
        return _store.find(key) != _store.end(); 
    }

    Value& get(const Key &key, Value &value)
    {
        if (!exist(key))
            return value;

        return get(key);
    }
    
    Value& get(const Key &key)
    {
        double now = _now();
        _keys_to_last_time[key] = now;
        _time_to_keys[now].push_back(key);
        _last_visits.push_back(now);
 
        return _store[key];
    }
    
    void set(const Key &key, const Value &value)
    {
        double now = _now();
        _keys_to_last_time[key] = now;
        _store[key] = value;
        _time_to_keys[now].push_back(key);
        _last_visits.push_back(now);
    }

    void sweep()
    {
        double now = _now();
        
        int c = 0;
        while (_last_visits.size() > 0)
        {
            auto least = _last_visits[0]; 
            if (now - least <= _timeout)
                break;
                
            _last_visits.pop_front();
            for (auto &key : _time_to_keys[least])
            {
                if (_store.find(key) != _store.end())
                {
                    if (now - _keys_to_last_time[key] >= _timeout)
                    {
                        if (_close_callback)
                        { 
                            auto value = _store[key];
                            auto it = _closed_values.find(value);
                            if (it == _closed_values.end())
                            {
                                _close_callback(value);
                                _closed_values.insert(value);
                            }
                        }
                                
                        _store.erase(key);
                        _keys_to_last_time.erase(key);
                        c += 1;
                    }
                }
            }
            _time_to_keys.erase(least);
        }
        if (c)
            _closed_values.clear();
    }

private:
    double _timeout;
    std::function<void(Value&)> _close_callback;
    std::unordered_map<Key, Value, Key_Hash> _store;
    std::unordered_map<double, std::vector<Key>> _time_to_keys;
    std::unordered_map<Key, double, Key_Hash> _keys_to_last_time;
    std::deque<double> _last_visits;
    std::unordered_set<Value, Value_Hash> _closed_values;
    
    double _now() 
    {
        static std::chrono::system_clock::time_point tp_epoch;
        std::chrono::system_clock::time_point tp_now = std::chrono::system_clock::now();
        std::chrono::duration<double> now_diff = tp_now - tp_epoch;
        return now_diff.count();
    }
};

#endif