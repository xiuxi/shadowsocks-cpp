#include <iostream>
#include <string>
#include <unistd.h>
#include <assert.h>
#include "lru_cache.hpp"

int main()
{
    LRUCache<std::string, int> lru(0.3);
    lru.set("a", 1);
    assert(lru.get("a") == 1);
    usleep(400000);
    lru.sweep();
    assert(!lru.exist("a"));

    lru.set("a", 2);
    lru.set("b", 3);
    usleep(200000);
    lru.sweep();
    assert(lru.get("a") == 2);
    assert(lru.get("b") == 3);
    
    usleep(200000);
    lru.sweep();
    lru.get("b");
    usleep(200000);
    lru.sweep();
    assert(!lru.exist("a"));
    assert(lru.get("b") == 3);
    
    usleep(500000);
    lru.sweep();
    assert(!lru.exist("a"));
    assert(!lru.exist("b"));
    
    bool close_cb_called = false;

    auto close_cb = [&](int t)
    {
        assert(!close_cb_called);
        close_cb_called = true;
    };
    
    lru = LRUCache<std::string, int>(0.1, close_cb);
    lru.set("s", 1);
    lru.set("t", 1);
    lru.get("s");
    usleep(100000);
    lru.get("s");
    usleep(300000);
    lru.sweep();
    
}