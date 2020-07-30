#pragma once

#include <tuple>
#include <iostream>

#include <stdlib.h>

#include "internal/config.h"


NS_EVLTLS_START

typedef void  (*free_func)(void*);
typedef void* (*realloc_func)(void*, size_t new_size);
struct SharedMem_shared;

class SharedMem //{
{
    private:
        size_t len;
        size_t offset;
        SharedMem_shared* shared;

        void ref();
        void unref();

    public:
        SharedMem();
        SharedMem(const SharedMem&);
        SharedMem(SharedMem&&);

        SharedMem& operator=(const SharedMem&);
        SharedMem& operator=(SharedMem&&);

        SharedMem(size_t size);
        SharedMem(const SharedMem& origin, size_t len, int offset = 0);
        SharedMem(void* b, size_t size, size_t offset = 0, free_func free = nullptr, realloc_func realloc = nullptr);

        SharedMem operator+(const SharedMem& a) const;
        SharedMem increaseOffset(int offset) const;

        const char* base() const;
        inline char* __base() const {return const_cast<char*>(this->base());};
        size_t size() const;

        inline bool empty() const {return this->shared == nullptr;}
        void clear_free();
        std::tuple<free_func, char*> get_free() const;

        std::string to_string();

        ~SharedMem();
}; //}

std::ostream& operator<<(std::ostream& o, const SharedMem& b);

NS_EVLTLS_END

