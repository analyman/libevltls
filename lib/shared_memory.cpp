#include "../include/evtls/shared_memory.h"
#include "../include/evtls/internal/config__.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <exception>


NS_EVLTLS_START


struct SharedMem_shared {
        const char* base;
        size_t ref;
        free_func free;
        realloc_func realloc;
};

SharedMem::SharedMem(size_t size): len(size), offset(0) //{
{
    if(this->len == 0) {
        this->shared = nullptr;
        return;
    }
    this->shared = new SharedMem_shared();
    this->shared->base = (char*)malloc(this->len);
    this->shared->free = free;
    this->shared->realloc = realloc;
    this->shared->ref = 1;
} //}
SharedMem::SharedMem(const SharedMem& origin, size_t len, int offset) //{
{
    this->offset = offset + origin.offset;
    assert(this->offset >= 0);
    this->len = len;
    this->shared = origin.shared;
    this->ref();
} //}
SharedMem::SharedMem(void* b, size_t size, size_t offset, free_func free, realloc_func realloc): len(size), offset(offset) //{
{
    assert(size > 0 && size > offset);
    this->shared = new SharedMem_shared();
    this->shared->base = (char*)b;
    this->shared->free = free;
    this->shared->realloc = realloc;
    this->shared->ref = 1;
} //}

SharedMem::SharedMem(): len(0), offset(0), shared(nullptr) {}
SharedMem::SharedMem(const SharedMem& buf) //{
{
    this->shared = buf.shared;
    this->len = buf.len;
    this->offset = buf.offset;
    this->ref();
    return;
} //}
SharedMem::SharedMem(SharedMem&& buf) //{
{
    this->shared = nullptr;
    (*this) = static_cast<SharedMem&&>(buf);
} //}

SharedMem& SharedMem::operator=(const SharedMem& buf) //{
{
    this->unref();
    this->len = buf.len;
    this->offset = buf.offset;
    this->shared = buf.shared;
    this->ref();
    return *this;
} //}
SharedMem& SharedMem::operator=(SharedMem&& buf) //{
{
    this->unref();
    this->len = buf.len;
    this->offset = buf.offset;
    this->shared = buf.shared;
    buf.shared = nullptr;
    buf.len = 0;
    buf.offset = 0;
    return *this;
} //}

void SharedMem::ref() //{
{
    if(this->shared == nullptr) return;
    ++this->shared->ref;
} //}
void SharedMem::unref() //{
{
    if(this->shared == nullptr) return;
    if(--this->shared->ref != 0) return;
    if(this->shared->free != nullptr)
        this->shared->free((char*)this->shared->base);
    delete this->shared;
} //}

SharedMem SharedMem::operator+(const SharedMem& a) const //{
{
    if(this->size() == 0) return a;
    if(a.size() == 0) return *this;
    if(this->shared->realloc == nullptr) {
        SharedMem buf(this->size() + a.size());
        if(this->size() > 0) memcpy(buf.__base(), this->base(), this->size());
        if(a.size() > 0)     memcpy(buf.__base() + this->size(), a.base(), a.size());
        return buf;
    } else {
        this->shared->base = (char*)this->shared->realloc(this->__base(), this->size() + a.size());
        memcpy(this->__base() + this->size(), a.base(), a.size());
        SharedMem buf(*this);
        buf.len += a.size();
        return buf;
    }
} //}
SharedMem SharedMem::increaseOffset(int a) const //{
{
    assert(a > 0);
    assert(this->len >= a);
    SharedMem buf(*this);
    buf.offset += a;
    buf.len -= a;
    if(buf.len == 0) return SharedMem();
    return buf;
} //}

const char*  SharedMem::base() const //{
{
    if(this->shared == nullptr) return nullptr;
    return this->shared->base + this->offset;
} //}
size_t SharedMem::size() const {return this->len;}

void SharedMem::clear_free() //{
{
    if(this->shared == nullptr) return;
    this->shared->free = nullptr;
} //}
std::tuple<free_func, char*> SharedMem::get_free() const //{
{
    if(this->shared == nullptr) return std::make_tuple(nullptr, nullptr);
    return std::make_tuple(this->shared->free, (char*)this->shared->base);
} //}

SharedMem::~SharedMem() {this->unref();}


static char __hex_code[17] = "0123456789ABCDEF";
std::ostream& operator<<(std::ostream& o, const SharedMem& b) //{
{
    size_t i;
    uint8_t m, n;
    const char* base = b.base();
    o << std::string(1, '\'');
    for(i=0; i<b.size(); i++) {
        m = (base[i] & 0xF0) >> 4;
        n = (base[i] & 0x0F);
        o << std::string("\\x") << std::string(1, __hex_code[m]) << std::string(1, __hex_code[n]);
    }
    o << std::string(1, '\'');
    return o;
} //}


NS_EVLTLS_END

