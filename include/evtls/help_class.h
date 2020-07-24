#pragma once
#include "internal/config.h"


NS_EVLTLS_START


class StoreFetchPointer {
    private:
        void* m_ptr;

    public:
        StoreFetchPointer();
        void  StorePtr(void* ptr);
        void* FetchPtr();
};


NS_EVLTLS_END

