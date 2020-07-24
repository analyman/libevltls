#include "../include/evtls/help_class.h"
#include "assert.h"

NS_EVLTLS_START

StoreFetchPointer::StoreFetchPointer(): m_ptr(nullptr) {}
void  StoreFetchPointer::StorePtr(void* ptr) {this->m_ptr = ptr;}
void* StoreFetchPointer::FetchPtr()          {return this->m_ptr;}

NS_EVLTLS_END

