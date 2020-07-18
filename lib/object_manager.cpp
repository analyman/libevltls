#include "../include/evltls/object_manager.h"
#include "../include/evltls/logger.h"

#include <assert.h>


NS_EVLTLS_START


CallbackManager::CallbackManager(): m_invalidate(false) {}
void CallbackManager::add_callback(CallbackPointer* ptr) {
    assert(this->m_list.find(ptr) == this->m_list.end());
    this->m_list.insert(ptr);
} 

void CallbackManager::remove_callback(CallbackPointer* ptr) {
    assert(this->m_list.find(ptr) != this->m_list.end());
    this->m_list.erase(this->m_list.find(ptr));
}

void CallbackManager::invalidate_callbacks() {
    assert(this->m_invalidate == false && "double invalidation is forbid");
    this->m_invalidate = true;
    for(auto& cbd: this->m_list)
        cbd->can_run = false;
}

CallbackManager::~CallbackManager() {
    this->invalidate_callbacks();
}

NS_EVLTLS_END

