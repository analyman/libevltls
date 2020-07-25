#include "../include/evtls/object_manager.h"
#include "../include/evtls/logger.h"
#include "../include/evtls/internal/config__.h"

#include <assert.h>


NS_EVLTLS_START

ObjectBoundary::ObjectBoundary(): m_checker() //{
{
} //}
void ObjectBoundary::SetChecker  (ObjectChecker* cc) //{
{
    assert(this->m_checker.find(cc) == this->m_checker.end());
    assert(cc->m_exist == true);
    this->m_checker.insert(cc);
} //}
void ObjectBoundary::cleanChecker(ObjectChecker* cc) //{
{
    assert(this->m_checker.find(cc) != this->m_checker.end());
    assert(cc->m_exist == true);
    this->m_checker.erase(this->m_checker.find(cc));
} //}
ObjectBoundary::~ObjectBoundary() //{
{
    for(auto& ck: this->m_checker)
        ck->m_exist = false;
} //}

std::shared_ptr<ObjectChecker> NewChecker() //{
{
    return std::shared_ptr<ObjectChecker>(new ObjectChecker());
} //}


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

