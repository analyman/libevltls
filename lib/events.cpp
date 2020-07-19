#include <assert.h>

#include "../include/evtls/internal/config__.h"
#include "../include/evtls/events.h"

NS_EVLTLS_START


#define DEBUG(all...) __logger->debug(all)


const auto& CBList_insert         = DLinkedList_insert<CallbackState>;
const auto& CBList_delete         = DLinkedList_delete<CallbackState>;
const auto& CBList_delete_target  = DLinkedList_delete_target<CallbackState>;
const auto& CBList_delete_all     = DLinkedList_delete_all<CallbackState>;
const auto& CBList_head           = DLinkedList_head<CallbackState>;
const auto& CBList_tail           = DLinkedList_tail<CallbackState>;
const auto& CBList_insert_to_head = DLinkedList_insert_to_head<CallbackState>;
const auto& CBList_insert_to_tail = DLinkedList_insert_to_tail<CallbackState>;
const auto& CBList_element_count  = DLinkedList_element_count<CallbackState>;


void  EventEmitter::delete_all() //{
{
    DEBUG("call %s", FUNCNAME);
    for(auto& cbs: this->m_listeners) {
        CBList_delete_all(&cbs.second);
        assert(cbs.second == nullptr);
    }
} //}

EventEmitter::EventListener EventEmitter::on(const std::string& event, EventCallback cb, CBFlags flags) //{
{
    DEBUG("call %s=(this=0x%lx, eventname=%s)", FUNCNAME, (long)this, event.c_str());
    assert(cb != nullptr);
    if(this->m_listeners.find(event) == this->m_listeners.end())
        this->m_listeners[event] = nullptr;
    auto x = CBList_insert_to_tail(&this->m_listeners[event], {cb, flags});
    return {event, x};
} //}
void  EventEmitter::emit(const std::string& event, EventArgs::Base* argv) //{
{
    DEBUG("call %s=(this=0x%lx, eventname=%s)", FUNCNAME, (long)this, event.c_str());
    if(this->m_listeners.find(event) == this->m_listeners.end()) {
        if(argv != nullptr) delete argv;
        return;
    }
    CBList_head(&this->m_listeners[event]);
    CBList* h = this->m_listeners[event];
    CBList** pevent = &this->m_listeners[event];
    std::vector<EventCallback> wait_cb_list; /** callback may modify this object, so defer callback */
    while(h != nullptr) {
        EventCallback ccb = h->value.cb;
        assert(ccb != nullptr);
        wait_cb_list.push_back(ccb);
        if((h->value.flags & CB_ONCE) != 0) { // delete callback;
            bool prev = h->prev != nullptr;
            CBList_delete(&h);
            *pevent = h;
            if(prev) h = h->next;
        } else {
            h = h->next;
        }
    }
    if(*pevent == nullptr) {this->m_listeners.erase(this->m_listeners.find(event));}
    if(argv == nullptr) argv = new EventArgs::Base();
    for(auto cb: wait_cb_list) cb(this, event, argv);
    delete argv;
} //}
int   EventEmitter::numberOfListener(const std::string& event) //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->m_listeners.find(event) == this->m_listeners.end()) return 0;
    auto cb = this->m_listeners[event];
    return CBList_element_count(&cb);
} //}
void  EventEmitter::remove(EventEmitter::EventListener listener) //{
{
    DEBUG("call %s=(this=0x%lx)", FUNCNAME, (long)this);
    assert(this->m_listeners.find(listener.m_eventname) != this->m_listeners.end());
    assert(listener.m_where != nullptr);
    CBList* l = this->m_listeners[listener.m_eventname];
    assert(l != nullptr);
    CBList_delete_target(&l, listener.m_where);
    if(l == nullptr) this->m_listeners.erase(listener.m_eventname);
} //}
void  EventEmitter::removeall() //{
{
    DEBUG("call %s", FUNCNAME);
    this->delete_all();
    this->m_listeners.clear();
} //}

EventEmitter::~EventEmitter() //{
{
    DEBUG("call %s", FUNCNAME);
    this->delete_all();
} //}


NS_EVLTLS_END

