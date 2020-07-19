#pragma once

#include <map>
#include <tuple>
#include <vector>

#include "internal/dlinkedlist.hpp"
#include "internal/config.h"

NS_EVLTLS_START

class EventEmitter;

namespace EventArgs {struct Base {inline virtual ~Base() {};};}


typedef void (*EventCallback)(EventEmitter* target, const std::string& event, EventArgs::Base* argv);
enum CBFlags: uint8_t {CB_NONE = 0,CB_ONCE = 1};

struct CallbackState {
    EventCallback cb;
    CBFlags       flags;
};
using CBList = DLinkedList<CallbackState>;


class __EventListener {
    private:
        friend EventEmitter;
        std::string m_eventname;
        CBList*     m_where;
        inline __EventListener(const std::string& e, CBList* l): m_eventname(e), m_where(l) {}

    public:
        inline __EventListener(): m_eventname(), m_where(nullptr) {};
        inline void clear()    {assert(this->m_where != nullptr); this->m_where = nullptr; this->m_eventname = "";}
        inline bool has()      {return this->m_where != nullptr;}
        inline operator bool() {return this->m_where != nullptr;}
};
class EventEmitter {
    public:
        using EventListener = __EventListener;


    private:
        std::map<std::string, CBList*> m_listeners;
        void delete_all();


    public:
        EventListener on(const std::string&, EventCallback cb, CBFlags flags = CB_NONE);
        void          emit(const std::string&, EventArgs::Base* argv);
        int           numberOfListener(const std::string& event);
        void          remove(EventListener);
        void          removeall();
        inline auto listeners() {return this->m_listeners;}

        virtual ~EventEmitter();
};

NS_EVLTLS_END

