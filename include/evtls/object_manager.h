#pragma once

#include <map>
#include <set>

#include <assert.h>

#include "internal/config.h"


NS_EVLTLS_START


class ObjectBoundary;
class ObjectChecker {
    private:
        bool m_exist;
        friend ObjectBoundary;

    public:
        inline ObjectChecker(): m_exist(true) {}
        inline bool exist() {return this->m_exist;}
};
class ObjectBoundary {
    private:
        ObjectChecker* m_checker;

    public:
        inline ObjectBoundary(): m_checker(nullptr) {}
        virtual inline ~ObjectBoundary() {if(m_checker) m_checker->m_exist = false;}
        inline void SetChecker(ObjectChecker* cc) {assert(cc != nullptr); assert(m_checker == nullptr); this->m_checker = cc;}
        inline void cleanChecker(ObjectChecker* cc) {assert(m_checker == cc && m_checker->exist()); this->m_checker = nullptr;}
};


class CallbackManager;
class CallbackPointer {
    private:
        bool can_run;
        friend class CallbackManager;

    public:
        inline CallbackPointer(): can_run(true) {}
        inline virtual ~CallbackPointer() {};
        inline bool CanRun() {return this->can_run;}
};

class CallbackManager: public ObjectBoundary {
    private:
        std::set<CallbackPointer*> m_list;
        bool m_invalidate;
        void invalidate_callbacks();
        
    public:
        CallbackManager();
        void add_callback(CallbackPointer* ptr);
        void remove_callback(CallbackPointer* ptr);
        ~CallbackManager();
};


NS_EVLTLS_END

