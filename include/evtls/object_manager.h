#pragma once

#include <map>
#include <set>
#include <memory>

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
        std::set<ObjectChecker*> m_checker;

    public:
        ObjectBoundary();
        void SetChecker  (ObjectChecker* cc);
        void cleanChecker(ObjectChecker* cc);
        virtual ~ObjectBoundary();
};
std::shared_ptr<ObjectChecker> NewChecker();


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

