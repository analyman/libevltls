#pragma once

#include "events.h"
#include "shared_memory.h"
#include "object_manager.h"

#include <assert.h>
#include <memory>
#define CALL_PURE_VIRTUAL_FUNCTION() assert(false && "call pure virtual function")

/* forward declaration */
struct addrinfo;
struct sockaddr;

NS_EVLTLS_START


enum StreamType {Memory, LIBUV, TLS_LIBUV, KPROXY_MULTIPLEXER};
class __UnderlyingStream {
    StreamType m_type;
    public:
    inline __UnderlyingStream(StreamType type): m_type(type) {}
    inline StreamType getType() {return this->m_type;}
    inline virtual ~__UnderlyingStream() {}
};

class EBStreamAbstraction: virtual public EventEmitter, virtual protected CallbackManager //{
{
    public:
        /** #status < 0 means error */
        using WriteCallback           = void (*)(SharedMem buf, int status, void* data);
        using ReadCallback            = void(*)(SharedMem buf, int status);
        using GetAddrInfoCallback     = void(*)(struct addrinfo* addr, void(*free)(struct addrinfo*), int status, void* data);
        using GetAddrInfoIPv4Callback = void(*)(uint32_t ipv4, int status, void* data);
        using GetAddrInfoIPv6Callback = void(*)(uint8_t  ipv6[16], int status, void* data);
        using ConnectCallback         = void(*)(int status, void* data);
        using ShutdownCallback        = void(*)(int status, void* data);
        using TimeoutCallback         = void(*)(void* data);

        using UNST = std::shared_ptr<__UnderlyingStream>;


    protected:
        enum CONNECTION_STATE { 
            UNINITIAL = 0, INITIAL, CONNECTING,
            CONNECT, GIVEUP, CLOSED,
            LISTENNING
        };
        CONNECTION_STATE m_state;

        size_t      m_stat_speed_out;
        size_t      m_stat_speed_in;
        size_t      m_stat_traffic_out;
        size_t      m_stat_traffic_in;

        bool m_waiting_calculating;
        void recalculatespeed();
        static void calculate_speed_callback(void* data);
        EBStreamAbstraction() noexcept;

        virtual void _write(SharedMem buf, WriteCallback cb, void* data) = 0;

        inline virtual void read_callback(SharedMem buf, int status) {CALL_PURE_VIRTUAL_FUNCTION();};
        inline virtual void end_signal() {CALL_PURE_VIRTUAL_FUNCTION();};

        inline virtual void should_start_write() {CALL_PURE_VIRTUAL_FUNCTION();}
        inline virtual void should_stop_write () {CALL_PURE_VIRTUAL_FUNCTION();}

        inline virtual void on_connection(UNST connection) {CALL_PURE_VIRTUAL_FUNCTION();};


    public:
        virtual bool bind(struct sockaddr* addr) = 0;
        virtual bool listen() = 0;

        virtual bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) = 0;
        /** local machine byte order */
        virtual bool connect(uint32_t ipv4,              uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual bool connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual bool connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual bool connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) = 0;

        virtual void stop_read() = 0;
        virtual void start_read() = 0;
        virtual bool in_read() = 0;

        virtual void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) = 0;
        virtual void getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) = 0;
        virtual void getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) = 0;

        virtual UNST newUnderlyStream() = 0;
        virtual void releaseUnderlyStream(UNST) = 0;
        virtual bool accept(UNST) = 0;

        virtual void shutdown(ShutdownCallback cb, void* data) = 0;

        virtual UNST transfer() = 0;
        virtual void regain(UNST) = 0;

        virtual void  release() = 0;
        virtual bool  hasStreamObject() = 0;

        virtual StreamType getType() = 0;

        /** statistics */
        size_t speed_out();            // bytes/second
        size_t speed_in ();            // bytes/second
        size_t traffic_out();          // bytes
        size_t traffic_in ();          // bytes
        virtual std::string remote_addr();     // remote address
        virtual uint16_t remote_port();        // remote port
        virtual std::string local_addr();      // local address
        virtual uint16_t local_port();         // local port

        virtual bool timeout(TimeoutCallback cb, void* data, int time_ms) = 0;

        inline virtual ~EBStreamAbstraction() {};
}; //}


NS_EVLTLS_END

