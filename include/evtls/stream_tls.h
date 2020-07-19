#pragma once

#include "stream.h"
#include "stream_object.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>


NS_EVLTLS_START


class EBStreamTLS: virtual public EBStreamAbstraction //{
{
    public:
        enum TLSMode {ServerMode, ClientMode};

    private:
        struct __EBStreamTLSCTX {
            EBStreamObject* mp_stream;
            TLSMode mode;
            SharedMem write_to_tls;
            SharedMem write_to_stream;

            BIO* rbio;
            BIO* wbio;
            SSL* ssl;
            SSL_CTX* ctx;
        };
        __EBStreamTLSCTX* m_ctx;
        class TLSUS: public __UnderlyingStream {
            __EBStreamTLSCTX* ctx;
            public:
            inline TLSUS(StreamType type, __EBStreamTLSCTX* ctx): __UnderlyingStream(type), ctx(ctx) {}
            inline __EBStreamTLSCTX* getstream() {return this->ctx;}
        };
        TLSMode m_mode;

        ConnectCallback m_wait_connect;
        void*           m_wait_connect_data;

        bool do_tls_handshake();
        void init_this(UNST stream, const std::string& certificate, const std::string& privateKey);

        static void stream_data_listener            (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_drain_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_error_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_end_listener             (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_close_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_connect_listener         (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_connection_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_unexpected_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_shouldStartWrite_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void stream_shouldStopWrite_listener (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        void register_listener();
        void call_connect_callback(int status);
        void error_happend();

        void pipe_to_tls(SharedMem buf);


    protected:
        void _write(SharedMem buf, WriteCallback cb, void* data) override;

        virtual EBStreamObject* getStreamObject(UNST) = 0;


    public:
        EBStreamTLS(TLSMode mode) noexcept;

        bool bind(struct sockaddr* addr) override;
        bool listen() override;

        bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) override;
        bool connect(uint32_t ipv4,              uint16_t port, ConnectCallback cb, void* data) override;
        bool connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) override;
        bool connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) override;
        bool connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) override;

        void stop_read() override;
        void start_read() override;
        bool in_read() override;

        void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) override;
        void getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) override;
        void getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) override;

        UNST newUnderlyStream() override;
        void releaseUnderlyStream(UNST) override;
        bool accept(UNST) override;

        void shutdown(ShutdownCallback cb, void* data) override;

        UNST transfer() override;
        void regain(UNST) override;

        void  release() override;
        bool  hasStreamObject() override;

        bool timeout(TimeoutCallback cb, void* data, int time_ms) override;

        ~EBStreamTLS();

        using EBStreamTLSCTX = __EBStreamTLSCTX;
        UNST createStreamWrapper(EBStreamTLSCTX*);
}; //}


NS_EVLTLS_END

