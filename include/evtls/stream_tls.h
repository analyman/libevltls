#pragma once

#include "stream.h"
#include "stream_object.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <set>
#include <map>

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
        __EBStreamTLSCTX* m_ctx_tmp;
        std::map<EBStreamObject*, __EBStreamTLSCTX*> m_sessions;
        class TLSUS: public __UnderlyingStream {
            __EBStreamTLSCTX* ctx;
            public:
            inline TLSUS(StreamType type, __EBStreamTLSCTX* ctx): __UnderlyingStream(type), ctx(ctx) {}
            inline __EBStreamTLSCTX* getstream() {return this->ctx;}
        };

        ConnectCallback m_wait_connect;
        void*           m_wait_connect_data;
        static void connect_timeout_callback(void* data);

        bool do_tls_handshake();

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

        static void session_stream_data_listener            (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_drain_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_error_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_end_listener             (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_close_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_connect_listener         (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_connection_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_shouldStartWrite_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void session_stream_shouldStopWrite_listener (EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        void add_session(__EBStreamTLSCTX* session);
        void transfer_to_session(EBStreamObject* session);
        void recover_to_server();
        void session_complete();
        void session_failure();
 
        void register_listener();
        void call_connect_callback(int status);
        void error_happend();

        void pipe_to_tls(SharedMem buf);
        int  ssl_read();
        void do_ssl_read_with_timeout_zero();
        static void call_do_ssl_read(void* data);

        __EBStreamTLSCTX* createCTX(EBStreamObject* stream, TLSMode mode, 
                                    const std::string& certificate, const std::string& privateKey);


    protected:
        void _write(SharedMem buf, WriteCallback cb, void* data) override;

        virtual EBStreamObject* getStreamObject(UNST) = 0;
        void init_this(UNST stream);


    public:
        EBStreamTLS(TLSMode mode, const std::string& certificate, const std::string& privateKey) noexcept;
        EBStreamTLS(UNST tlsctx) noexcept;

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
        static EBStreamTLSCTX* getCTXFromWrapper(UNST);
        static void releaseCTX(EBStreamTLSCTX*);
}; //}


NS_EVLTLS_END

