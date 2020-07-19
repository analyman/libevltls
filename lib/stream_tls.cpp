#include "../include/evtls/stream_tls.h"
#include "../include/evtls/logger.h"
#include "../include/evtls/utils.h"

#include "../include/evtls/internal/config__.h"


#define DEBUG(all...) __logger->debug(all)
#define READ_SIZE (64 * 1024)


NS_EVLTLS_START


EBStreamTLS::EBStreamTLS(TLSMode mode) noexcept //{
{
    this->m_ctx = nullptr;
    this->m_mode = mode;
} //}

void EBStreamTLS::init_this(UNST stream, const std::string& certificate, const std::string& privateKey) //{
{
    assert(!this->m_ctx);
    this->m_ctx = new __EBStreamTLSCTX();

    this->m_ctx->mp_stream = this->getStreamObject(stream);
    this->m_ctx->mp_stream->storePtr(this);

    this->m_ctx->mode = this->m_mode;

    this->m_ctx->ctx = SSL_CTX_new(TLS_method()); // TODO

    if(this->m_ctx->mode == TLSMode::ServerMode) {
        if(SSL_CTX_use_certificate(this->m_ctx->ctx, str_to_x509(certificate)) != 0) {
            this->error_happend();
            return;
        }
        if(SSL_CTX_use_PrivateKey (this->m_ctx->ctx, str_to_privateKey(privateKey)) != 0) {
            this->error_happend();
            return;
        }
        if(SSL_check_private_key(this->m_ctx->ssl) != 0) {
            this->error_happend();
            return;
        }
    }

    this->m_ctx->rbio = BIO_new(BIO_s_mem());
    this->m_ctx->wbio = BIO_new(BIO_s_mem());
    this->m_ctx->ssl  = SSL_new(this->m_ctx->ctx);

    if(this->m_ctx->mode == TLSMode::ServerMode)
        SSL_set_accept_state(this->m_ctx->ssl);
    else
        SSL_set_connect_state(this->m_ctx->ssl);

    SSL_set_bio(this->m_ctx->ssl, this->m_ctx->rbio, this->m_ctx->wbio);
    this->register_listener();
} //}

void EBStreamTLS::register_listener() //{
{
    this->m_ctx->mp_stream->on("data",  stream_data_listener);
    this->m_ctx->mp_stream->on("drain", stream_drain_listener);
    this->m_ctx->mp_stream->on("error", stream_error_listener);
    this->m_ctx->mp_stream->on("end",   stream_end_listener);
    this->m_ctx->mp_stream->on("close", stream_close_listener);
    if(this->m_ctx->mode == TLSMode::ServerMode) {
        this->m_ctx->mp_stream->on("connection", stream_connection_listener);
        this->m_ctx->mp_stream->on("connect", stream_unexpected_listener);
    } else {
        this->m_ctx->mp_stream->on("connect", stream_connect_listener);
        this->m_ctx->mp_stream->on("connection", stream_unexpected_listener);
    }
    this->m_ctx->mp_stream->on("shouldStartWrite", stream_shouldStartWrite_listener);
    this->m_ctx->mp_stream->on("shouldStopWrite",  stream_shouldStopWrite_listener);
} //}

#define GETTHIS(argname) \
    EBStreamObject* stream = dynamic_cast<decltype(stream)>(obj); assert(stream); \
    EBStreamTLS* _this = \
        dynamic_cast<decltype(_this)>(static_cast<EBStreamTLS*>(stream->fetchPtr())); \
    assert(_this); \
    EBStreamObject::argname* args = dynamic_cast<decltype(args)>(aaa); assert(args)
/** [static] */
void EBStreamTLS::stream_data_listener            (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(DataArgs);
    _this->pipe_to_tls(args->_buf);
} //}
void EBStreamTLS::stream_drain_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(DrainArgs);
    return;
} //}
void EBStreamTLS::stream_error_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ErrorArgs);
    _this->error_happend();
} //}
void EBStreamTLS::stream_end_listener             (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(EndArgs);
    _this->end_signal();
} //}
void EBStreamTLS::stream_close_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(CloseArgs);
    _this->error_happend();
} //}
void EBStreamTLS::stream_connect_listener         (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ConnectArgs);
    if(_this->m_wait_connect == nullptr) {
        _this->error_happend();
    } else {
        _this->do_tls_handshake();
    }
} //}
void EBStreamTLS::stream_connection_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ConnectionArgs);
    _this->on_connection(args->connection);
} //}
void EBStreamTLS::stream_unexpected_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    EBStreamObject* stream = dynamic_cast<decltype(stream)>(obj); assert(stream);
    EBStreamTLS* _this =
        dynamic_cast<decltype(_this)>(static_cast<EBStreamTLS*>(stream->fetchPtr()));
    assert(_this);
    _this->error_happend();
} //}
void EBStreamTLS::stream_shouldStartWrite_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ShouldStartWriteArgs);
    _this->should_start_write();
} //}
void EBStreamTLS::stream_shouldStopWrite_listener (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ShouldStopWriteArgs);
    _this->should_stop_write();
} //}
#undef GETTHIS

void EBStreamTLS::call_connect_callback(int status) //{
{
    assert(this->m_wait_connect != nullptr);
    auto _cb   = this->m_wait_connect;
    auto _data = this->m_wait_connect_data;
    this->m_wait_connect = nullptr;
    this->m_wait_connect_data = nullptr;
    _cb(status, _data);
} //}
void EBStreamTLS::error_happend() //{
{
    this->read_callback(SharedMem(), -1);
} //}

// FIXME
bool EBStreamTLS::do_tls_handshake() //{
{
    SSL_do_handshake(this->m_ctx->ssl);
    // TODO
    return true;
} //}
void EBStreamTLS::pipe_to_tls(SharedMem wbuf) //{
{
    assert(this->m_ctx != nullptr);
    SharedMem& buf = this->m_ctx->write_to_stream;
    buf = buf + wbuf;
    char rbuf[READ_SIZE];

    while(buf.size() > 0) {
        auto n = BIO_write(this->m_ctx->rbio, buf.base(), buf.size());

        if(n < 0) {
            this->error_happend();
            return;
        }
        buf.increaseOffset(n);

        if(!SSL_is_init_finished(this->m_ctx->ssl)) {
            auto k = SSL_accept(this->m_ctx->ssl);
            auto status = SSL_get_error(this->m_ctx->ssl, k);
            if(status == SSL_ERROR_WANT_READ) {
                int b = 0;
                do {
                    b = BIO_read(this->m_ctx->wbio, rbuf, sizeof(rbuf));
                    if(b > 0) {
                        SharedMem bbuf(b);
                        memcpy(bbuf.__base(), rbuf, b);
                        this->m_ctx->mp_stream->write(bbuf);
                    } else if(!BIO_should_retry(this->m_ctx->wbio)) {
                        this->error_happend();
                        return;
                    }
                } while(b > 0);
            }
        } else {
            if(this->m_wait_connect != nullptr)
                this->call_connect_callback(0);
        }

        int k=0;
        char rbuf[READ_SIZE];
        do {
            k = SSL_read(this->m_ctx->ssl, rbuf, sizeof(rbuf));
            if(k > 0) {
                SharedMem buf(k);
                memcpy(buf.__base(), rbuf, k);
                this->read_callback(buf, 0);
            }
        } while(k>0);

        int status = SSL_get_error(this->m_ctx->ssl, k);
        switch(status) {
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                this->error_happend();
                return;
            default:
                break;
        }
    }
} //}

void EBStreamTLS::_write(SharedMem kbuf, WriteCallback cb, void* data) //{
{
    assert(this->m_ctx != nullptr);
    assert(SSL_is_init_finished(this->m_ctx->ssl) == 1);

    SharedMem& buf = this->m_ctx->write_to_tls;
    buf = buf + kbuf;

    char rbuf[READ_SIZE];
    SharedMem bbuf;

    while(buf.size() > 0) {
        int n = SSL_write(this->m_ctx->ssl, buf.base(), buf.size());
        int status = SSL_get_error(this->m_ctx->ssl, n);

        if(n > 0) {
            buf = buf.increaseOffset(n);
            while(n > 0) {
                n = BIO_read(this->m_ctx->wbio, rbuf, sizeof(rbuf));
                if(n > 0) {
                    SharedMem kbuf(n);
                    memcpy(kbuf.__base(), rbuf, n);
                    bbuf = bbuf + kbuf;
                } else if (!BIO_should_retry(this->m_ctx->wbio)) {
                    cb(SharedMem(), -1, data);
                    return;
                }
            }
        } else {
            switch(status) {
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    cb(SharedMem(), -1, data);
                    return;
                defautl:
                    break;
            }
            if(n == 0) break; // TODO
        }
    }

    this->m_ctx->mp_stream->__write(bbuf, cb, data);
} //}


bool EBStreamTLS::bind(struct sockaddr* addr) //{
{
    return this->m_ctx->mp_stream->bind(addr);
} //}
bool EBStreamTLS::listen() //{
{
    return this->m_ctx->mp_stream->listen();
} //}

#define SETCONNECT() \
    assert(this->m_ctx != nullptr); \
    assert(this->m_wait_connect != nullptr);\
    this->m_wait_connect = cb; \
    this->m_wait_connect_data = data
bool EBStreamTLS::connect(struct sockaddr* addr, ConnectCallback cb, void* data) //{
{
    SETCONNECT();
    return this->m_ctx->mp_stream->connectTo(addr);
} //}
bool EBStreamTLS::connect(uint32_t ipv4,              uint16_t port, ConnectCallback cb, void* data) //{
{
    SETCONNECT();
    return this->m_ctx->mp_stream->connectTo(ipv4, port);
} //}
bool EBStreamTLS::connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) //{
{
    SETCONNECT();
    return this->m_ctx->mp_stream->connectTo(ipv6, port);
} //}
bool EBStreamTLS::connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) //{
{
    SETCONNECT();
    return this->m_ctx->mp_stream->connectTo(domname, port);
} //}
bool EBStreamTLS::connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) //{
{
    SETCONNECT();
    return this->m_ctx->mp_stream->connectTo(domname, port);
} //}

void EBStreamTLS::stop_read() //{
{
    this->m_ctx->mp_stream->stopRead();
} //}
void EBStreamTLS::start_read() //{
{
    this->m_ctx->mp_stream->startRead();
} //}
bool EBStreamTLS::in_read() //{
{
    return this->m_ctx->mp_stream->in_read();
} //}

void EBStreamTLS::getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) //{
{
    this->m_ctx->mp_stream->getaddrinfo(hostname, cb, data);
} //}
void EBStreamTLS::getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) //{
{
    this->m_ctx->mp_stream->getaddrinfoipv4(hostname, cb, data);
} //}
void EBStreamTLS::getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) //{
{
    this->m_ctx->mp_stream->getaddrinfoipv6(hostname, cb, data);
} //}

EBStreamAbstraction::UNST EBStreamTLS::newUnderlyStream() //{
{
    __EBStreamTLSCTX* new_stream = new __EBStreamTLSCTX();
    new_stream->ctx = this->m_ctx->ctx;
    SSL_CTX_up_ref(this->m_ctx->ctx);
    new_stream->mode = this->m_ctx->mode;
    new_stream->ssl = SSL_new(new_stream->ctx);
    new_stream->rbio = BIO_new(BIO_s_mem());
    new_stream->wbio = BIO_new(BIO_s_mem());
    new_stream->mp_stream = this->m_ctx->mp_stream->NewStreamObject();
    return UNST(new TLSUS(this->getType(), new_stream));
} //}
void EBStreamTLS::releaseUnderlyStream(UNST stream) //{
{
    assert(this->m_ctx == nullptr);
    assert(this->getType() == stream->getType());
    TLSUS* ctx = dynamic_cast<decltype(ctx)>(stream.get()); assert(ctx);
    auto mm = ctx->getstream();
    assert(mm != nullptr);

    delete mm->mp_stream;
    SSL_CTX_free(mm->ctx);
    SSL_free(mm->ssl);
    delete  ctx;
} //}
bool EBStreamTLS::accept(UNST stream) //{
{
    assert(this->getType() == stream->getType());
    TLSUS* stream__ = dynamic_cast<decltype(stream__)>(stream.get());
    assert(stream__);
    return this->m_ctx->mp_stream->accept(stream__->getstream()->mp_stream);
} //}

void EBStreamTLS::shutdown(ShutdownCallback cb, void* data) //{
{
    SSL_shutdown(this->m_ctx->ssl);
    char rbuf[READ_SIZE];
    SharedMem buf;
    int n = 0;
    do {
        n = BIO_read(this->m_ctx->wbio, rbuf, sizeof(rbuf));
        if(n > 0) {
            SharedMem kbuf(n);
            memcpy(kbuf.__base(), rbuf, n);
            buf = buf + kbuf;
        } else if (!BIO_should_retry(this->m_ctx->wbio)) {
            this->error_happend();
            return;
        }
    } while(n > 0);

    this->m_ctx->mp_stream->write(buf);
    this->m_ctx->mp_stream->end();
} //}

EBStreamAbstraction::UNST EBStreamTLS::transfer() //{
{
    assert(this->m_ctx != nullptr);
    auto ctx = this->m_ctx;
    this->m_ctx = nullptr;
    return UNST(new TLSUS(this->getType(), ctx));
} //}
void EBStreamTLS::regain(UNST stream) //{
{
    assert(this->m_ctx == nullptr);
    assert(this->getType() == stream->getType());
    TLSUS* ctx = dynamic_cast<decltype(ctx)>(stream.get()); assert(ctx);
    this->m_ctx = ctx->getstream();
    assert(this->m_ctx->mode == this->m_mode);
} //}

void  EBStreamTLS::release() //{
{
    assert(this->m_ctx != nullptr);
    auto ctx = this->m_ctx;
    this->m_ctx = nullptr;

    delete ctx->mp_stream;
    ctx->mp_stream = nullptr;

    SSL_CTX_free(ctx->ctx);
    ctx->ctx = nullptr;
    SSL_free(ctx->ssl);
    ctx->ssl = nullptr;

    ctx->rbio = nullptr;
    ctx->wbio = nullptr;

    delete  ctx;
} //}
bool  EBStreamTLS::hasStreamObject() //{
{
    return (this->m_ctx != nullptr);
} //}

bool EBStreamTLS::timeout(TimeoutCallback cb, void* data, int time_ms) //{
{
    this->m_ctx->mp_stream->SetTimeout(cb, data, time_ms);
    return true;
} //}

EBStreamTLS::~EBStreamTLS() //{
{
    if(this->m_wait_connect != nullptr)
        this->call_connect_callback(-1);
} //}


NS_EVLTLS_END


