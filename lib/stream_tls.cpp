#include "../include/evtls/stream_tls.h"
#include "../include/evtls/logger.h"
#include "../include/evtls/utils.h"

#include "../include/evtls/internal/config__.h"


#define DEBUG(all...) __logger->debug(all)
#define READ_SIZE (64 * 1024)


NS_EVLTLS_START


EBStreamTLS::EBStreamTLS(TLSMode mode, const std::string& cert, const std::string& privateKey) noexcept //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_wait_connect = nullptr;
    this->m_wait_connect_data = nullptr;
    this->m_ctx_tmp = nullptr;
    this->m_ctx = createCTX(nullptr, mode, cert, privateKey);
    assert(this->m_ctx);
} //}
EBStreamTLS::EBStreamTLS(UNST tlsctx) noexcept //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_wait_connect = nullptr;
    this->m_wait_connect_data = nullptr;
    TLSUS* ctx = dynamic_cast<decltype(ctx)>(tlsctx.get()); assert(ctx);
    this->m_ctx_tmp = nullptr;
    this->m_ctx = ctx->getstream();
    assert(this->m_ctx->mp_stream->fetchPtr() == nullptr);
    this->m_ctx->mp_stream->storePtr(this);
    this->register_listener();
    this->do_ssl_read_with_timeout_zero();
} //}

void EBStreamTLS::init_this(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx);
    assert(!this->m_ctx->mp_stream);

    this->m_ctx->mp_stream = this->getStreamObject(stream);
    assert(this->m_ctx->mp_stream->fetchPtr() == nullptr);
    this->m_ctx->mp_stream->storePtr(this);

    this->register_listener();
} //}

EBStreamTLS::EBStreamTLSCTX* EBStreamTLS::createCTX(EBStreamObject* stream, TLSMode mode, //{
                                                    const std::string& cert, 
                                                    const std::string& privateKey)
{
    DEBUG("call %s", FUNCNAME);
    return EBStreamTLS::getCTX(mode, stream, cert, privateKey);
} //}

void EBStreamTLS::register_listener() //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME); \
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
    assert(_this->m_ctx->mode == TLSMode::ClientMode);
    if(_this->m_wait_connect == nullptr) {
        _this->error_happend();
    } else {
        _this->m_ctx->mp_stream->startRead();
        if(!_this->do_tls_handshake()) {
            _this->error_happend();
        }
    }
} //}
void EBStreamTLS::stream_connection_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ConnectionArgs);
    assert(_this->m_ctx->mode == TLSMode::ServerMode);
    auto newstreamobject = _this->m_ctx->mp_stream->NewStreamObject(args->connection);
    auto connection = new EBStreamTLSCTX();
    connection->ctx = _this->m_ctx->ctx;
    SSL_CTX_up_ref(connection->ctx);
    connection->mode = _this->m_ctx->mode;
    connection->mp_stream = newstreamobject;
    connection->rbio = BIO_new(BIO_s_mem());
    connection->wbio = BIO_new(BIO_s_mem());
    connection->ssl = SSL_new(connection->ctx);
    SSL_set_bio(connection->ssl, connection->rbio, connection->wbio);
    _this->add_session(connection);
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

/** [static] */
void EBStreamTLS::session_stream_data_listener            (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(DataArgs);
    _this->transfer_to_session(stream);
    _this->pipe_to_tls(args->_buf);
    _this->recover_to_server();
} //}
void EBStreamTLS::session_stream_drain_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(DrainArgs);
    return;
} //}
void EBStreamTLS::session_stream_error_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ErrorArgs);
    _this->transfer_to_session(stream);
    _this->error_happend();
    _this->recover_to_server();
} //}
void EBStreamTLS::session_stream_end_listener             (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(EndArgs);
    _this->transfer_to_session(stream);
    _this->error_happend();
    _this->recover_to_server();
} //}
void EBStreamTLS::session_stream_close_listener           (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(CloseArgs);
    _this->transfer_to_session(stream);
    _this->error_happend();
    _this->recover_to_server();
} //}
void EBStreamTLS::session_stream_connect_listener         (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ConnectArgs);
    _this->transfer_to_session(stream);
    _this->error_happend();
    _this->recover_to_server();
} //}
void EBStreamTLS::session_stream_connection_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ConnectionArgs);
    _this->transfer_to_session(stream);
    _this->error_happend();
    _this->recover_to_server();
} //}
void EBStreamTLS::session_stream_shouldStartWrite_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ShouldStartWriteArgs);
} //}
void EBStreamTLS::session_stream_shouldStopWrite_listener (EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    GETTHIS(ShouldStopWriteArgs);
} //}
#undef GETTHIS

void EBStreamTLS::add_session(__EBStreamTLSCTX* session) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx->mode == TLSMode::ServerMode);
    assert(this->m_ctx_tmp == nullptr);
    assert(this->m_sessions.find(session->mp_stream) == this->m_sessions.end());
    this->m_sessions[session->mp_stream] = session;

    session->mp_stream->storePtr(this);
    session->mp_stream->on("data",  session_stream_data_listener);
    session->mp_stream->on("drain", session_stream_drain_listener);
    session->mp_stream->on("error", session_stream_error_listener);
    session->mp_stream->on("end",   session_stream_end_listener);
    session->mp_stream->on("close", session_stream_close_listener);
    session->mp_stream->on("connection", session_stream_connection_listener);
    session->mp_stream->on("connect", session_stream_connect_listener);
    session->mp_stream->on("shouldStartWrite", session_stream_shouldStartWrite_listener);
    session->mp_stream->on("shouldStopWrite",  session_stream_shouldStopWrite_listener);
    session->mp_stream->startRead();
} //}

void EBStreamTLS::transfer_to_session(EBStreamObject* stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_sessions.find(stream) != this->m_sessions.end());
    auto session = this->m_sessions[stream];
    assert(this->m_ctx_tmp == nullptr);
    this->m_ctx_tmp = this->m_ctx;
    this->m_ctx = session;
    assert(this->m_sessions.find(this->m_ctx->mp_stream) != this->m_sessions.end());
} //}
void EBStreamTLS::recover_to_server() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx_tmp != nullptr);
    this->m_ctx = this->m_ctx_tmp;
    this->m_ctx_tmp = nullptr;
} //}

void EBStreamTLS::session_complete() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx_tmp != nullptr);
    assert(this->m_sessions.find(this->m_ctx->mp_stream) != this->m_sessions.end());
    this->m_sessions.erase(this->m_sessions.find(this->m_ctx->mp_stream));
    auto session = this->m_ctx;

    session->mp_stream->stopRead();
    session->mp_stream->removeall();
    session->mp_stream->storePtr(nullptr);

    this->on_connection(UNST(new TLSUS(this->getType(), session)));
} //}
void EBStreamTLS::session_failure() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx_tmp != nullptr);
    assert(this->m_sessions.find(this->m_ctx->mp_stream) != this->m_sessions.end());
    this->m_sessions.erase(this->m_sessions.find(this->m_ctx->mp_stream));
    auto session = this->m_ctx;

    session->mp_stream->stopRead();
    session->mp_stream->removeall();
    session->mp_stream->storePtr(nullptr);

    this->releaseUnderlyStream(UNST(new TLSUS(this->getType(), session)));
    this->on_connection(UNST(new TLSUS(this->getType(), nullptr)));
} //}

void EBStreamTLS::call_connect_callback(int status) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_wait_connect != nullptr);
    auto _cb   = this->m_wait_connect;
    auto _data = this->m_wait_connect_data;
    this->m_wait_connect = nullptr;
    this->m_wait_connect_data = nullptr;
    _cb(status, _data);
    this->do_ssl_read_with_timeout_zero();
} //}
void EBStreamTLS::error_happend() //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->m_ctx_tmp == nullptr) {
        this->read_callback(SharedMem(), -1);
    } else {
        this->session_failure();
    }
} //}

bool EBStreamTLS::do_tls_handshake() //{
{
    DEBUG("call %s with %s", FUNCNAME, this->m_ctx->mode == TLSMode::ServerMode ? "ServerMode" : "ClientMode");
    char buf[READ_SIZE];

    int n = SSL_do_handshake(this->m_ctx->ssl);
    int status = SSL_get_error(this->m_ctx->ssl, n);

    switch(status) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            do {
                n = BIO_read(this->m_ctx->wbio, buf, sizeof(buf));
                if(n > 0) {
                    SharedMem sbuf(n);
                    memcpy(sbuf.__base(), buf, n);
                    this->m_ctx->mp_stream->write(sbuf);
                } else if (!BIO_should_retry(this->m_ctx->wbio)) {
                    return false;
                }
            } while (n > 0);
            return true;
        case SSL_ERROR_ZERO_RETURN:
        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL:
            return false;
        default:
            break;
    }

    return true;
} //}

#define SAFE_ERROR_HAPPEND() \
    this->error_happend(); \
    if(checker->exist()) this->cleanChecker(checker.get())
void EBStreamTLS::pipe_to_tls(SharedMem wbuf) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx != nullptr);
    SharedMem& buf = this->m_ctx->write_to_stream;
    buf = buf + wbuf;
    char rbuf[READ_SIZE];

    enum do_something {NOTHING, CALL_CONNECT_CB, COMPLETE_SESSION};
    do_something doit = NOTHING;

    auto checker = NewChecker();
    this->SetChecker(checker.get());

    while(buf.size() > 0) {
        if(!checker->exist()) break;

        auto n = BIO_write(this->m_ctx->rbio, buf.base(), buf.size());

        if(n < 0) {
            SAFE_ERROR_HAPPEND();
            return;
        }
        buf = buf.increaseOffset(n);

        if(!SSL_is_init_finished(this->m_ctx->ssl)) {
            if(SSL_in_before(this->m_ctx->ssl) && this->m_ctx->mode == TLSMode::ServerMode) // FIXME
                SSL_accept(this->m_ctx->ssl);

            if(!this->do_tls_handshake()) {
                SAFE_ERROR_HAPPEND();
                return;
            }

            if(SSL_is_init_finished(this->m_ctx->ssl)) {
                if(this->m_wait_connect != nullptr) {
                    assert(this->m_ctx->mode == TLSMode::ClientMode);
                    doit = CALL_CONNECT_CB;
                    break;
                } else {
                    assert(this->m_ctx->mode == TLSMode::ServerMode);
                    doit = COMPLETE_SESSION;
                    break;
                }
            }
        }

        int k = this->ssl_read();
        if(!checker->exist()) break;

        int status = SSL_get_error(this->m_ctx->ssl, k);
        switch(status) {
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                SAFE_ERROR_HAPPEND();
                return;
            default:
                break;
        }
    }

    if(checker->exist()) 
        this->cleanChecker(checker.get());
    else
        return;

    switch(doit) {
        case CALL_CONNECT_CB:
            this->m_ctx->mp_stream->stopRead();
            this->call_connect_callback(0);
            break;
        case COMPLETE_SESSION:
            this->session_complete();
            break;
        case NOTHING:
        default:
            return;
    }
} //}
#undef SAFE_ERROR_HAPPEND

int  EBStreamTLS::ssl_read() //{
{
    DEBUG("call %s", FUNCNAME);
    int k=0;
    char rbuf[READ_SIZE];
    auto checker = new ObjectChecker();
    this->SetChecker(checker);

    do {
        if(!checker->exist()) break;
        auto c = this->m_ctx;
        auto s = c->ssl;
        k = SSL_read(s, rbuf, sizeof(rbuf));
        if(k > 0) {
            SharedMem buf(k);
            memcpy(buf.__base(), rbuf, k);
            this->read_callback(buf, 0);
        }
    } while(k>0);

    if(checker->exist()) this->cleanChecker(checker);
    delete checker;
    return k;
} //}
struct __do_ssl_read_state: public CallbackPointer {
    EBStreamTLS* _this;
    inline __do_ssl_read_state(EBStreamTLS* _this): _this(_this) {}
};
void EBStreamTLS::do_ssl_read_with_timeout_zero() //{
{
    DEBUG("call %s", FUNCNAME);
    auto ptr = new __do_ssl_read_state(this);
    this->add_callback(ptr);
    this->timeout(call_do_ssl_read, ptr, 0);
} //}
/** [static] */
void EBStreamTLS::call_do_ssl_read(void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __do_ssl_read_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto   run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    _this->ssl_read();
} //}

void EBStreamTLS::_write(SharedMem kbuf, WriteCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx != nullptr);
    assert(this->m_ctx_tmp == nullptr);
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
    DEBUG("call %s", FUNCNAME);
    return this->m_ctx->mp_stream->bind(addr);
} //}
bool EBStreamTLS::listen() //{
{
    DEBUG("call %s", FUNCNAME);
    return this->m_ctx->mp_stream->listen();
} //}

struct __connect_callback_state: public CallbackPointer {
    EBStreamTLS* _this;
    EBStreamTLS::ConnectCallback _cb;
    void* _data;
    inline __connect_callback_state(EBStreamTLS* _this, EBStreamTLS::ConnectCallback cb, void* data):
        _this(_this), _cb(cb), _data(data) {}
};
#define SETCONNECT() \
    DEBUG("call %s", FUNCNAME); \
    assert(this->m_ctx != nullptr); \
    assert(this->m_wait_connect == nullptr);\
    this->m_wait_connect = cb; \
    this->m_wait_connect_data = data; \
    auto ptr = new __connect_callback_state(this, cb, data); \
    this->add_callback(ptr); \
    auto ttt = this->timeout(connect_timeout_callback, ptr, MAX_TLS_CONNECT_TIMEOUT); \
    assert(ttt)

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
/** [static] */
void EBStreamTLS::connect_timeout_callback(void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __connect_callback_state* msg =
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto _cb = msg->_cb;
    auto _data = msg->_data;
    auto run = msg->CanRun();
    delete msg;

    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(_this->m_wait_connect != nullptr)
        _this->call_connect_callback(-1);
} //}

void EBStreamTLS::stop_read() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(SSL_is_init_finished(this->m_ctx->ssl) == 1);
    this->m_ctx->mp_stream->stopRead();
} //}
void EBStreamTLS::start_read() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(SSL_is_init_finished(this->m_ctx->ssl) == 1);
    this->m_ctx->mp_stream->startRead();
} //}
bool EBStreamTLS::in_read() //{
{
    DEBUG("call %s", FUNCNAME);
    if(SSL_is_init_finished(this->m_ctx->ssl) <= 0) return false;
    return this->m_ctx->mp_stream->in_read();
} //}

void EBStreamTLS::getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_ctx->mp_stream->getaddrinfo(hostname, cb, data);
} //}
void EBStreamTLS::getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_ctx->mp_stream->getaddrinfoipv4(hostname, cb, data);
} //}
void EBStreamTLS::getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_ctx->mp_stream->getaddrinfoipv6(hostname, cb, data);
} //}

EBStreamAbstraction::UNST EBStreamTLS::newUnderlyStream() //{
{
    DEBUG("call %s", FUNCNAME);
    __EBStreamTLSCTX* new_stream = new __EBStreamTLSCTX();
    new_stream->ctx = this->m_ctx->ctx;
    SSL_CTX_up_ref(this->m_ctx->ctx);
    new_stream->mode = this->m_ctx->mode;
    new_stream->ssl = SSL_new(new_stream->ctx);
    new_stream->rbio = BIO_new(BIO_s_mem());
    new_stream->wbio = BIO_new(BIO_s_mem());
    new_stream->mp_stream = this->m_ctx->mp_stream->NewStreamObject(); // FIXME LOSS
    return UNST(new TLSUS(this->getType(), new_stream));
} //}
void EBStreamTLS::releaseUnderlyStream(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->getType() == stream->getType());
    TLSUS* ctx = dynamic_cast<decltype(ctx)>(stream.get()); assert(ctx);
    auto mm = ctx->getstream();
    assert(mm != nullptr);

    delete mm->mp_stream;
    SSL_CTX_free(mm->ctx);
    SSL_free(mm->ssl);
} //}
bool EBStreamTLS::accept(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->getType() == stream->getType());
    TLSUS* stream__ = dynamic_cast<decltype(stream__)>(stream.get());
    assert(stream__);
    return this->m_ctx->mp_stream->accept(stream__->getstream()->mp_stream);
} //}

void EBStreamTLS::shutdown(ShutdownCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx != nullptr);
    if(this->in_read()) this->stop_read();
    auto ctx = this->m_ctx;
    ctx->mp_stream->removeall();
    ctx->mp_stream->storePtr(nullptr);
    this->m_ctx = nullptr;
    return UNST(new TLSUS(this->getType(), ctx));
} //}
void EBStreamTLS::regain(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_ctx == nullptr);
    assert(this->getType() == stream->getType());
    TLSUS* ctx = dynamic_cast<decltype(ctx)>(stream.get()); assert(ctx);
    this->m_ctx = ctx->getstream();
    assert(this->m_ctx->mp_stream->fetchPtr() == nullptr);
    this->m_ctx->mp_stream->storePtr(this);
    this->register_listener();
} //}

void  EBStreamTLS::release() //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    return (this->m_ctx != nullptr);
} //}

bool EBStreamTLS::timeout(TimeoutCallback cb, void* data, int time_ms) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_ctx->mp_stream->SetTimeout(cb, data, time_ms);
    return true;
} //}

EBStreamTLS::~EBStreamTLS() //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->hasStreamObject())
        this->release();
} //}

EBStreamTLS::UNST EBStreamTLS::createStreamWrapper(EBStreamTLSCTX* ctx) //{
{
    return UNST(new TLSUS(this->getType(), ctx));
} //}

/** [static] */
EBStreamTLS::EBStreamTLSCTX* EBStreamTLS::getCTXFromWrapper(UNST stream) //{
{
    TLSUS* m = dynamic_cast<decltype(m)>(stream.get()); assert(m);
    return m->getstream();
} //}
void EBStreamTLS::releaseCTX(EBStreamTLSCTX* mm) //{
{
    assert(mm != nullptr);

    if(mm->mp_stream) delete mm->mp_stream;
    SSL_CTX_free(mm->ctx);
    BIO_free(mm->rbio);
    BIO_free(mm->wbio);
    SSL_free(mm->ssl);
    delete mm;
} //}

/** [static] */
EBStreamTLS::EBStreamTLSCTX* EBStreamTLS::getCTX(TLSMode mode, EBStreamObject* stream, //{
        const std::string& cert, const std::string& privatekey)
{
    DEBUG("call %s", FUNCNAME);
    EBStreamTLSCTX* ans = new std::remove_pointer_t<decltype(ans)>();
    ans->mode = mode;

    ans->ctx = SSL_CTX_new(TLS_method());

    if(ans->mode == TLSMode::ServerMode) {
        if(SSL_CTX_use_certificate(ans->ctx, str_to_x509(cert)) != 1) {
            // FIXME ??? seems this assert is too strict, but this function will 
            // be called from constructor and error handler call virtual function the behavior
            // is unexpected
            assert(false && "bad certificate");
            return nullptr;
        }
        if(SSL_CTX_use_PrivateKey (ans->ctx, str_to_privateKey(privatekey)) != 1) {
            assert(false && "bad private key");
            return nullptr;
        }
        if(SSL_CTX_check_private_key(ans->ctx) != 1) {
            assert(false && "inconsistent certificate and private key");
            return nullptr;
        }
    }

    ans->rbio = BIO_new(BIO_s_mem());
    ans->wbio = BIO_new(BIO_s_mem());
    ans->ssl  = SSL_new(ans->ctx);

    if(ans->mode == TLSMode::ServerMode)
        SSL_set_accept_state(ans->ssl);
    else
        SSL_set_connect_state(ans->ssl);

    SSL_set_bio(ans->ssl, ans->rbio, ans->wbio);

    ans->mp_stream = stream;
    return ans;
} //}

NS_EVLTLS_END


