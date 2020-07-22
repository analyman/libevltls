#include "../include/evtls/stream_object.h"
#include "../include/evtls/logger.h"
#include "../include/evtls/internal/config__.h"


#define DEBUG(all...) __logger->debug(all)


NS_EVLTLS_START


void EBStreamObject::read_callback(SharedMem buf, int status) //{
{
    DEBUG("call %s", FUNCNAME);
    if(status == 0) {
        this->emit("data", new DataArgs(buf));
    } else {
        this->emit("error", new ErrorArgs("read error"));
    }
} //}
void EBStreamObject::end_signal() //{
{
    DEBUG("call %s", FUNCNAME);
    this->emit("end", new EndArgs());
} //}

void EBStreamObject::on_connection(UNST con) //{
{
    DEBUG("call %s", FUNCNAME);
    this->emit("connection", new ConnectionArgs(con));
} //}

void EBStreamObject::should_start_write() //{
{
    DEBUG("call %s", FUNCNAME);
    this->emit("shouldStartWrite", new ShouldStartWriteArgs());
} //}
void EBStreamObject::should_stop_write() //{
{
    DEBUG("call %s", FUNCNAME);
    this->emit("shouldStopWrite", new ShouldStopWriteArgs());
} //}


EBStreamObject::EBStreamObject(size_t m) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_max_write_buffer_size = m;
    this->m_writed_size = 0;
    this->m_closed = false;
    this->m_end = false;
    this->m_store_ptr = nullptr;
} //}

struct EBStreamObject$write$_write: public CallbackPointer {
    EBStreamObject* _this;
    size_t _n;
    inline EBStreamObject$write$_write(EBStreamObject* _this, size_t n): _this(_this), _n(n) {}
};
int EBStreamObject::write(SharedMem buf) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    this->m_writed_size += buf.size();
    auto ptr = new EBStreamObject$write$_write(this, buf.size());
    this->add_callback(ptr);
    this->_write(buf, write_callback, ptr);
    return (this->m_writed_size > this->m_max_write_buffer_size) ? -1 : 0;
} //}
/** [static] */
void EBStreamObject::write_callback(SharedMem buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    EBStreamObject$write$_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto _this = msg->_this;
    auto n     = msg->_n;
    auto run   = msg->CanRun();
    delete msg;
    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->emit("error", new ErrorArgs("write error"));
        return;
    }

    _this->m_writed_size -= n;
    if(_this->m_writed_size <= _this->m_max_write_buffer_size &&
       _this->m_writed_size + n > _this->m_max_write_buffer_size)
        _this->emit("drain", new DrainArgs());
    return;
} //}

struct __write_state: public CallbackPointer {
    EBStreamObject* _this;
    EBStreamObject::WriteCallback _cb;
    void* _data;
    size_t _n;
    inline __write_state(EBStreamObject* _this, EBStreamObject::WriteCallback cb, void* data, size_t n):
        _this(_this), _cb(cb), _data(data), _n(n) {}
};
void EBStreamObject::__write(SharedMem buf, WriteCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    this->m_writed_size += buf.size();
    auto ptr = new __write_state(this, cb, data, buf.size());
    this->add_callback(ptr);
    this->_write(buf, __write_callback, ptr);
} //}
/** [static] */
void EBStreamObject::__write_callback(SharedMem buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __write_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto _this = msg->_this;
    auto _cb   = msg->_cb;
    auto _data = msg->_data;
    auto _n    = msg->_n;
    auto run   = msg->CanRun();
    delete msg;
    if(!run) {
        _cb(SharedMem(), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        _cb(SharedMem(), -1, _data);
        return;
    }

    _this->m_writed_size -= _n;
    if(_this->m_writed_size <= _this->m_max_write_buffer_size &&
       _this->m_writed_size + _n > _this->m_max_write_buffer_size)
        _this->emit("drain", new DrainArgs());
    _cb(buf, 0, _data);
    return;
} //}

struct EBStreamObject$connectWith_sockaddr$connect: public CallbackPointer {
    EBStreamObject* _this;
    inline EBStreamObject$connectWith_sockaddr$connect(EBStreamObject* _this): _this(_this) {}
};
bool EBStreamObject::connectTo(struct sockaddr* addr) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(addr, connect_callback, ptr);
} //}
bool EBStreamObject::connectTo(const std::string& addr, uint16_t port) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this); // FIXME LOSS
    this->add_callback(ptr);
    return this->connect(addr, port, connect_callback, ptr);
} //}
bool EBStreamObject::connectTo(uint32_t ipv4, uint16_t port) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(ipv4, port, connect_callback, ptr);
} //}
bool EBStreamObject::connectTo(uint8_t ipv6[16], uint16_t port) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(ipv6, port, connect_callback, ptr);
} //}
/** [static] */
void EBStreamObject::connect_callback(int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
   EBStreamObject$connectWith_sockaddr$connect* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto _this = msg->_this;
    auto run   = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->emit("error", new ErrorArgs("connect error"));
        return;
    }

    _this->emit("connect", new ConnectArgs());
} //}

void EBStreamObject::getDNS(const std::string& addr, GetAddrInfoCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->getaddrinfo(addr.c_str(), cb, data);
} //}

void EBStreamObject::startRead() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false); 
    this->start_read();
} //}
void EBStreamObject::stopRead()  //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false); 
    this->stop_read();
} //}
static void dummy_end_callback(int, void*) {}
void EBStreamObject::end()       //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false); 
    this->m_end = true; 
    this->shutdown(dummy_end_callback, nullptr);
} //}

void EBStreamObject::close() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;
    this->emit("close", new CloseArgs());
} //}

void EBStreamObject::SetTimeout(TimeoutCallback cb, void* data, int time_ms) {this->timeout(cb, data, time_ms);}

void  EBStreamObject::storePtr(void* ptr) {this->m_store_ptr = ptr;}
void* EBStreamObject::fetchPtr() {return this->m_store_ptr;}

EBStreamObject::~EBStreamObject() {}

EBStreamObject* EBStreamObject::NewStreamObject() {return this->NewStreamObject(this->newUnderlyStream());}

NS_EVLTLS_END

