#include "../include/evtls/stream.h"
#include "../include/evtls/object_manager.h"

#include "../include/evtls/logger.h"
#include "../include/evtls/internal/config__.h"


#define DEBUG(all...) __logger->debug(all)


NS_EVLTLS_START


EBStreamAbstraction::EBStreamAbstraction() noexcept //{
{
    this->m_stat_speed_in = 0;
    this->m_stat_speed_out = 0;
    this->m_stat_traffic_in = 0;
    this->m_stat_traffic_out = 0;
    this->m_waiting_calculating = false;
} //}

struct __prev_traffic: public CallbackPointer {
    EBStreamAbstraction* _this;
    size_t _prev_out;
    size_t _prev_in;
    inline __prev_traffic(EBStreamAbstraction* _this, size_t prev_out, size_t prev_in): _this(_this), _prev_out(prev_out), _prev_in(prev_in) {}
};
void EBStreamAbstraction::recalculatespeed() //{
{
    if(this->m_waiting_calculating) return;
    auto ptr = new __prev_traffic(this, this->m_stat_traffic_out, this->m_stat_traffic_in);
    this->add_callback(ptr);

    if(!this->timeout(calculate_speed_callback, ptr, STREAM_RECALCULATE_SPEED_PER)) {
        this->remove_callback(ptr);
        delete ptr;
    } else {
        this->m_waiting_calculating = true;
    }
} //}
/** [static] */
void EBStreamAbstraction::calculate_speed_callback(void* data) //{
{
    __prev_traffic* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto _prev_out = msg->_prev_out;
    auto _prev_in = msg->_prev_in;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    _this->m_waiting_calculating = false;
    auto speed_out = (_this->m_stat_traffic_out - _prev_out) / STREAM_RECALCULATE_SPEED_PER;
    auto speed_in  = (_this->m_stat_traffic_in  - _prev_in ) / STREAM_RECALCULATE_SPEED_PER;
    _this->m_stat_speed_out = speed_out;
    _this->m_stat_speed_in  = speed_in;

    _this->recalculatespeed();
} //}

size_t EBStreamAbstraction::speed_out() //{
{
    this->recalculatespeed();
    return this->m_stat_speed_out;
} //}
size_t EBStreamAbstraction::speed_in() //{
{
    this->recalculatespeed();
    return this->m_stat_speed_in;
} //}
size_t EBStreamAbstraction::traffic_out() //{
{
    return this->m_stat_traffic_out;
} //}
size_t EBStreamAbstraction::traffic_in() //{
{
    return this->m_stat_traffic_in;
} //}
std::string EBStreamAbstraction::remote_addr() //{
{
    return "";
} //}
std::string EBStreamAbstraction::local_addr()  //{
{
    return "";
} //}
uint16_t EBStreamAbstraction::remote_port() //{
{
    return 0;
} //}
uint16_t EBStreamAbstraction::local_port()  //{
{
    return 0;
} //}


#if defined(_WIN32) || defined(_WIN64) // sockaddr_in sockaddr_in6
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif // defined(_WIN32) || defined(_WIN64)
bool EBStreamAbstraction::bind_ipv4(uint16_t port, uint32_t ipv4) //{
{
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ipv4);
    return this->bind((::sockaddr*)(&addr));
} //}
bool EBStreamAbstraction::bind_ipv6(uint16_t port, uint8_t ipv6[16]) //{
{
    sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    if(ipv6 == nullptr)
        memset(&addr.sin6_addr, 0, sizeof(addr.sin6_addr));
    else
        memcpy(&addr.sin6_addr, ipv6, sizeof(addr.sin6_addr));
    return this->bind((::sockaddr*)(&addr));
} //}


NS_EVLTLS_END

