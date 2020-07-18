#include "../include/evltls/stream.h"
#include "../include/evltls/object_manager.h"

#include "../include/evltls/logger.h"
#include "../include/evltls/internal/config.h"


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


NS_EVLTLS_END

