#pragma once

#include "stream.h"
#include "shared_memory.h"
#include "internal/config.h"


NS_EVLTLS_START


/**
 * @event drain
 * @event data
 * @event connect
 * @event connection
 * @event end
 * @event error
 * @event close
 *
 * @event shouldStartWrite
 * @event shouldStopWrite
 */
class EBStreamObject: virtual protected EBStreamAbstraction, virtual protected CallbackManager, virtual public EventEmitter //{
{
    public:
        using WriteCallback       = EBStreamAbstraction::WriteCallback;
        using ConnectCallback     = EBStreamAbstraction::ConnectCallback;
        using GetAddrInfoCallback = EBStreamAbstraction::GetAddrInfoCallback;
        struct DataArgs: public EventArgs::Base {
            SharedMem _buf;
            inline DataArgs(SharedMem buf): _buf(buf) {}
        };
        struct ErrorArgs: public EventArgs::Base {
            std::string _msg;
            inline ErrorArgs(const std::string& err): _msg(err) {}
        };
        struct DrainArgs: public EventArgs::Base {};
        struct CloseArgs: public EventArgs::Base {};
        struct EndArgs: public EventArgs::Base {};
        struct ConnectArgs: public EventArgs::Base {};
        struct ConnectionArgs: public EventArgs::Base {
            UNST connection;
            inline ConnectionArgs(UNST con): connection(con) {}
        };

        struct ShouldStartWriteArgs: public EventArgs::Base {};
        struct ShouldStopWriteArgs:  public EventArgs::Base {};


    private:
        size_t m_max_write_buffer_size;
        size_t m_writed_size;

        bool m_end;
        bool m_closed;

        void* m_store_ptr;

        static void write_callback(SharedMem, int status, void* data);
        static void __write_callback(SharedMem, int status, void* data);
        static void connect_callback(int status, void* data);


    protected:
        virtual void read_callback(SharedMem buf, int status) override;
        virtual void end_signal() override;

        virtual void should_start_write() override;
        virtual void should_stop_write () override;

        virtual void on_connection(UNST) override;


    public:
        EBStreamObject(size_t max_write_buffer_size);

        using EBStreamAbstraction::bind;
        using EBStreamAbstraction::bind_ipv4;
        using EBStreamAbstraction::bind_ipv6;
        using EBStreamAbstraction::listen;
        using EBStreamAbstraction::in_read;

        using EBStreamAbstraction::getaddrinfo;
        using EBStreamAbstraction::getaddrinfoipv4;
        using EBStreamAbstraction::getaddrinfoipv6;

        void __write(SharedMem buf, WriteCallback cb, void* data);
        int  write(SharedMem);
        bool connectTo(struct sockaddr*);
        bool connectTo(uint32_t ipv4, uint16_t port);
        bool connectTo(uint8_t ipv6[16], uint16_t port);
        bool connectTo(const std::string& addr, uint16_t port);
        void getDNS(const std::string& addr, GetAddrInfoCallback cb, void* data);
        void startRead();
        void stopRead();
        void end();
        void close();

        virtual bool accept(EBStreamObject* stream) = 0;
        
        void SetTimeout(TimeoutCallback cb, void* data, int time_ms);

        void  storePtr(void* ptr);
        void* fetchPtr();

        using EBStreamAbstraction::speed_out;
        using EBStreamAbstraction::speed_in;
        using EBStreamAbstraction::traffic_out;
        using EBStreamAbstraction::traffic_in;
        using EBStreamAbstraction::remote_addr;
        using EBStreamAbstraction::remote_port;
        using EBStreamAbstraction::local_addr;
        using EBStreamAbstraction::local_port;

        virtual ~EBStreamObject();

        virtual EBStreamObject* NewStreamObject();
        virtual EBStreamObject* NewStreamObject(UNST) = 0;
}; //}


NS_EVLTLS_END

