#pragma once

#include "stream.h"
#include "stream_tls.h"
#include "stream_object.h"
#include "internal/config.h"

NS_EVLTLS_START


class StreamObjectTLS: public EBStreamObject, public EBStreamTLS //{
{
    public:
        StreamObjectTLS(size_t max_buffer, TLSMode mode);
}; //}


NS_EVLTLS_END

