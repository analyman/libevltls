#pragma once

#include "../logger.h"
#define __logger Logger::logger

#if defined(_WIN32) || defined(_WIN64)
#define FUNCNAME __func__
#else
#define FUNCNAME __PRETTY_FUNCTION__
#endif // defined(_WIN32) || defined(_WIN64)

/** speed recalculate timeout */
#define STREAM_RECALCULATE_SPEED_PER 500

/** maximum waiting time of tls connect request */
#define MAX_TLS_CONNECT_TIMEOUT (8000)

