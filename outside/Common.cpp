#include <outside/Common.h>
#include <sys/time.h>

uint64_t get_current_time_ms() {
    struct timeval tm;
    gettimeofday(&tm, NULL);
    return (uint64_t)tm.tv_sec * 1000 + tm.tv_usec / 1000;
}
