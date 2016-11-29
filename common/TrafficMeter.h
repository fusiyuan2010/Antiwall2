#ifndef _COMMON_TRAFFICMETER_H_
#define _COMMON_TRAFFICMETER_H_
#include <ctime>


class TrafficMeter {
    static const int MAX_SAMPLE_WINDOW = 60;
    int bytes_[MAX_SAMPLE_WINDOW];
    time_t ts_[MAX_SAMPLE_WINDOW];
public:
    TrafficMeter();
    void UpdateSample(int size);
    int GetSpeed(int window_size);
};

#endif

