#include <common/TrafficMeter.h>

TrafficMeter::TrafficMeter() 
{
    for(int i = 0; i < MAX_SAMPLE_WINDOW; i++) 
        ts_[i] = 0;
}

void TrafficMeter::UpdateSample(int size) 
{
    time_t t = time(NULL);
    if (ts_[t % MAX_SAMPLE_WINDOW] == t)
        bytes_[t % MAX_SAMPLE_WINDOW] += size;
    else {
        bytes_[t % MAX_SAMPLE_WINDOW] = size;
        ts_[t % MAX_SAMPLE_WINDOW] = t;
    }
}

int TrafficMeter::GetSpeed(int window_size) 
{
    time_t t = time(NULL);
    int total = 0;
    for(int i = 0; i < window_size; i++) {
        int p = (t - i) % MAX_SAMPLE_WINDOW;
        if (t - i == ts_[p])
            total += bytes_[p];
    }
    return total / window_size;
}


