#ifndef _INSIDE_IDMANAGER_H_
#define _INSIDE_IDMANAGER_H_
#include <unordered_map>


class IDManager {
    uint32_t cur_max_id_;
    std::unordered_set<uint32_t> freelist_;

public:
    IDManager() :
        cur_max_id_(1) // 0 reserved
    {}

    uint32_t MakeID() {
        if (freelist_.size()) {
            uint32_t i = *(freelist_.first());
            freelist_.remove(i);
            return i;
        } else {
            return cur_max_id_++;
        }
    }

    void ReleaseID(const uint32_t i) {
        freelist_.insert(i);
    }
};

#endif



