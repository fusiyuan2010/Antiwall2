#ifndef _COMMON_ENCRYPTIONCTX_H_
#define _COMMON_ENCRYPTIONCTX_H_
#include <string>
#include <cstdlib>
#include <cstring>


class EncryptionCtx {

    uint8_t *key_;
    int keylen_;
    int pos_;
    
public:
    EncryptionCtx() 
        : key_(NULL), pos_(0) {
    }

    ~EncryptionCtx() {
        if (key_) 
            free(key_);
    }

    static void MakeRandomKey(uint8_t *key, int len) {
        for (int i = 0; i < len; i++) {
            key[i] = rand() % 256;
        }
    }

    void SetKey(uint8_t *key, int len) {
        if (key_)
            free(key_);
        key_ = (uint8_t *)malloc(len);
        memcpy(key_, key, len);
        keylen_ = len;
    }

    void Encrypt(void *buf_, int len) {
        //return;
        uint8_t *buf = (uint8_t *)buf_;
        for (int i = 0; i < len; i++) {
            buf[i] ^= key_[pos_];
            pos_++;
            pos_ %= keylen_;
        }
    }

    void Decrypt(void *buf, int len) {
        // symmatric currently
        Encrypt(buf, len);
    }
};

#endif

