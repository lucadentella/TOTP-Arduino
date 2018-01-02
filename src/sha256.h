#ifndef Sha256_h
#define Sha256_h

#include <inttypes.h>
#include "Print.h"

#if ARDUINO < 100
#define __WRITE_RESULT void
#define __WRITE_RETURN(x) return;
#else
#define __WRITE_RESULT size_t
#define __WRITE_RETURN(x) return x;
#endif

#define SHA256_HASH_LENGTH 32
#define SHA256_BLOCK_LENGTH 64

union _sha256_buffer {
  uint8_t b[SHA256_BLOCK_LENGTH];
  uint32_t w[SHA256_BLOCK_LENGTH/4];
};
union _sha256_state {
  uint8_t b[SHA256_HASH_LENGTH];
  uint32_t w[SHA256_HASH_LENGTH/4];
};

class Sha256Class : public Print
{
  public:
    void init(void);
    void initHmac(const uint8_t* secret, int secretLength);
    uint8_t* result(void);
    uint8_t* resultHmac(void);
    virtual __WRITE_RESULT write(uint8_t);
    using Print::write;
  private:
    void pad();
    void addUncounted(uint8_t data);
    void hashBlock();
    uint32_t ror32(uint32_t number, uint8_t bits);
    _sha256_buffer buffer;
    uint8_t bufferOffset;
    _sha256_state state;
    uint32_t byteCount;
    uint8_t keyBuffer[SHA256_BLOCK_LENGTH];
    uint8_t innerHash[SHA256_HASH_LENGTH];
};
extern Sha256Class Sha256;

#endif