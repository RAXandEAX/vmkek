#include <stdint.h>
uint64_t hard_constant(void) {
    uint64_t v = UINT64_C(0xc30b150000007a11);
    v *= UINT64_C(0x6c622725);
    v ^= v >> 16;
    v *= UINT64_C(0x5bd1e995);
    v ^= v >> 13;
    return v & UINT64_C(0xffff);
}
uint64_t xor_pair(uint64_t x, uint64_t k) { return (x ^ k) ^ k; }
uint64_t mul_pair(uint64_t x) { return (x * UINT64_C(3)) * UINT64_C(0xaaaaaaaaaaaaaaab); }
