#include <stdint.h>
uint64_t separate(uint64_t a, uint64_t b, uint64_t c) { uint64_t t = a + b; return t ^ c; }
uint64_t pair(uint64_t a, uint64_t b, uint64_t c) { uint64_t t = a + b; return t ^ c; }
uint64_t fused(uint64_t a, uint64_t b, uint64_t c) { return (a + b) ^ c; }
