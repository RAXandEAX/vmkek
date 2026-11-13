#include <stdint.h>

uint64_t plain(uint64_t x, uint64_t b, uint64_t a, uint64_t k) {
    (void)k;
    return (x + b) * a;
}

uint64_t immediate_pair(uint64_t x, uint64_t b, uint64_t a, uint64_t k) {
    x = (x ^ k) ^ k;
    return (x + b) * a;
}

uint64_t encoded_region(uint64_t x, uint64_t b, uint64_t a, uint64_t k) {
    uint64_t encoded = x + k;
    encoded = encoded + b;
    encoded = encoded * a + (1 - a) * k;
    return encoded - k;
}
