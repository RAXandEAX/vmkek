#include <stdint.h>

#define A UINT64_C(0x7fffffffffffffff)
#define B UINT64_C(4)

uint64_t r06_reference(uint64_t word) {
    return (word + A) + B;
}

uint64_t r06_add_pair(uint64_t word) {
    return word + (A + B);
}

uint64_t r06_subtract_negated_pair(uint64_t word) {
    return word - (UINT64_C(0) - (A + B));
}
