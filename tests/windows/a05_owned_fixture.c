#include <stdint.h>

#pragma code_seg(".a05rx")
__declspec(dllexport) __declspec(noinline) uint32_t a05_probe(uint32_t input) {
    volatile uint32_t value = input;
    value += 5;
    return value * 2;
}
#pragma code_seg()

#pragma section(".a05mark", read, execute)
__declspec(allocate(".a05mark")) static const unsigned char marker[16] = {
    0x51, 0x62, 0x73, 0x84, 0x95, 0xa6, 0xb7, 0xc8,
    0xd9, 0xea, 0xfb, 0x0c, 0x1d, 0x2e, 0x3f, 0x40
};

__declspec(dllexport) const unsigned char *a05_marker(void) {
    return marker;
}

__declspec(dllexport) __declspec(noinline) uint32_t a05_run(void) {
    return a05_probe(17);
}

__declspec(dllexport) uint32_t a05_witness(void) {
    return 0xa05;
}
