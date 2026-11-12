#include <stddef.h>

#ifndef VMKEK_A04_REVISION
#define VMKEK_A04_REVISION 1
#endif

#pragma section(".a04rx", read, execute)
__declspec(allocate(".a04rx")) static const unsigned char markers[32] = {
    VMKEK_A04_REVISION, 0x13, 0x29, 0x37, 0x41, 0x53, 0x67, 0x79,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};
__declspec(allocate(".a04rx")) static const void *const relocated = markers;

__declspec(dllexport) const void *a04_range(unsigned int index) {
    switch (index) {
    case 0: return markers;
    case 1: return markers + 16;
    case 2: return &relocated;
    default: return NULL;
    }
}

__declspec(dllexport) unsigned int a04_call(void) {
    return VMKEK_A04_REVISION;
}
