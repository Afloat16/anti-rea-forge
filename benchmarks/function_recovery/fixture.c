#include <stdint.h>
__attribute__((noinline,used)) uint32_t rg_compute(uint32_t x) {
    uint32_t v = x ^ 2681093749u;
    if ((x & 0x1041u) != 0) v += 1468064831u;
    else v = (v << 4) | (v >> (32 - 4));
    switch ((x >> 4) & 3u) {
        case 0: v ^= 396296759u; break;
        case 1: v += x * 1280855273u; break;
        case 2: v = (v ^ (v >> 6)) * 4061442183u; break;
        default: v -= 4280913221u; break;
    }
    for (uint32_t i = 0; i < 3; ++i) {
        if (((v >> i) & 1u) != 0) {
            v ^= 1822181993u;
            v = (v << 6) | (v >> (32 - 6));
        } else v = v * 403242993u + x + i;
    }
    return v ^ (v >> 8);
}
