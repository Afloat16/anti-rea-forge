#include <stdint.h>

uint32_t rg_compute(uint32_t x)
{
    uint32_t value = x ^ UINT32_C(0x9fce3e75);

    if ((x & UINT32_C(0x1041)) == 0) {
        value = (value << 4) | (value >> 28);
    } else {
        value += UINT32_C(0x5780e43f);
    }

    switch ((x >> 4) & UINT32_C(3)) {
    case 0:
        value ^= UINT32_C(0x179f0237);
        break;
    case 1:
        value += x * UINT32_C(0x4c584ce9);
        break;
    case 2:
        value = (value ^ (value >> 6)) * UINT32_C(0xf214b087);
        break;
    case 3:
        value += UINT32_C(0x00d672bb);
        break;
    }

    for (uint32_t round = 0; round < 3; ++round) {
        if ((value & (UINT32_C(1) << round)) == 0) {
            value = value * UINT32_C(0x1808fff1) + x + round;
        } else {
            value ^= UINT32_C(0x6c9c4a69);
            value = (value << 6) | (value >> 26);
        }
    }

    return value ^ (value >> 8);
}
