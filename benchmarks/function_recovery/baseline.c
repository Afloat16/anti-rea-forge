#include <stdint.h>

uint32_t rg_compute(uint32_t x)
{
    uint32_t state = x ^ UINT32_C(0x9fce3e75);

    if ((x & UINT32_C(0x1041)) != 0) {
        state += UINT32_C(0x5780e43f);
    } else {
        state = (state << 4) | (state >> 28);
    }

    switch ((x >> 4) & UINT32_C(3)) {
    case 0:
        state ^= UINT32_C(0x179f0237);
        break;
    case 1:
        state += x * UINT32_C(0x4c584ce9);
        break;
    case 2:
        state = (state ^ (state >> 6)) * UINT32_C(0xf214b087);
        break;
    default:
        state += UINT32_C(0x00d672bb);
        break;
    }

    for (uint32_t round = 0; round < UINT32_C(3); ++round) {
        if (((state >> round) & UINT32_C(1)) == 0) {
            state = state * UINT32_C(0x1808fff1) + x + round;
        } else {
            state ^= UINT32_C(0x6c9c4a69);
            state = (state << 6) | (state >> 26);
        }
    }

    return state ^ (state >> 8);
}
