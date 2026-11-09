#include <stdint.h>

/*
 * Independently recovered from the published VM interpreter and decoded
 * bytecode. This implementation contains only the resulting uint32_t
 * arithmetic and control flow.
 */
static uint32_t rotate_left(uint32_t value, unsigned int amount)
{
    return (value << amount) | (value >> (32U - amount));
}

uint32_t rg_compute(uint32_t x)
{
    uint32_t value = x ^ UINT32_C(2681093749);

    if ((x & UINT32_C(4161)) == 0U) {
        value = rotate_left(value, 4U);
    } else {
        value += UINT32_C(1468064831);
    }

    switch ((x >> 4U) & 3U) {
    case 0U:
        value ^= UINT32_C(396296759);
        break;
    case 1U:
        value += x * UINT32_C(1280855273);
        break;
    case 2U:
        value = (value ^ (value >> 6U)) * UINT32_C(4061442183);
        break;
    default:
        value += UINT32_C(14054075);
        break;
    }

    for (uint32_t round = 0U; round < 3U; ++round) {
        if ((value & (UINT32_C(1) << round)) == 0U) {
            value = value * UINT32_C(403242993) + round + x;
        } else {
            value = rotate_left(value ^ UINT32_C(1822181993), 6U);
        }
    }

    return value ^ (value >> 8U);
}
