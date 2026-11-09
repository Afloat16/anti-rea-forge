#include <stdint.h>
#include <stdio.h>
uint32_t rg_compute(uint32_t);
int main(void) {
    unsigned char in[4], out[4];
    size_t n;
    while ((n = fread(in, 1, 4, stdin)) == 4) {
        uint32_t x = (uint32_t)in[0] | (uint32_t)in[1] << 8 | (uint32_t)in[2] << 16 | (uint32_t)in[3] << 24;
        uint32_t y = rg_compute(x);
        for (unsigned i = 0; i < 4; ++i) out[i] = (unsigned char)(y >> (i * 8));
        if (fwrite(out, 1, 4, stdout) != 4) return 2;
    }
    return n == 0 && !ferror(stdin) && fflush(stdout) == 0 ? 0 : 2;
}
