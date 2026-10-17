// 位域与选择：产出 BFE / BFI / LEA / IMNMX / SEL / PLOP3
__global__ void bitfield_kernel(unsigned* o, unsigned x, unsigned y, int n) {
    int i = threadIdx.x;
    unsigned r = (x >> (n & 31)) & ((1u << 5) - 1);
    r |= (y & 0xff) << 12;
    r += (unsigned)((long long)x * 4 + y);
    bool p = (x > y), q = (n > 0);
    o[i] = (p && q) ? r : (p || q) ? ~r : r ^ y;
}
