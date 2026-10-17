// 位操作：产出 POPC / BREV / FLO / SHF / PRMT / LOP3
__global__ void bits_kernel(unsigned* o, unsigned x, unsigned y) {
    int i = threadIdx.x;
    unsigned r = __popc(x) + __brev(y) + __clz(x);
    r ^= __funnelshift_l(x, y, 5);
    r += __funnelshift_r(x, y, 11);
    r |= __byte_perm(x, y, 0x4321);
    o[i] = r & ~(x | y);
}
