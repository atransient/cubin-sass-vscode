// uniform 数据通路：产出 ULDC / UIADD3 / UMOV / USHF / UIMAD / S2UR
__global__ void uniform_kernel(int* o, const int* __restrict__ base, int n) {
    int i = threadIdx.x;
    int b = blockIdx.x;
    // 与线程无关的量走 uniform 寄存器
    int u = n * 3 + b * 7;
    o[i] = base[u + (i & 31)] + (u << 2);
}
