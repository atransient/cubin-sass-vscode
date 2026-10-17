// local memory：产出 LDL / STL（数组下标动态、无法放进寄存器）
__global__ void local_kernel(int* o, int n) {
    int buf[48];
    int i = threadIdx.x;
    for (int k = 0; k < 48; ++k) buf[k] = k * n + i;
    int s = 0;
    for (int k = 0; k < 48; ++k) s += buf[(k * n + i) % 48];
    o[i] = s;
}
