// 整数运算：产出 IADD3 / LOP3 / SHF / IMNMX 等
__global__ void int_kernel(int* o, int x, int y) {
    int i = threadIdx.x;
    o[i] = ((x + y) ^ (x << 3)) | (x > y ? x : y);
}
