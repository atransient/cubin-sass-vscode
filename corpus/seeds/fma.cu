// 浮点乘加 + 索引计算：产出 FFMA / IMAD / IMAD.WIDE / LDG / STG
__global__ void fma_kernel(float* a, float* b, float* c) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    c[i] = a[i] * b[i] + c[i];
}
