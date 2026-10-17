// 类型转换：产出 F2I / I2F / F2F / I2I（含 64 位，触发 CVT64 派生标记）
__global__ void cvt_kernel(double* od, float* of, long long* ol, int* oi,
                           double d, float f, int n, long long l) {
    int i = threadIdx.x;
    od[i] = (double)n + (double)f;
    of[i] = (float)d + (float)l;
    ol[i] = (long long)d + (long long)f;
    oi[i] = (int)f + (int)d + (int)(short)n + (int)(unsigned char)n;
}
