// 双精度：产出 DADD / DMUL / DFMA / DSETP / MUFU.RCP64H
__global__ void dbl_kernel(double* o, double a, double b) {
    int i = threadIdx.x;
    double r = fma(a, b, a + b) * (a - b);
    r = r / b;
    o[i] = (a < b) ? r : -r;
}
