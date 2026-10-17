// 半精度：产出 HADD2 / HFMA2 / HMUL2 / HSETP2 / HMNMX2
#include <cuda_fp16.h>
__global__ void half_kernel(__half2* o, const __half2* a, const __half2* b) {
    int i = threadIdx.x;
    __half2 x = a[i], y = b[i];
    __half2 r = __hfma2(x, y, __hadd2(x, y));
    r = __hmul2(r, __hsub2(x, y));
    __half2 g = __hgt2(x, y);
    r = __hadd2(__hmul2(g, __hmax2(r, x)),
                __hmul2(__hsub2(__float2half2_rn(1.0f), g), __hmin2(r, y)));
    o[i] = r;
}
