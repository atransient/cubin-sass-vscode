// 执行 oracle 专用种子（P1-A-5）：给 CVT 一族提供**原生宿主**。
//
// `gpu_fuzz.py` 要求宿主 kernel 本来就含有被测的助记符 —— 把一条 F2F 塞进 FFMA
// 的槽位，nvdisasm 和驱动判的是上下文非法，跟被扫的位无关。而 `corpus/seeds/cvt.cu`
// 虽然有 F2F/F2I/I2F，签名却是 (double*,float*,long long*,int*,...)，与
// `nvisa/oracle/runner.c` 的三个 float 缓冲对不上，未改动的宿主自己就跑不出结果，
// 执行那一路等于没有。
//
// 这里沿用 execfma.cu 的固定形状 (float*,float*,float*)，同时让编译器发出
// FRND（rintf/truncf）、F2FP（float2 -> half2 打包）和 F2F/F2I/I2F。
// 语义已知：a=2 b=3 c=1 时 c[0] 的期望值见下面的注释。
#include <cuda_fp16.h>

extern "C" __global__ void f(float* a, float* b, float* c) {
    int i = threadIdx.x;
    float x = a[i] * b[i];              // 6.0
    float r = rintf(x + 0.4f);          // FRND.ROUND        -> 6.0
    float t = truncf(x + 0.9f);         // FRND.TRUNC        -> 6.0
    double d = (double)r;               // F2F.F64.F32
    int   n  = (int)t;                  // F2I.S32.F32       -> 6
    float back = (float)(d + (double)n);// F2F.F32.F64       -> 12.0
    __half2 h = __float22half2_rn(make_float2(back, c[i]));  // F2FP
    float2 f2 = __half22float2(h);
    c[i] = f2.x + f2.y;                 // 12.0 + 1.0 = 13.0
}
