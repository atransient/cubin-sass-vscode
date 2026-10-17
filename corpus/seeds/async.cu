// 异步拷贝与屏障：产出 LDGSTS / LDGDEPBAR / DEPBAR / BAR.ARV
#include <cuda_pipeline.h>
__global__ void async_kernel(float* o, const float* g) {
    __shared__ float sh[256];
    int i = threadIdx.x;
    __pipeline_memcpy_async(&sh[i & 255], &g[i], sizeof(float));
    __pipeline_commit();
    __pipeline_wait_prior(0);
    __syncthreads();
    o[i] = sh[(i + 3) & 255];
}
