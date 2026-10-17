// 原子操作：产出 ATOMG / ATOMS / RED / ATOM.CAS
__global__ void atomic_kernel(int* g, float* gf, unsigned* gu) {
    __shared__ int s[64];
    int i = threadIdx.x;
    s[i & 63] = 0;
    __syncthreads();
    atomicAdd(&s[i & 63], i);
    atomicAdd(g + (i & 15), i);
    atomicAdd(gf + (i & 15), 1.0f);
    atomicMax(g + 1, i);
    atomicAnd(gu, (unsigned)i);
    atomicExch(g + 2, i);
    atomicCAS(gu + 1, 0u, (unsigned)i);
    __syncthreads();
    g[3] = s[i & 63];
}
