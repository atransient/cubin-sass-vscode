// warp 级：产出 VOTE / VOTEU / SHFL / MATCH / WARPSYNC / BAR
__global__ void warp_kernel(int* o, int x) {
    int i = threadIdx.x;
    unsigned m = __activemask();
    int r = __shfl_sync(m, x, 0);
    r += __shfl_down_sync(m, x, 1);
    r += __shfl_xor_sync(m, x, 2);
    r += __any_sync(m, x > 0) + __all_sync(m, x > 0);
    r += (int)__ballot_sync(m, x & 1);
    r += (int)__match_any_sync(m, x);
    __syncwarp();
    __syncthreads();
    o[i] = r;
}
