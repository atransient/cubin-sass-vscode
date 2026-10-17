// 访存宽度与作用域：产出 LDG/STG 的 .64/.128/.U8/.S16、LDS/STS、LD/ST
__global__ void mem_kernel(float4* o4, float2* o2, char* oc, short* os,
                           const float4* i4, const float2* i2,
                           const char* ic, const short* is) {
    __shared__ float sh[128];
    int i = threadIdx.x;
    o4[i] = i4[i];
    o2[i] = i2[i];
    oc[i] = ic[i] + 1;
    os[i] = is[i] + 1;
    sh[i & 127] = (float)i;
    __syncthreads();
    o2[i].x += sh[(i + 1) & 127];
}
