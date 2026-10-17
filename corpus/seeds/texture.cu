// 纹理/表面：产出 TEX / TLD / SULD / SUST
__global__ void tex_kernel(float* o, cudaTextureObject_t t,
                           cudaSurfaceObject_t s, float u, float v) {
    int i = threadIdx.x;
    float a = tex2D<float>(t, u + i, v);
    float b = tex1Dfetch<float>(t, i);
    o[i] = a + b;
    surf2Dwrite(a, s, i * 4, 0);
}
