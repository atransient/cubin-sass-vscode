/* Hardware oracle: load a (possibly patched) cubin and actually run it.
 *
 *   runner <cubin> <entry> <a> <b> <c>
 *
 * Launches <entry> with 4 threads over three float buffers pre-filled with
 * a / b / c, then prints one JSON line describing what happened:
 *
 *   {"ok":true,"stage":"done","err":"","out":[7.0,7.0,7.0,7.0]}
 *   {"ok":false,"stage":"sync","err":"CUDA_ERROR_ILLEGAL_INSTRUCTION","out":[]}
 *
 * The stage matters: a bad encoding can fail at module load (driver rejects
 * it), at launch, or only once the warp retires -- each says something
 * different about how far the encoding got.
 *
 * Deliberately one process per query: an illegal instruction poisons the
 * CUDA context, so isolation is worth the fork cost.
 */
#include <cuda.h>
#include <stdio.h>
#include <stdlib.h>

#define N 4

static const char *err_name(CUresult r) {
    const char *s = NULL;
    cuGetErrorName(r, &s);
    return s ? s : "UNKNOWN";
}

static int fail(const char *stage, CUresult r) {
    printf("{\"ok\":false,\"stage\":\"%s\",\"err\":\"%s\",\"out\":[]}\n",
           stage, err_name(r));
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: runner <cubin> <entry> [a b c]\n");
        return 2;
    }
    const char *path = argv[1], *entry = argv[2];
    float va = argc > 3 ? atof(argv[3]) : 2.0f;
    float vb = argc > 4 ? atof(argv[4]) : 3.0f;
    float vc = argc > 5 ? atof(argv[5]) : 1.0f;

    CUresult r;
    CUdevice dev;
    CUcontext ctx;
    CUmodule mod;
    CUfunction fn;

    if ((r = cuInit(0)) != CUDA_SUCCESS) return fail("init", r);
    if ((r = cuDeviceGet(&dev, 0)) != CUDA_SUCCESS) return fail("device", r);
    if ((r = cuCtxCreate(&ctx, 0, dev)) != CUDA_SUCCESS) return fail("context", r);
    if ((r = cuModuleLoad(&mod, path)) != CUDA_SUCCESS) return fail("load", r);
    if ((r = cuModuleGetFunction(&fn, mod, entry)) != CUDA_SUCCESS)
        return fail("entry", r);

    float ha[N], hb[N], hc[N];
    for (int i = 0; i < N; i++) { ha[i] = va; hb[i] = vb; hc[i] = vc; }

    CUdeviceptr A, B, C;
    size_t bytes = sizeof(float) * N;
    if ((r = cuMemAlloc(&A, bytes)) != CUDA_SUCCESS) return fail("alloc", r);
    if ((r = cuMemAlloc(&B, bytes)) != CUDA_SUCCESS) return fail("alloc", r);
    if ((r = cuMemAlloc(&C, bytes)) != CUDA_SUCCESS) return fail("alloc", r);
    cuMemcpyHtoD(A, ha, bytes);
    cuMemcpyHtoD(B, hb, bytes);
    cuMemcpyHtoD(C, hc, bytes);

    void *args[] = {&A, &B, &C};
    if ((r = cuLaunchKernel(fn, 1, 1, 1, N, 1, 1, 0, 0, args, 0)) != CUDA_SUCCESS)
        return fail("launch", r);
    if ((r = cuCtxSynchronize()) != CUDA_SUCCESS) return fail("sync", r);
    if ((r = cuMemcpyDtoH(hc, C, bytes)) != CUDA_SUCCESS) return fail("readback", r);

    printf("{\"ok\":true,\"stage\":\"done\",\"err\":\"\",\"out\":[");
    for (int i = 0; i < N; i++) printf("%s%.6g", i ? "," : "", hc[i]);
    printf("]}\n");
    return 0;
}
