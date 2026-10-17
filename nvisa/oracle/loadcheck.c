// cuModuleLoad smoke test（`--smoke`）。
//
// 只加载、只查符号，**不发射任何 kernel**。保存报告要能说「驱动收下了这个
// cubin」，而这跟「跑出来的结果对不对」是两件事（后者要实际执行，
// 走 runner.c 那条路）。手改过的 .text 不该在这里被执行：加载失败说明
// 打包错了，加载成功也只说明结构合法。
#include <cuda.h>
#include <stdio.h>

static const char *err_name(CUresult r) {
    const char *s = NULL;
    cuGetErrorName(r, &s);
    return s ? s : "?";
}

static int fail(const char *stage, CUresult r) {
    printf("{\"ok\":false,\"stage\":\"%s\",\"err\":\"%s\"}\n", stage, err_name(r));
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: loadcheck <cubin> [entry ...]\n");
        return 2;
    }
    CUresult r;
    CUdevice dev;
    CUcontext ctx;
    CUmodule mod;
    CUfunction fn;

    if ((r = cuInit(0)) != CUDA_SUCCESS) return fail("init", r);
    if ((r = cuDeviceGet(&dev, 0)) != CUDA_SUCCESS) return fail("device", r);
    if ((r = cuCtxCreate(&ctx, 0, dev)) != CUDA_SUCCESS) return fail("context", r);
    if ((r = cuModuleLoad(&mod, argv[1])) != CUDA_SUCCESS) return fail("load", r);
    for (int i = 2; i < argc; i++)
        if ((r = cuModuleGetFunction(&fn, mod, argv[i])) != CUDA_SUCCESS)
            return fail("entry", r);
    printf("{\"ok\":true,\"stage\":\"loaded\",\"err\":\"\"}\n");
    return 0;
}
