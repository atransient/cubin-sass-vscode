// 执行 oracle 专用种子：extern "C" 保证入口名可预测（runner 用 cuModuleGetFunction 查名）
// 形状固定为 (float* a, float* b, float* c) 以匹配 nvisa/oracle/runner.c 的调用约定。
// 语义已知：c[i] = a[i]*b[i] + c[i]，a=2 b=3 c=1 时结果 7.0。
extern "C" __global__ void f(float* a, float* b, float* c) {
    int i = threadIdx.x;
    c[i] = a[i] * b[i] + c[i];
}
