// 控制流：产出 BRA / BSSY / BSYNC / CALL / RET / EXIT，含长跳转与循环
__device__ __noinline__ int helper(int x) { return x * x + 1; }
__global__ void control_kernel(int* o, int n, int m) {
    int i = threadIdx.x;
    int s = 0;
    for (int k = 0; k < n; ++k) {
        if (k & 1) { s += helper(k); }
        else if (k % 3 == 0) { s -= k * m; }
        else { s ^= k; }
        // 拉长循环体，逼出 ≥0x400 的分支偏移
        s += (s << 1) ^ (s >> 3) ^ (s * m) ^ (s + n);
        s += (s << 2) ^ (s >> 5) ^ (s * n) ^ (s + m);
        s += (s << 3) ^ (s >> 7) ^ (s * k) ^ (s + k);
        s += (s << 4) ^ (s >> 9) ^ (s * i) ^ (s + i);
    }
    o[i] = s;
}
