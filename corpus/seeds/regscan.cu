// 制造大量不同寄存器编号的同型指令，便于 XOR 差分定位寄存器字段
__global__ void reg_kernel(float* p) {
    float v0=p[0], v1=p[1], v2=p[2], v3=p[3], v4=p[4], v5=p[5], v6=p[6], v7=p[7];
    v0 = v0*v1 + v2;  v1 = v1*v2 + v3;  v2 = v2*v3 + v4;  v3 = v3*v4 + v5;
    v4 = v4*v5 + v6;  v5 = v5*v6 + v7;  v6 = v6*v7 + v0;  v7 = v7*v0 + v1;
    p[0]=v0; p[1]=v1; p[2]=v2; p[3]=v3; p[4]=v4; p[5]=v5; p[6]=v6; p[7]=v7;
}
