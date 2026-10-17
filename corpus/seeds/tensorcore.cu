// tensor core：产出 HMMA / IMMA / LDSM
#include <mma.h>
using namespace nvcuda::wmma;
__global__ void mma_kernel(float* o, const __half* a, const __half* b) {
    fragment<matrix_a, 16, 16, 16, __half, row_major> fa;
    fragment<matrix_b, 16, 16, 16, __half, col_major> fb;
    fragment<accumulator, 16, 16, 16, float> fc;
    fill_fragment(fc, 0.0f);
    load_matrix_sync(fa, a, 16);
    load_matrix_sync(fb, b, 16);
    mma_sync(fc, fa, fb, fc);
    store_matrix_sync(o, fc, 16, mem_row_major);
}
