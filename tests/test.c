#include "tests.h"
#include <assert.h>
#include <unistd.h>

int
main() {
    assert(GHASH_test_empty_input_returns_zero());
    assert(GHASH_test_two_blocks());

    assert(GCTR_test_empty_input_returns_empty_cipher());
    assert(GCTR_test_all_zero_input());
    assert(GCTR_test_multiblock_no_remainder());
    assert(GCTR_test_multiblock_non_multiple_of_128());

    assert(GCMAE_empty_message());
    assert(GCMAE_one_block());
    assert(GCMAE_multiblock());
    assert(GCMAE_multiblock_remainder());
}
