#ifndef TESTS_H
#define TESTS_H

#include <stdbool.h>

// AES-GCM Test Vectors
// https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

bool GCTR_test_empty_input_returns_empty_cipher();
bool GCTR_test_all_zero_input();
bool GCTR_test_multiblock_no_remainder();
bool GCTR_test_multiblock_non_multiple_of_128();

bool GHASH_test_empty_input_returns_zero();
bool GHASH_test_two_blocks();

bool GCMAE_basic();

#endif
