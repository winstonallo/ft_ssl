#ifndef TESTS_H
#define TESTS_H

#include <stdbool.h>

// AES-GCM Test Vectors
// https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

bool GCM_AE_empty_message();
bool GCM_AE_one_block();
bool GCM_AE_multiblock();
bool GCM_AE_multiblock_remainder();

bool GCM_AD_one_block();
bool GCM_AD_empty_message();
bool GCM_AD_multiblock();
bool GCM_AD_multiblock_remainder();

#endif
