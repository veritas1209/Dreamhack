#include <stdio.h>

const short _m = 19;
const short blk = 10;
const short d = 3;
const short r = 4;

const size_t pubkey_size = ((size_t) _m * blk * 5 + 7) / 8;
const size_t privkey_size = ((size_t) _m * (blk * 4 + d) + 7) / 8 + ((size_t) (blk + 1) / 2 * 2 * d);

const size_t plaintext_size = (size_t) _m * blk * 3 / 8;
const size_t ciphertext_size = ((size_t) _m * blk * 6 + 7) / 8;
