#ifndef LRSIGN_H
#define LRSIGN_H value

#include "rsign.h"
#include "parameters.h"
#include "stdint.h"

#define LRSIG_TAG(sig) (sig) 
#define LRSIG_SALT(sig) (LRSIG_TAG(sig) + PK_BYTES )
#define LRSIG_CHALLENGE(sig) (LRSIG_SALT(sig) + HASH_BYTES)
#define LRSIG_Z(sig) (LRSIG_CHALLENGE(sig) + SEED_BYTES)
#define LRSIG_COMMITMENT_RANDOMNESS(sig) (LRSIG_Z(sig) + S3_BYTES*ZEROS)
#define LRSIG_PATHS(sig) (LRSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES*ZEROS)
#define LRSIG_SEEDS(sig, logN) (LRSIG_PATHS(sig) + logN*HASH_BYTES*ZEROS )
#define LRSIG_BYTES(logN) (LRSIG_SEEDS(0,logN) + SEED_BYTES*ONES)

int lrsign(const unsigned char *sk_I, const int64_t I, const unsigned char *pks, const int64_t ring_size, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len);
int  lrverify(const unsigned char *pks, const int64_t ring_size, const unsigned char *m, uint64_t mlen, const unsigned char *sig);

#endif
