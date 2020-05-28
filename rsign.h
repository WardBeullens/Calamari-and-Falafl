#ifndef RSIGN_H
#define RSIGN_H value

#include "parameters.h"
#include "seedtree.h"
#include "stdint.h"

#define SEED_BUF_BYTES (HASH_BYTES + SEED_BYTES + sizeof(uint32_t))

#define SK_BYTES SEED_BYTES

extern uint64_t restarts;

#define RSIG_SALT(sig) (sig)
#define RSIG_CHALLENGE(sig) (RSIG_SALT(sig) + HASH_BYTES)
#define RSIG_Z(sig) (RSIG_CHALLENGE(sig) + SEED_BYTES)
#define RSIG_COMMITMENT_RANDOMNESS(sig) (RSIG_Z(sig) + S3_BYTES*ZEROS)
#define RSIG_PATHS(sig) (RSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES*ZEROS)
#define RSIG_SEEDS(sig, logN) (RSIG_PATHS(sig) + logN*HASH_BYTES*ZEROS )
#define RSIG_BYTES(logN) (RSIG_SEEDS(0,logN) + SEED_BYTES*ONES)

void keygen(unsigned char *pk, unsigned char *sk);
int rsign(const unsigned char *sk_I, const int64_t I, const unsigned char *pks, const int64_t ring_size, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len);
int  rverify(const unsigned char *pks, const int64_t ring_size, const unsigned char *m, uint64_t mlen, const unsigned char *sig);

#ifdef BG
	int bg_check(XELT *X);
#endif

void commit(const XELT *R, const unsigned char *randomness, const unsigned char *salt, unsigned char *commitment);
void build_tree_and_path(const unsigned char *commitments_in, int logN, int64_t I, unsigned char * root, unsigned char *path);
void reconstruct_root(const unsigned char *data, const unsigned char *path, int logN, unsigned char *root);
void derive_challenge(const unsigned char *challenge_seed, unsigned char *challenge);
int log_round_up(int64_t a);

#endif
