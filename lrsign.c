#include "lrsign.h"

#define EXPAND_BUF_LEN (SEED_BYTES*(rings+2))
#define FM_ROOTS(fm) fm
#define FM_MESSAGE_HASH(fm) (FM_ROOTS(fm) + HASH_BYTES*EXECUTIONS)
#define FM_SALT(fm) (FM_MESSAGE_HASH(fm) + HASH_BYTES)
#define FM_TPRIME(fm) (FM_SALT(fm) + HASH_BYTES)
#define FM_BYTES (FM_TPRIME(0) + EXECUTIONS*HASH_BYTES)

int lrsign(const unsigned char *sk, const int64_t I, const unsigned char *pks, const int64_t rings, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len){
	if (I >= rings || rings > (((uint64_t) 1) << 32))
		return -1;

	int logN = log_round_up(rings);
	uint64_t rings_round_up = (((uint64_t)1) << logN);

	GRPELTS2 r[EXECUTIONS];
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		init_grpelt(r[i]);
	}

	unsigned char seed_tree[(2*EXECUTIONS-1)*SEED_BYTES];
	unsigned char *seeds = seed_tree + (EXECUTIONS-1)*SEED_BYTES;

	unsigned char seedbuf[SEED_BUF_BYTES];
	unsigned char expand_buf[EXPAND_BUF_LEN];
	unsigned char commitments[HASH_BYTES*rings_round_up];
	unsigned char commitment_randomness[EXECUTIONS*SEED_BYTES];
	XELT R,Tprime;
	unsigned char fm[FM_BYTES];

	unsigned char paths[HASH_BYTES*EXECUTIONS*logN];

	// generate response
	GRPELTS2 z;
	GRPELTS1L s;
	init_grpelt(z);
	init_grpelt(s);
	sample_S1L(s,sk);

	// compute Tag
	public_key *tag = (public_key *) LRSIG_TAG(sig);
	derive_tag(tag,s);

	// choose salt
	RAND_bytes(LRSIG_SALT(sig),HASH_BYTES);

	// copy salt
	memcpy(FM_SALT(fm), LRSIG_SALT(sig), HASH_BYTES);
	memcpy(seedbuf + SEED_BYTES, LRSIG_SALT(sig), HASH_BYTES);
	uint32_t *ctr = (uint32_t *) (seedbuf + HASH_BYTES + SEED_BYTES);

	unsigned char zero_seed[SEED_BYTES] = {0};

	// pick random seeds
	restart: generate_seed_tree(seed_tree,EXECUTIONS,LRSIG_SALT(sig));

	// hash message
	HASH(m,mlen,FM_MESSAGE_HASH(fm));

	for (int i = 0; i < EXECUTIONS; ++i)
	{
		// generate commitment randomness and r
		memcpy(seedbuf, seeds + i*SEED_BYTES, SEED_BYTES);
		(*ctr)  = EXECUTIONS + i; 
		EXPAND(seedbuf, SEED_BUF_BYTES, expand_buf, EXPAND_BUF_LEN);

		// sample r
		sample_S2_with_seed(expand_buf + SEED_BYTES*rings, r[i]);

		PREP_GRPELT pg;
		do_half_action(&pg,r[i]);

		// Memory access at secret location!
		memcpy(commitment_randomness + i*SEED_BYTES , expand_buf + I*SEED_BYTES , SEED_BYTES);

		// compute and commit to T'
		do_tag_action(&Tprime,tag,r[i]);
		commit(&Tprime, zero_seed , RSIG_SALT(sig), FM_TPRIME(fm) + i*HASH_BYTES);

		// compute R_i and commitments
		for (int j = 0; j < rings; ++j)
		{
			finish_action(&R,(public_key*) (pks + j*sizeof(public_key)), &pg);
			commit(&R,expand_buf + j*SEED_BYTES, RSIG_SALT(sig), commitments + j*HASH_BYTES);
		}

		// generate dummy commitments
		EXPAND(expand_buf + SEED_BYTES * (rings +1), SEED_BYTES, commitments + rings*HASH_BYTES, (rings_round_up-rings)*HASH_BYTES);

		build_tree_and_path(commitments, logN, I, FM_ROOTS(fm) + i*HASH_BYTES, paths + i*HASH_BYTES*logN );
	}

	// generate challenge
	EXPAND(fm, FM_BYTES, LRSIG_CHALLENGE(sig), SEED_BYTES);
	unsigned char challenge[EXECUTIONS];
	derive_challenge(LRSIG_CHALLENGE(sig),challenge);

	int zeros = 0;
	int ones = 0;
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		if (challenge[i] == 0)
		{
			// compute and pack z in signature
			add(z, s, r[i]);
			if( !is_in_S3(z) ){
				restarts += 1;
				goto restart;
			}

			#ifdef BG
			XELT W;
			do_action(&W,&X0,z);
			if( !bg_check(&W) ){
				restarts += 1;
				goto restart;
			}
			do_tag_action(&W,&X0,z);
			if( !bg_check(&W) ){
				restarts += 1;
				goto restart;
			}
			#endif

			pack_S3(LRSIG_Z(sig) + zeros*S3_BYTES, z);

			// copy commitment randomess to signature
			memcpy(LRSIG_COMMITMENT_RANDOMNESS(sig) + zeros*SEED_BYTES, commitment_randomness + i*SEED_BYTES, SEED_BYTES);
			// copy Merkle tree path to signature
			memcpy(LRSIG_PATHS(sig) + zeros*logN*HASH_BYTES, paths + i*HASH_BYTES*logN, HASH_BYTES*logN);
			zeros++;
		}
	}

	release_seeds(seed_tree, EXECUTIONS, challenge, LRSIG_SEEDS(sig,logN) , sig_len );
	(*sig_len) *= SEED_BYTES;
	(*sig_len) += LRSIG_SEEDS(0,logN);

	for (int i = 0; i < EXECUTIONS; ++i)
	{
		clear_grpelt(r[i]);
	}

	clear_grpelt(z);
	clear_grpelt(s);
}

int  lrverify(const unsigned char *pks, const int64_t rings, const unsigned char *m, uint64_t mlen, const unsigned char *sig){
	if (rings > (((uint64_t) 1) << 32))
		return -1;

	int valid = 0;

	int logN = log_round_up(rings);
	uint64_t rings_round_up = (((uint64_t)1) << logN);

	// expand challenge
	unsigned char challenge[EXECUTIONS];
	derive_challenge(LRSIG_CHALLENGE(sig),challenge);

	// derive seeds
	unsigned char seed_tree[(2*EXECUTIONS-1)*SEED_BYTES];
	unsigned char *seeds = seed_tree + (EXECUTIONS-1)*SEED_BYTES;
	uint64_t nodes_used;
	fill_down(seed_tree,EXECUTIONS, challenge, LRSIG_SEEDS(sig,logN), &nodes_used, LRSIG_SALT(sig));

	unsigned char fm[FM_BYTES];

	// hash message
	HASH(m,mlen,FM_MESSAGE_HASH(fm))

	// copy salt
	memcpy(FM_SALT(fm), LRSIG_SALT(sig), HASH_BYTES);

	public_key *tag = (public_key *) LRSIG_TAG(sig);
	unsigned char zero_seed[SEED_BYTES] = {0};

	int zeros = 0;
	int ones = 0;
	GRPELTS2 r,z;
	XELT R,Tprime;
	init_grpelt(r);
	init_grpelt(z);

	unsigned char expand_buf[EXPAND_BUF_LEN];
	unsigned char seedbuf[SEED_BUF_BYTES];
	memcpy(seedbuf + SEED_BYTES, LRSIG_SALT(sig) , HASH_BYTES);
	uint32_t *ctr = (uint32_t *) (seedbuf + SEED_BYTES + HASH_BYTES);

	unsigned char commitments[HASH_BYTES*rings_round_up];
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		if (challenge[i] == 0){
			// unpack z
			unpack_S3(LRSIG_Z(sig) + zeros*S3_BYTES, z);

			if(!is_in_S3(z)){
				printf("z not in S3! \n");
				valid = -1;
				break;
			}

			// compute z * X_0 and z \bullet T_0 
			do_action(&R,&X0,z);

			do_tag_action(&Tprime,&X0,z);
			commit(&Tprime, zero_seed , RSIG_SALT(sig), FM_TPRIME(fm) + i*HASH_BYTES);

			// commit to it
			commit(&R,LRSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES*zeros, RSIG_SALT(sig), commitments);
			// reconstruct root
			reconstruct_root(commitments, LRSIG_PATHS(sig) + zeros*logN*HASH_BYTES, logN, FM_ROOTS(fm) + i*HASH_BYTES);
			zeros++;
		}
		else{
			// generate commitment randomness and r
			memcpy(seedbuf, seeds + i*SEED_BYTES, SEED_BYTES);
			(*ctr)  = EXECUTIONS + i; 
			EXPAND(seedbuf, SEED_BUF_BYTES, expand_buf, EXPAND_BUF_LEN);

			// sample r
			sample_S2_with_seed(expand_buf + SEED_BYTES*rings, r);

			PREP_GRPELT pg;
			do_half_action(&pg,r);

			// compute and commit to T'
			do_tag_action(&Tprime,tag,r);
			commit(&Tprime, zero_seed , RSIG_SALT(sig), FM_TPRIME(fm) + i*HASH_BYTES);

			// compute R_i and commitments
			for (int j = 0; j < rings; ++j)
			{
				finish_action(&R, (public_key*) (pks + j*sizeof(public_key)), &pg);
				commit(&R,expand_buf + j*SEED_BYTES, RSIG_SALT(sig), commitments + j*HASH_BYTES);
			}

			// generate dummy commitments
			EXPAND(expand_buf + SEED_BYTES * (rings +1), SEED_BYTES, commitments + rings*HASH_BYTES, (rings_round_up-rings)*HASH_BYTES);

			// compute root
			build_tree_and_path(commitments, logN, -1 , FM_ROOTS(fm) + i*HASH_BYTES, NULL );
			ones++;
		}
	}

	clear_grpelt(r);
	clear_grpelt(z);

	// check hash of first message
	unsigned char challenge_seed[SEED_BYTES];
	EXPAND(fm, FM_BYTES, challenge_seed, SEED_BYTES);

	if(memcmp(LRSIG_CHALLENGE(sig) , challenge_seed, SEED_BYTES) != 0){
		printf("challenge seed does not match! \n");
		return -1;
	}

	return valid;
}