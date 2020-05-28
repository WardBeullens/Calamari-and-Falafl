#include "rsign.h"
#include "seedtree.h"


static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %lu \n",#A ,rdtsc() - cl); cl = rdtsc();

uint64_t restarts  = 0; 
uint64_t restarts2 = 0; 

void keygen(unsigned char *pk, unsigned char *sk){
	GRPELTS1 s;
	init_grpelt(s);

	RAND_bytes(sk,SEED_BYTES);

	sample_S1(s,sk);
	
	public_key *X = (public_key *) pk;
	derive_pk(X,s);

	clear_grpelt(s);
}

#ifdef BG
void commit(const XELT *R, const unsigned char *randomness, const unsigned char *salt, unsigned char *commitment){
	unsigned char buf[512 + 3*SEED_BYTES];
	memcpy(buf+512,randomness,SEED_BYTES);
	memcpy(buf+512+SEED_BYTES,salt,2*SEED_BYTES);

	for (int i = 0; i < K; ++i)
	{
		for (int j = 0; j < 128; ++j)
		{
			buf[i*128 + j] = (*R).high.vec[i].coeffs[j] || ((*R).high.vec[i].coeffs[j] << 4);
		}
	}

	HASH(buf, 512 + SEED_BYTES, commitment);
}
#else
void commit(const XELT *R, const unsigned char *randomness, const unsigned char *salt, unsigned char *commitment){
	unsigned char buf[sizeof(XELT) + 3*SEED_BYTES];
	memcpy(buf,(const unsigned char *)R,sizeof(XELT));
	memcpy(buf+sizeof(XELT),randomness,SEED_BYTES);
	memcpy(buf+sizeof(XELT)+SEED_BYTES,salt,2*SEED_BYTES);
	HASH(buf, sizeof(XELT) + SEED_BYTES, commitment);
}
#endif

void build_tree_and_path(const unsigned char *commitments_in, int logN, int64_t I, unsigned char * root, unsigned char *path){
	uint64_t rings_round_up = ((uint64_t)1)<<logN;
	unsigned char commitments[rings_round_up*HASH_BYTES];
	memcpy(commitments,commitments_in,rings_round_up*HASH_BYTES);
	int64_t *intpath = (int64_t *) path;
	unsigned char temp[HASH_BYTES];

	if(I >= 0){
		memset(path,0,logN*HASH_BYTES);
	}
	for (int depth = logN-1; depth >= 0; --depth)
	{
		if (I >= 0){
			for (int64_t i = 0; i < ((uint64_t) 1) << (depth+1); ++i)
			{
				int64_t mask = ((I^1) - i) | (i- (I^1));
				mask >>=63;
				mask ^= 0xffffffffffffffff;
				intpath[4*depth]   ^= (mask & *((int64_t *) (commitments + i*HASH_BYTES     )));
				intpath[4*depth+1] ^= (mask & *((int64_t *) (commitments + i*HASH_BYTES + 8 )));
				intpath[4*depth+2] ^= (mask & *((int64_t *) (commitments + i*HASH_BYTES + 16)));
				intpath[4*depth+3] ^= (mask & *((int64_t *) (commitments + i*HASH_BYTES + 24)));
			}

			// the above just does the following in constant time:
			// memcpy(path + depth*HASH_BYTES, commitments + (I^1)*HASH_BYTES, HASH_BYTES);

			I /= 2;
		}

		for (int i = 0; i < ((uint64_t) 1) << depth; ++i)
		{
			if(memcmp(commitments + HASH_BYTES*i*2,commitments + (2*i+1)*HASH_BYTES, HASH_BYTES ) > 0){
				memcpy(temp, commitments + HASH_BYTES*i*2, HASH_BYTES);
				memcpy(commitments + HASH_BYTES*i*2, commitments + HASH_BYTES*(i*2+1), HASH_BYTES);
				memcpy(commitments + HASH_BYTES*(i*2+1), temp, HASH_BYTES);
			}
			HASH(commitments + 2*i*HASH_BYTES,2*HASH_BYTES, commitments + i*HASH_BYTES);
		}
	}
	memcpy(root,commitments,HASH_BYTES);
}

void reconstruct_root(const unsigned char *data, const unsigned char *path, int logN, unsigned char *root){
	unsigned char current[2*HASH_BYTES];
	unsigned char temp[HASH_BYTES];
	memcpy(current, data, HASH_BYTES);
	for (int depth = logN-1; depth >= 0; --depth)
	{
		memcpy(current+HASH_BYTES, path+depth*HASH_BYTES, HASH_BYTES);
		if(memcmp(current,current + HASH_BYTES, HASH_BYTES ) > 0){
			memcpy(temp, current, HASH_BYTES);
			memcpy(current, current + HASH_BYTES, HASH_BYTES);
			memcpy(current + HASH_BYTES, temp, HASH_BYTES);
		}
		HASH(current,2*HASH_BYTES, current);
	}
	memcpy(root,current,HASH_BYTES);
}

#define SHAKE128_RATE 168

void derive_challenge(const unsigned char *challenge_seed, unsigned char *challenge){
	memset(challenge,1,EXECUTIONS);
	int zeros = 0;
	int pos = SHAKE128_RATE;

	unsigned char inbuf[SEED_BYTES + 4];
	uint16_t out_buf[SHAKE128_RATE/2];
	memcpy(inbuf,challenge_seed,SEED_BYTES);
	uint32_t *ctr = (uint32_t *) (inbuf + SEED_BYTES);
	(*ctr) = 0;

	while(zeros < ZEROS){
		if (pos >= SHAKE128_RATE/2){
			EXPAND(inbuf,SEED_BYTES+4,(unsigned char *) out_buf, SHAKE128_RATE);
			pos = 0;
			(*ctr)++;
		}

		out_buf[pos] &= EXECUTIONS_MASK;
		if (out_buf[pos] < EXECUTIONS && challenge[out_buf[pos]] == 1){
			challenge[out_buf[pos]] = 0;
			zeros += 1;
		}
		pos += 1;
	}
}

#ifdef BG
int bg_check(XELT *X){
	if (polyveck_chknorm(&(*X).low, (1<<(D-1)) - ETA) ){
		return 0;
	}
	polyveck temp;
	temp = (*X).all;
	//printf("%d \n", temp.vec[0].coeffs[0] );
	for (int i = 0; i < K; ++i)
	{
		for (int j = 0; j < N; ++j)
		{
			temp.vec[i].coeffs[j] += (Q/2);
		}
	}
	polyveck_freeze(&temp);
	if (polyveck_chknorm(&temp, (Q-1)/2 - ETA ) ) {
		restarts2 ++;
		return 0;
	}
	//printf("pass \n");
	return 1;
}
#endif

int log_round_up(int64_t a){
	int logN = 0;
	while ((((int64_t) 1) << logN) < a ){
		logN ++;
	}
	return logN;
}

int rsign(const unsigned char *sk, const int64_t I, const unsigned char *pks, const int64_t rings, const unsigned char *m, uint64_t mlen, unsigned char *sig, uint64_t *sig_len){
	if (I >= rings || rings > (((uint64_t) 1) << 32))
		return -1;

	int logN = log_round_up(rings);
	uint64_t rings_round_up = (((uint64_t)1) << logN);

	GRPELTS2 *r = aligned_alloc(32, sizeof(GRPELTS2)*EXECUTIONS);
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		init_grpelt(r[i]);
	}

	unsigned char *seed_tree = malloc((2*EXECUTIONS-1)*SEED_BYTES);
	unsigned char *seeds = seed_tree + (EXECUTIONS-1)*SEED_BYTES;

	#define BUF_LEN (SEED_BYTES*(rings+2))
	unsigned char seedbuf[SEED_BUF_BYTES];
	unsigned char buf[BUF_LEN];
	unsigned char commitments[HASH_BYTES*rings_round_up];
	unsigned char *commitment_randomness = malloc(EXECUTIONS*SEED_BYTES);
	XELT R;
	unsigned char *roots = malloc(HASH_BYTES*(EXECUTIONS+2));
	unsigned char *paths = malloc(HASH_BYTES*EXECUTIONS*logN);

	// generate response
	GRPELTS2 z;
	GRPELTS1 s;
	init_grpelt(z);
	init_grpelt(s);
	sample_S1(s,sk);

	// choose salt
	RAND_bytes(RSIG_SALT(sig),HASH_BYTES);

	// copy salt
	memcpy(roots + (EXECUTIONS+1)*HASH_BYTES, RSIG_SALT(sig), HASH_BYTES);
	memcpy(seedbuf + SEED_BYTES, RSIG_SALT(sig), HASH_BYTES);
	uint32_t *ctr = (uint32_t *) (seedbuf + HASH_BYTES + SEED_BYTES);

	// pick random seeds
	restart: generate_seed_tree(seed_tree,EXECUTIONS,RSIG_SALT(sig));

	// hash message
	HASH(m,mlen,roots + EXECUTIONS*HASH_BYTES);

	for (int i = 0; i < EXECUTIONS; ++i)
	{
		// generate commitment randomness and r
		memcpy(seedbuf, seeds + i*SEED_BYTES, SEED_BYTES);
		(*ctr)  = EXECUTIONS + i; 
		EXPAND(seedbuf, SEED_BUF_BYTES, buf, BUF_LEN);

		// sample r
		sample_S2_with_seed(buf + SEED_BYTES*rings, r[i]);

		PREP_GRPELT pg;
		do_half_action(&pg,r[i]);

		// TODO: do this without accessing secret indices !!
		memcpy(commitment_randomness + i*SEED_BYTES , buf + I*SEED_BYTES , SEED_BYTES);

		// compute R_i and commitments
		for (int j = 0; j < rings; ++j)
		{
			finish_action(&R,(public_key*) (pks + j*sizeof(public_key)), &pg);
			commit(&R,buf + j*SEED_BYTES, RSIG_SALT(sig), commitments + j*HASH_BYTES);
		}

		// generate dummy commitments
		EXPAND(buf + SEED_BYTES * (rings +1), SEED_BYTES, commitments + rings*HASH_BYTES, (rings_round_up-rings)*HASH_BYTES);

		build_tree_and_path(commitments, logN, I, roots + i*HASH_BYTES, paths + i*HASH_BYTES*logN );
	}

	// generate challenge
	EXPAND(roots, HASH_BYTES*(EXECUTIONS+2), RSIG_CHALLENGE(sig), SEED_BYTES);
	unsigned char *challenge = malloc(EXECUTIONS);
	derive_challenge(RSIG_CHALLENGE(sig),challenge);

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
			#endif

			pack_S3(RSIG_Z(sig) + zeros*S3_BYTES, z);

			// copy commitment randomess to signature
			memcpy(RSIG_COMMITMENT_RANDOMNESS(sig) + zeros*SEED_BYTES, commitment_randomness + i*SEED_BYTES, SEED_BYTES);
			// copy Merkle tree path to signature
			memcpy(RSIG_PATHS(sig) + zeros*logN*HASH_BYTES, paths + i*HASH_BYTES*logN, HASH_BYTES*logN);
			zeros++;
		}
	}

	release_seeds(seed_tree, EXECUTIONS, challenge, RSIG_SEEDS(sig,logN) , sig_len );
	(*sig_len) *= SEED_BYTES;
	(*sig_len) += RSIG_SEEDS(0,logN);

	for (int i = 0; i < EXECUTIONS; ++i)
	{
		clear_grpelt(r[i]);
	}

	free(r);
	free(seed_tree);
	free(commitment_randomness);
	free(roots);
	free(paths);
	free(challenge);

	clear_grpelt(z);
	clear_grpelt(s);
}

int  rverify(const unsigned char *pks, const int64_t rings, const unsigned char *m, uint64_t mlen, const unsigned char *sig){
	if (rings > (((uint64_t) 1) << 32))
		return -1;

	int valid = 0;

	int logN = log_round_up(rings);
	uint64_t rings_round_up = (((uint64_t)1) << logN);

	// expand challenge
	unsigned char challenge[EXECUTIONS];
	derive_challenge(RSIG_CHALLENGE(sig),challenge);

	// derive seeds
	unsigned char seed_tree[(2*EXECUTIONS-1)*SEED_BYTES];
	unsigned char *seeds = seed_tree + (EXECUTIONS-1)*SEED_BYTES;
	uint64_t nodes_used;
	fill_down(seed_tree,EXECUTIONS, challenge, RSIG_SEEDS(sig,logN), &nodes_used, RSIG_SALT(sig));

	// reconstruct roots
	unsigned char roots[(EXECUTIONS+2)*HASH_BYTES];

	// hash message
	HASH(m,mlen,roots + EXECUTIONS*HASH_BYTES)

	// copy salt
	memcpy(roots + (EXECUTIONS+1)*HASH_BYTES, RSIG_SALT(sig), HASH_BYTES);

	int zeros = 0;
	int ones = 0;
	GRPELTS2 r,z;
	XELT R;
	init_grpelt(r);
	init_grpelt(z);

	unsigned char buf[BUF_LEN];
	unsigned char seedbuf[SEED_BUF_BYTES];
	memcpy(seedbuf + SEED_BYTES, RSIG_SALT(sig) , HASH_BYTES);
	uint32_t *ctr = (uint32_t *) (seedbuf + SEED_BYTES + HASH_BYTES);

	unsigned char commitments[HASH_BYTES*rings_round_up];
	for (int i = 0; i < EXECUTIONS; ++i)
	{
		if (challenge[i] == 0){
			// unpack z
			unpack_S3(RSIG_Z(sig) + zeros*S3_BYTES, z);

			if(!is_in_S3(z)){
				printf("z not in S3! \n");
				valid = -1;
				break;
			}

			// compute z*X_0
			do_action(&R,&X0,z);

			// commit to it
			commit(&R,RSIG_COMMITMENT_RANDOMNESS(sig) + SEED_BYTES*zeros, RSIG_SALT(sig), commitments);
			// reconstruct root
			reconstruct_root(commitments, RSIG_PATHS(sig) + zeros*logN*HASH_BYTES, logN, roots + i*HASH_BYTES);
			zeros++;
		}
		else{
			// generate commitment randomness and r
			memcpy(seedbuf, seeds + i*SEED_BYTES, SEED_BYTES);
			(*ctr)  = EXECUTIONS + i; 
			EXPAND(seedbuf, SEED_BUF_BYTES, buf, BUF_LEN);

			// sample r
			sample_S2_with_seed(buf + SEED_BYTES*rings, r);

			PREP_GRPELT pg;
			do_half_action(&pg,r);

			// compute R_i and commitments
			for (int j = 0; j < rings; ++j)
			{
				finish_action(&R, (public_key*) (pks + j*sizeof(public_key)), &pg);
				commit(&R,buf + j*SEED_BYTES, RSIG_SALT(sig), commitments + j*HASH_BYTES);
			}

			// generate dummy commitments
			EXPAND(buf + SEED_BYTES * (rings +1), SEED_BYTES, commitments + rings*HASH_BYTES, (rings_round_up-rings)*HASH_BYTES);

			// compute root
			build_tree_and_path(commitments, logN, -1 , roots + i*HASH_BYTES, NULL );
			ones++;
		}
	}

	clear_grpelt(r);
	clear_grpelt(z);

	// check hash of roots
	unsigned char challenge_seed[SEED_BYTES];
	EXPAND(roots, HASH_BYTES*(EXECUTIONS+2), challenge_seed, SEED_BYTES);

	if(memcmp(RSIG_CHALLENGE(sig) , challenge_seed, SEED_BYTES) != 0){
		printf("challenge seed does not match! \n");
		return -1;
	}

	return valid;
}


