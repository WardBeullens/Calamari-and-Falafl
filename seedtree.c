#include "seedtree.h"
#include <openssl/rand.h>

#define LEFT_CHILD(i) (2*i+1)
#define RIGHT_CHILD(i) (2*i+2)
#define PARENT(i) ((i-1)/2)
#define SIBLING(i) (((i)%2)? i+1 : i-1 )
#define IS_LEFT_SIBLING(i) (i%2)

void generate_seed_tree(unsigned char *seed_tree, uint64_t leaves, const unsigned char *salt){
	unsigned char buf[sizeof(uint32_t) + HASH_BYTES + SEED_BYTES];
	memcpy(buf,salt,HASH_BYTES);
	uint32_t *pos = (uint32_t *) (buf + HASH_BYTES + SEED_BYTES);

	RAND_bytes(seed_tree,SEED_BYTES);
	for(uint32_t i=0; i<leaves-1; i++){
		memcpy(buf + HASH_BYTES, seed_tree + i*SEED_BYTES, SEED_BYTES);
		*pos = i;
		EXPAND(buf,HASH_BYTES + SEED_BYTES + sizeof(uint32_t),seed_tree + LEFT_CHILD(i)*SEED_BYTES, 2*SEED_BYTES);
	}
}

void fill_tree(const unsigned char *indices, unsigned char *tree, uint64_t leaves){
	int i;

	memcpy(tree+leaves-1, indices, leaves);

	// flip bits
	// 1 = cannot be released
	// 0 = has to be released
	for (int i = 0; i < leaves; ++i)
	{
		tree[i+leaves-1] ^= 1;
	}

	// fill up the internal part of tree
	for(i= leaves-2; i>=0; i--){
		if((tree[LEFT_CHILD(i)] == 0)  && (tree[RIGHT_CHILD(i)] == 0) ){
			tree[i] = 0;
		}
		else{
			tree[i] = 1;
		}
	}
}

void release_seeds(unsigned char *tree, uint64_t leaves, const unsigned char *indices, unsigned char *out, uint64_t *seeds_released ){
	(*seeds_released) = 0;
	unsigned char class_tree[2*leaves-1];
	fill_tree(indices,class_tree,leaves);

	int i;
	for(i=0; i< 2*leaves-1; i++){
		if((class_tree[i] == 0) && (class_tree[PARENT(i)] == 1)){
			memcpy(out + (*seeds_released)*SEED_BYTES, tree + i*SEED_BYTES, SEED_BYTES);
			(*seeds_released)++;
		}
	}
}

void fill_down(unsigned char *tree, uint64_t leaves, const unsigned char *indices, const unsigned char *in, uint64_t *nodes_used, const unsigned char *salt){
	unsigned char class_tree[2*leaves-1];
	fill_tree(indices,class_tree,leaves);

	unsigned char buf[HASH_BYTES+SEED_BYTES + sizeof(uint32_t)];
	memcpy(buf, salt, HASH_BYTES);
	uint32_t *pos = (uint32_t *) (buf + HASH_BYTES + SEED_BYTES);

	int i;
	(*nodes_used) = 0;
	for(i=0; i<2*leaves-1; i++){
		if(class_tree[i] == 0){
			if(class_tree[PARENT(i)] == 1){
				memcpy(tree + SEED_BYTES*i, in + SEED_BYTES*(*nodes_used), SEED_BYTES);
				(*nodes_used)++;
			}
			if(i<leaves-1){
				memcpy(buf + HASH_BYTES, tree + SEED_BYTES*i, SEED_BYTES);
				*pos = i;
				EXPAND(buf, HASH_BYTES + SEED_BYTES + sizeof(uint32_t),tree + SEED_BYTES*LEFT_CHILD(i), 2*SEED_BYTES);
			}
		}
	}
}

void print_seed(const unsigned char *seed){
	int i=0;
	for(i=0; i<SEED_BYTES ; i++){
		printf("%2X ", seed[i]);
	}
	printf("\n");
}

void print_hash(const unsigned char *hash){
	int i=0;
	for(i=0; i<HASH_BYTES ; i++){
		printf("%2X ", hash[i]);
	}
	printf("\n");
}

void print_tree(const unsigned char *tree, int depth){
	int i=0;
	for(i=0; i<(2<<depth)-1 ; i++){
		printf("%4d: ", i);
		print_hash(tree + HASH_BYTES*i);
	}
	printf("\n");
}