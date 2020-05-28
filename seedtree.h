#ifndef MERKLETREE_H
#define MERKLETREE_H

#include <stdio.h>
#include "stdint.h"
#include <string.h>
#include "parameters.h"


void generate_seed_tree(unsigned char *seed_tree, uint64_t leaves, const unsigned char *salt);
void release_seeds(unsigned char *tree, uint64_t leaves, const unsigned char *indices, unsigned char *out, uint64_t *seeds_released );
void fill_down(unsigned char *tree, uint64_t leaves, const unsigned char *indices, const unsigned char *in, uint64_t *nodes_used, const unsigned char *salt);

void print_seed(const unsigned char *seed);
void print_hash(const unsigned char *hash);
void print_tree(const unsigned char *tree, int depth);

#endif