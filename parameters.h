#ifndef PARAMETERS
#define PARAMETERS

#define LOG_1(n) (((n) >= 2) ? 2 : 1)
#define LOG_2(n) (((n) >= 1<<2) ? (2 + LOG_1((n)>>2)) : LOG_1(n))
#define LOG_4(n) (((n) >= 1<<4) ? (4 + LOG_2((n)>>4)) : LOG_2(n))
#define LOG_8(n) (((n) >= 1<<8) ? (8 + LOG_4((n)>>8)) : LOG_4(n))
#define LOG(n)   (((n) >= 1<<16) ? (16 + LOG_8((n)>>16)) : LOG_8(n))

#include "libkeccak.a.headers/SimpleFIPS202.h"
#include <openssl/rand.h>

#define SEED_BYTES 16
#define HASH_BYTES 32

#define HASH(data,len,out) SHAKE128(out, HASH_BYTES, data, len);
#define TREEHASH(data,len,out) SHAKE128(out, SEED_BYTES, data, len);
#define EXPAND(data,len,out,outlen) SHAKE128(out, outlen, data, len);

#include <string.h>

#ifdef LATTICE
	#include "lattice_BG_instantiation.h"

	#define EXECUTIONS 1749  
	#define ZEROS      16    
#endif

#ifdef ISOGENY
	#include "isogeny_instantiation.h"

	#define EXECUTIONS 247  
	#define ZEROS      30   
#endif

#define do_action(out, in, g) { \
	PREP_GRPELT pg; \
	do_half_action(&pg, g); \
	finish_action(out, in,&pg); \
}

#define ONES (EXECUTIONS-ZEROS)
#define LOG_EXECUTIONS LOG(EXECUTIONS)
#define EXECUTIONS_ROUND_UP (((uint64_t)1) << LOG_EXECUTIONS)

#define EXECUTIONS_MASK (1 << (LOG_EXECUTIONS)) -1

#if EXECUTIONS > 65536
	EXECUTIONS should not exceed 2^16
#endif


#endif
