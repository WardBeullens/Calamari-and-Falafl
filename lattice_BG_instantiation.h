#include "polyvec.h"
#include "sign.h" // for expand_mat

#define BG

typedef struct {
	polyveck all;
	polyveck high;
	polyveck low;
} XELT;

#define public_key polyveck
#define PK_BYTES sizeof(public_key)

static const public_key X0 = {0};

#define S1_BYTES ((K+L)*POLETA_SIZE_PACKED)
#define S1L_BYTES (((2*K)+L)*POLETA_SIZE_PACKED)

#define S3_BYTES (L*POLZ_SIZE_PACKED)
#define XELT_BYTES sizeof(XELT)

#define PREP_GRPELT polyveck

polyvecl mat[K];
polyvecl Bmat[K];

#define init_action() { \
unsigned char matseed[SEEDBYTES] = {0}; \
/* Expand matrix */ \
	expand_mat(mat, matseed); \
	matseed[0] = 1; \
	expand_mat(Bmat, matseed); \
} 

typedef struct {
	polyvecl s;
	polyveck e;
} GRPELTS1;

typedef struct {
	polyvecl s;
	polyveck e;
	polyveck e2;
} GRPELTS1L;

typedef struct {
	polyvecl s;
} GRPELTS2;

#define sample_S1(a,seed) \
{ \
	unsigned char s1seed[CRHBYTES] = {0}; \
	memcpy(s1seed,seed,SEED_BYTES); \
	poly_uniform_eta_4x(&a.s.vec[0], &a.s.vec[1], &a.s.vec[2], &a.e.vec[0], s1seed, 0, 1, 2, 0); \
	poly_uniform_eta_4x(&a.e.vec[0], &a.e.vec[1], &a.e.vec[2], &a.e.vec[3], s1seed, 3, 4, 5, 6); \
} 

#define sample_S1L(a,seed) \
{ \
	unsigned char s1seed[CRHBYTES] = {0}; \
	memcpy(s1seed,seed,SEED_BYTES); \
	poly_uniform_eta_4x(&a.s.vec[0], &a.s.vec[1], &a.s.vec[2], &a.e.vec[0], s1seed, 0, 1, 2, 0); \
	poly_uniform_eta_4x(&a.e.vec[0], &a.e.vec[1], &a.e.vec[2], &a.e.vec[3], s1seed, 3, 4, 5, 6); \
	poly_uniform_eta_4x(&a.e2.vec[0], &a.e2.vec[1], &a.e2.vec[2], &a.e2.vec[3], s1seed, 7, 8, 9, 10); \
} 

#define sample_S2_with_seed(seed,a) \
{ \
	unsigned char s2seed[CRHBYTES] = {0}; \
	memcpy(s2seed,seed,SEED_BYTES); \
	poly_uniform_gamma1m1_4x(&a.s.vec[0], &a.s.vec[1], &a.s.vec[2], &a.s.vec[0], s2seed, 0, 1, 2, 0); \
}

#define pack_S1(data, g) \
for(int i = 0; i < L; ++i) \
	polyeta_pack(data + i*POLETA_SIZE_PACKED, &g.s.vec[i]); 

#define unpack_S1(data, g) \
for(int i=0; i < L; ++i) \
	polyeta_unpack(&g.s.vec[i], data + i*POLETA_SIZE_PACKED); 

#define pack_S3(data, g) \
polyvecl_freeze(&g.s); \
for(int i = 0; i < L; ++i) \
	polyz_pack(data + i*POLZ_SIZE_PACKED, &g.s.vec[i]); 

#define unpack_S3(data, g) \
for(int i = 0; i < L; ++i) \
	polyz_unpack(&g.s.vec[i], data + i*POLZ_SIZE_PACKED); 


#define add(out, in1, in2) { \
polyvecl_add(&out.s,&in1.s,&in2.s); \
polyvecl_freeze(&out.s); \
}

#define is_in_S3(g) ( ! ( polyvecl_chknorm(&g.s, GAMMA1 - ETA) ) )

#define derive_pk(out, g) { \
/* Matrix-vector multiplication */ \
	polyvecl s1hat = g.s; \
	polyvecl_ntt(&s1hat); \
	for(int i = 0; i < K; ++i) { \
	polyvecl_pointwise_acc_montgomery(&((*out).vec[i]), &mat[i], &s1hat); \
	poly_invntt_tomont(&((*out).vec[i])); \
	} \
	/* Add error vector s2 */ \
	polyveck_add(out, out, &g.e); \
	polyveck_freeze(out); \
}

#define derive_tag(out, g) { \
/* Matrix-vector multiplication */ \
	polyvecl s1hat = g.s; \
	polyvecl_ntt(&s1hat); \
	for(int i = 0; i < K; ++i) { \
	polyvecl_pointwise_acc_montgomery(&((*out).vec[i]), &Bmat[i], &s1hat); \
	poly_invntt_tomont(&((*out).vec[i])); \
	} \
	/* Add error vector e2 */ \
	polyveck_add(out, out, &g.e2); \
	polyveck_freeze(out); \
}

#define do_half_action(out, g) { \
/* Matrix-vector multiplication */ \
	polyvecl s1hat = g.s; \
	polyvecl_ntt(&s1hat); \
	for(int i = 0; i < K; ++i) { \
	polyvecl_pointwise_acc_montgomery(&((*out).vec[i]), &mat[i], &s1hat); \
	poly_invntt_tomont(&((*out).vec[i])); \
	} \
}

#define finish_action(out,in,pg) { \
	polyveck_add(&(*out).all, in, pg); \
	polyveck_freeze(&(*out).all); \
	polyveck_power2round(&((*out).high),&((*out).low),&(*out).all); \
	polyveck_freeze(&(*out).low); \
}

#define do_tag_action(out, in, g) { \
/* Matrix-vector multiplication */ \
	polyvecl s1hat = g.s; \
	polyvecl_ntt(&s1hat); \
	for(int i = 0; i < K; ++i) { \
	polyvecl_pointwise_acc_montgomery(&((*out).all.vec[i]), &Bmat[i], &s1hat); \
	poly_invntt_tomont(&((*out).all.vec[i])); \
	} \
	polyveck_add(&(*out).all, in, &(*out).all); \
	polyveck_freeze(&(*out).all); \
	polyveck_power2round(&((*out).high),&((*out).low),&(*out).all); \
	polyveck_freeze(&(*out).low); \
}


#define is_equal_X(A,B) (memcmp(&(A.high),&(B.high),sizeof(polyveck)) == 0)

#define init_grpelt(g) 
#define clear_grpelt(g) 