#include "polyvec.h"
#include "sign.h" // for expand_mat

#define XELT polyveck
static const polyveck X0 = {0};

#define S1_BYTES ((K+L)*POLETA_SIZE_PACKED)
#define S3_BYTES ((K+L)*POLZ_SIZE_PACKED)
#define XELT_BYTES sizeof(XELT)

#define PREP_GRPELT XELT

polyvecl mat[K];

#define init_action() { \
unsigned char matseed[SEEDBYTES] = {0}; \
/* Expand matrix */ \
	expand_mat(mat, matseed); \
} 

typedef struct {
	polyvecl s;
	polyveck e;
} GRPELT;

static const GRPELT G0 = {0};

#define sample_S1(a) \
{ \
	unsigned char s1seed[CRHBYTES]; \
	RAND_bytes(s1seed,CRHBYTES); \
	poly_uniform_eta_4x(&a.s.vec[0], &a.s.vec[1], &a.s.vec[2], &a.e.vec[0], s1seed, 0, 1, 2, 0); \
	poly_uniform_eta_4x(&a.e.vec[0], &a.e.vec[1], &a.e.vec[2], &a.e.vec[3], s1seed, 3, 4, 5, 6); \
	} 

#define sample_S2_with_seed(seed,a) \
{ \
	unsigned char s2seed[CRHBYTES] = {0}; \
	memcpy(s2seed,seed,SEED_BYTES); \
	poly_uniform_gamma1m1_4x(&a.s.vec[0], &a.s.vec[1], &a.s.vec[2], &a.e.vec[0], s2seed, 0, 1, 2, 0); \
	poly_uniform_gamma1m1_4x(&a.e.vec[0], &a.e.vec[1], &a.e.vec[2], &a.e.vec[3], s2seed, 3, 4, 5, 6); \
}

#define pack_S1(data, g) \
for(int i = 0; i < L; ++i) \
	polyeta_pack(data + i*POLETA_SIZE_PACKED, &g.s.vec[i]); \
	for(int i = 0; i < K; ++i) \
	polyeta_pack(data + (L+i)*POLETA_SIZE_PACKED, &g.e.vec[i]); 

#define unpack_S1(data, g) \
for(int i=0; i < L; ++i) \
	polyeta_unpack(&g.s.vec[i], data + i*POLETA_SIZE_PACKED); \
for(int i=0; i < K; ++i) \
	polyeta_unpack(&g.e.vec[i], data + (L+i)*POLETA_SIZE_PACKED);

#define pack_S3(data, g) \
polyvecl_freeze(&g.s); \
polyveck_freeze(&g.e); \
for(int i = 0; i < L; ++i) \
	polyz_pack(data + i*POLZ_SIZE_PACKED, &g.s.vec[i]); \
for(int i = 0; i < K; ++i) \
	polyz_pack(data + (L+i)*POLZ_SIZE_PACKED, &g.e.vec[i]);

#define unpack_S3(data, g) \
for(int i = 0; i < L; ++i) \
	polyz_unpack(&g.s.vec[i], data + i*POLZ_SIZE_PACKED); \
for(int i = 0; i < K; ++i) \
	polyz_unpack(&g.e.vec[i], data + (L+i)*POLZ_SIZE_PACKED);


#define add(out, in1, in2) { \
polyvecl_add(&out.s,&in1.s,&in2.s); \
polyveck_add(&out.e,&in1.e,&in2.e); \
polyvecl_freeze(&out.s); \
polyveck_freeze(&out.e); \
}

#define is_in_S3(g) ( ! ( polyvecl_chknorm(&g.s, GAMMA1 - ETA) || polyveck_chknorm(&g.e, GAMMA1 - ETA) ) )

#define do_half_action(out, g) { \
/* Matrix-vector multiplication */ \
	polyvecl s1hat = g.s; \
	polyvecl_ntt(&s1hat); \
	for(int i = 0; i < K; ++i) { \
	polyvecl_pointwise_acc_montgomery(&((*out).vec[i]), &mat[i], &s1hat); \
	poly_invntt_tomont(&((*out).vec[i])); \
	} \
	/* Add error vector s2 */ \
	polyveck_add(out, out, &g.e); \
}

#define finish_action(out,in,pg) \
polyveck_add(out, in, pg); \
polyveck_freeze(out)

#define is_equal_X(A,B) (memcmp(&A,&B,sizeof(XELT)) == 0)

#define init_grpelt(g) 
#define clear_grpelt(g) 