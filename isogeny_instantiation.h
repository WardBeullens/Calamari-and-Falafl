#if SEED_BYTES != 16
	SEED_BYTES must be 16 for CSIDH-512;
#endif

#include "gmp.h"
#include "ClassGroupAction/classgroup.h"
#include "ClassGroupAction/csidh.h"

#define S1_BYTES 33
#define S3_BYTES 33
#define XELT_BYTES 64
#define PK_BYTES XELT_BYTES
#define init_action init_classgroup
#define GRPELTS1 mpz_t
#define GRPELTS1L GRPELTS1
#define GRPELTS2 GRPELTS1
#define XELT public_key
#define X0 base

extern mpz_t cn;

#define sample_S1(A,B) sample_mod_cn_with_seed(B,A)
#define sample_S1L sample_S1
#define sample_S2_with_seed sample_mod_cn_with_seed 

//Add and subtract is silly trick to force gmp to export 33 bytes
#define pack_S1(data, g) \
mpz_add(g,g,cn); \
mpz_export(data, NULL, 1, 1, 1, 0, g); \
mpz_sub(g,g,cn)

#define unpack_S1(data, g) \
mpz_import(g, 33, 1, 1, 0, 0, data); \
mpz_sub(g,g,cn);

#define pack_S3 pack_S1
#define unpack_S3 unpack_S1

#define add(out, in1, in2) \
mpz_add(out, in1, in2); \
mpz_fdiv_r(out, out,cn)

#define is_in_S3(g) 1

#define PREP_GRPELT private_key

#define do_half_action(pg,g){ \
	mod_cn_2_vec(g, (*pg).e); \
}

#define do_half_tag_action(pg,g){ \
	mpz_t gg; \
	mpz_init(gg); \
	mpz_mul_ui(gg,g,2); \
	mpz_tdiv_r(gg,g,cn); \
	mod_cn_2_vec(gg, (*pg).e); \
}

#define finish_action(out,in,pg){ \
	action(out, in, pg); \
}

/*#define do_half_action(pg,g) 
#define do_half_tag_action(pg,g)
#define finish_action(out,in,pg) memcpy(out,in,PK_BYTES) */

#define do_tag_action(out, in, g) { \
	PREP_GRPELT pg; \
	do_half_tag_action(&pg, g); \
	finish_action(out, in,&pg); \
}

#define derive_pk(PK,S) do_action(PK,&X0,S)
#define derive_tag(PK,S) do_tag_action(PK,&X0,S)

#define is_equal_X(A,B) (memcmp(&A,&B,sizeof(XELT)) == 0)

#define init_grpelt(g) mpz_init(g)
#define clear_grpelt(g) mpz_clear(g) 