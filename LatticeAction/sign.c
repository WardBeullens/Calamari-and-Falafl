#include <stdint.h>
#include "fips202.h"
#ifdef USE_AES
#include "aes256ctr.h"
#endif
#include "params.h"
#include "sign.h"
#include "randombytes.h"
#include "symmetric.h"
#include "poly.h"
#include "polyvec.h"

/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*              or AES256CTR(rho,j|i).
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/
#ifdef USE_AES
void expand_mat(polyvecl mat[K], const uint8_t rho[SEEDBYTES]) {
  unsigned int i, j;
  aes256ctr_ctx state;

  aes256ctr_init(&state, rho, 0);

  for(i = 0; i < K; ++i)
    for(j = 0; j < L; ++j)
      poly_uniform_aes(&mat[i].vec[j], &state, (i << 8) + j);
}
#elif L == 2 && K == 3
void expand_mat(polyvecl mat[3], const uint8_t rho[SEEDBYTES])
{
  poly t0, t1;

  poly_uniform_4x(&mat[0].vec[0],
                  &mat[0].vec[1],
                  &mat[1].vec[0],
                  &mat[1].vec[1],
                  rho, 0, 1, 256, 257);
  poly_uniform_4x(&mat[2].vec[0],
                  &mat[2].vec[1],
                  &t0,
                  &t1,
                  rho, 512, 513, 0, 0);
}
#elif L == 3 && K == 4
void expand_mat(polyvecl mat[4], const uint8_t rho[SEEDBYTES])
{
  poly_uniform_4x(&mat[0].vec[0],
                  &mat[0].vec[1],
                  &mat[0].vec[2],
                  &mat[1].vec[0],
                  rho, 0, 1, 2, 256);
  poly_uniform_4x(&mat[1].vec[1],
                  &mat[1].vec[2],
                  &mat[2].vec[0],
                  &mat[2].vec[1],
                  rho, 257, 258, 512, 513);
  poly_uniform_4x(&mat[2].vec[2],
                  &mat[3].vec[0],
                  &mat[3].vec[1],
                  &mat[3].vec[2],
                  rho, 514, 768, 769, 770);
}
#elif L == 4 && K == 5
void expand_mat(polyvecl mat[5], const uint8_t rho[SEEDBYTES])
{
  poly_uniform_4x(&mat[0].vec[0],
                  &mat[0].vec[1],
                  &mat[0].vec[2],
                  &mat[0].vec[3],
                  rho, 0, 1, 2, 3);
  poly_uniform_4x(&mat[1].vec[0],
                  &mat[1].vec[1],
                  &mat[1].vec[2],
                  &mat[1].vec[3],
                  rho, 256, 257, 258, 259);
  poly_uniform_4x(&mat[2].vec[0],
                  &mat[2].vec[1],
                  &mat[2].vec[2],
                  &mat[2].vec[3],
                  rho, 512, 513, 514, 515);
  poly_uniform_4x(&mat[3].vec[0],
                  &mat[3].vec[1],
                  &mat[3].vec[2],
                  &mat[3].vec[3],
                  rho, 768, 769, 770, 771);
  poly_uniform_4x(&mat[4].vec[0],
                  &mat[4].vec[1],
                  &mat[4].vec[2],
                  &mat[4].vec[3],
                  rho, 1024, 1025, 1026, 1027);
}
#elif L == 5 && K == 6
void expand_mat(polyvecl mat[6], const uint8_t rho[SEEDBYTES])
{
  poly t0, t1;

  poly_uniform_4x(&mat[0].vec[0],
                  &mat[0].vec[1],
                  &mat[0].vec[2],
                  &mat[0].vec[3],
                  rho, 0, 1, 2, 3);
  poly_uniform_4x(&mat[0].vec[4],
                  &mat[1].vec[0],
                  &mat[1].vec[1],
                  &mat[1].vec[2],
                  rho, 4, 256, 257, 258);
  poly_uniform_4x(&mat[1].vec[3],
                  &mat[1].vec[4],
                  &mat[2].vec[0],
                  &mat[2].vec[1],
                  rho, 259, 260, 512, 513);
  poly_uniform_4x(&mat[2].vec[2],
                  &mat[2].vec[3],
                  &mat[2].vec[4],
                  &mat[3].vec[0],
                  rho, 514, 515, 516, 768);
  poly_uniform_4x(&mat[3].vec[1],
                  &mat[3].vec[2],
                  &mat[3].vec[3],
                  &mat[3].vec[4],
                  rho, 769, 770, 771, 772);
  poly_uniform_4x(&mat[4].vec[0],
                  &mat[4].vec[1],
                  &mat[4].vec[2],
                  &mat[4].vec[3],
                  rho, 1024, 1025, 1026, 1027);
  poly_uniform_4x(&mat[4].vec[4],
                  &mat[5].vec[0],
                  &mat[5].vec[1],
                  &mat[5].vec[2],
                  rho, 1028, 1280, 1281, 1282);
  poly_uniform_4x(&mat[5].vec[3],
                  &mat[5].vec[4],
                  &t0,
                  &t1,
                  rho, 1283, 1284, 0, 0);
}
#else
#error
#endif
