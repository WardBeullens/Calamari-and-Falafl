#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"

/*************************************************
* Name:        power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - uint32_t a: input element
*              - uint32_t *a0: pointer to output element Q + a0
*
* Returns a1.
**************************************************/
inline uint32_t power2round(uint32_t a, uint32_t *a0)  {
  int32_t t;

  /* Centralized remainder mod 2^D */
  t = a & ((1U << D) - 1);
  t -= (1U << (D-1)) + 1;
  t += (t >> 31) & (1U << D);
  t -= (1U << (D-1)) - 1;
  *a0 = Q + t;
  a = (a - t) >> D;
  return a;
}

#endif
