#ifndef SIGN_H
#define SIGN_H

#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

void expand_mat(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);

#endif
