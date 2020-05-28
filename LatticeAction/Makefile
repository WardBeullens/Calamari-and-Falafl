CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -march=native -mtune=native -O3 -fomit-frame-pointer


LIBSOURCES = sign.c polyvec.c poly.c ntt.s invntt.s pointwise.S fips202.c fips202x4.c \
  keccak4x/KeccakP-1600-times4-SIMD256.o \
  nttconsts.c rejsample.c reduce.s rounding.c
LIBHEADERS = sign.h config.h api.h params.h polyvec.h poly.h ntt.h \
  rejsample.h reduce.h rounding.h symmetric.h fips202.h fips202x4.h randombytes.h  

liblattice: $(LIBSOURCES) $(LIBHEADERS)  
	$(CC) $(CFLAGS) $(LIBSOURCES) randombytes.c -c 
	ar rcs liblattice.a *.o 
	rm -f *.o


.PHONY: clean

clean:
	rm -f *~ test/*~
	rm -f keccak4x/KeccakP-1600-times4-SIMD256.o
	rm -f PQCgenKAT_sign
	rm -f PQCgenKAT_sign-AES
	rm -f test/test_vectors
	rm -f test/test_vectors-AES
	rm -f test/test_dilithium
	rm -f test/test_dilithium-AES
	rm -f test/test_mul
