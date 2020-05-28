
BITS?=512

ifndef UINT_IMPL
	UINT_IMPL=uint.c
	ifneq ("$(wildcard p${BITS}/uint.s)", "")
		UINT_IMPL="$(wildcard p${BITS}/uint.*)"
	endif
endif

ifndef FP_IMPL
	FP_IMPL=fp.c
	ifneq ("$(wildcard p${BITS}/fp.s)", "")
		FP_IMPL="$(wildcard p${BITS}/fp.*)"
	endif
endif

classgroup: csidh.c mont.c classgroup.c reduce.c rng.c rng.h reduce.h csidh.h mont.h classgroup.h keccaklib
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VAL},-DBENCH_VAL=${BENCH_VAL}) \
		$(if ${BENCH_ACT},-DBENCH_ACT=${BENCH_ACT}) \
		-I ./ \
		-I p${BITS}/ \
		-I ../XKCP/bin/Haswell/ \
		-L ../XKCP/bin/Haswell/ \
		-std=c11 -pedantic \
		-Wall -Wextra \
		-march=native -O3 \
		p${BITS}/constants.c \
		rng.c \
		${UINT_IMPL} ${FP_IMPL} \
		mont.c \
		csidh.c \
		reduce.c \
		classgroup.c \
		-c -lm -g -lgmp -lcrypto -lkeccak 
	ar rcs libclassgroup.a *.o 
	rm -f *.o

keccaklib: 
	(cd ../XKCP; make Haswell/libkeccak.a)

clean:
	@rm -f main bench testcsifish

