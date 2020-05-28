#include "rsign.h"
#include "lrsign.h"
#include "parameters.h"
#include <stdio.h>
#include <time.h>
#include "stdlib.h"

#define KEYGENS  (1<<1) // (1<<3)
#define SIGNINGS 1
#define MESSAGE_BYTES 500

#ifdef TEST_LINKABLE
	#define sign lrsign
	#define verify lrverify
	#define SIG_BYTES LRSIG_BYTES
#else
 	#define sign rsign
	#define verify rverify
	#define SIG_BYTES RSIG_BYTES
#endif

#define LOG_N LOG(KEYGENS)

static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %lu \n",#A ,rdtsc() - cl); cl = rdtsc();

extern uint64_t restarts;

#define PS(x) ((x > Q/2)? ((int)x-Q):((int) x))

int main(int argc, char const *argv[])
{
	init_action();

	unsigned char *pks = aligned_alloc(32, KEYGENS*PK_BYTES);
	unsigned char *sks = aligned_alloc(32, KEYGENS*SK_BYTES);

	clock_t t0;
	double keygenTime = 0;
	double signTime = 0;
	double verifyTime = 0;
	uint64_t signature_size = 0;
	uint64_t keygenCycles = 0;
	uint64_t signCycles = 0;
	uint64_t verifyCycles = 0;
	uint64_t t;

	printf("PK BYTES %ld \n", (long int) PK_BYTES);
	printf("SK BYTES %ld \n", (long int) SK_BYTES);

	for (int i = 0; i < KEYGENS ; ++i)
	{
		//printf("keygen #%d \n", i);
		t0 = clock();
		t = rdtsc();

		keygen(pks + i*PK_BYTES, sks + i*SK_BYTES);

		keygenCycles += rdtsc() - t;
		keygenTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;
	}

	printf("keygen cycles :       %lu \n", keygenCycles/KEYGENS );
	printf("keygen time :         %.1lf ms \n\n", keygenTime/KEYGENS );

	unsigned char message[MESSAGE_BYTES] = {0};
	unsigned char *sig = aligned_alloc(32,SIG_BYTES(LOG_N));

	for (int i = 0; i < SIGNINGS; ++i)
	{
		//printf("signing #%d \n", i);
		uint64_t ss;

		t0 = clock();
		t = rdtsc();
		sign(sks + (i%KEYGENS)*SK_BYTES, i%KEYGENS, pks, KEYGENS, message, MESSAGE_BYTES, sig, &ss);
		signCycles += rdtsc()-t;
		signTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;
		signature_size += ss;

		//printf("verify #%d \n", i);

		t0 = clock();
		t = rdtsc();
		int ver = verify(pks, KEYGENS, message, MESSAGE_BYTES, sig);
		verifyCycles += rdtsc()-t;
		verifyTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

		if( ver  != 0){
			printf("signature #%d does not verify successfully! \n", i);
		}
	}

	printf("signing cycles :      %lu \n", signCycles/SIGNINGS );
	printf("signing time :        %.1lf ms \n\n", signTime/SIGNINGS );

	printf("signature size :      %lu bytes \n\n", signature_size/SIGNINGS);

	printf("verification cycles : %lu \n", verifyCycles/SIGNINGS );
	printf("verification time :   %.1lf ms \n", verifyTime/SIGNINGS );
	printf("restarts: %ld \n", restarts);

	free(pks);
	free(sks);
	free(sig);

	return 0;
}
