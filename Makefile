CC=gcc
CFLAGS=-I XKCP/bin/Haswell/
LFLAGS=-L XKCP/bin/Haswell/ -lgmp -lkeccak -lcrypto

IMPLEMENTATION_SOURCE = seedtree.c lrsign.c rsign.c test.c
IMPLEMENTATION_HEADERS= seedtree.h lrsign.h rsign.h parameters.h 

test_rs_iso: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) ClassGroupAction/libclassgroup.a keccaklib
	gcc -o test_rs_iso $(IMPLEMENTATION_SOURCE) $(CFLAGS) -I ClassGroupAction/p512/ -I ClassGroupAction/ -DISOGENY -L ClassGroupAction/ -lclassgroup $(LFLAGS) -std=c11 -O3 -g -march=native 

test_rs_lat: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) keccaklib LatticeAction/liblattice.a
	gcc -o test_rs_lat $(IMPLEMENTATION_SOURCE) $(CFLAGS) -I LatticeAction/ -DLATTICE -L LatticeAction/ -llattice $(LFLAGS) -std=c11 -O3 -g -march=native 

test_lrs_iso: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) ClassGroupAction/libclassgroup.a keccaklib
	gcc -o test_lrs_iso $(IMPLEMENTATION_SOURCE) $(CFLAGS) -I ClassGroupAction/p512/ -I ClassGroupAction/ -DTEST_LINKABLE -DISOGENY -L ClassGroupAction/ -lclassgroup $(LFLAGS) -std=c11 -O3 -g -march=native 

test_lrs_lat: $(IMPLEMENTATION_SOURCE) $(IMPLEMENTATION_HEADERS) keccaklib LatticeAction/liblattice.a
	gcc -o test_lrs_lat $(IMPLEMENTATION_SOURCE) $(CFLAGS) -I LatticeAction/ -DLATTICE -L LatticeAction/ -DTEST_LINKABLE -llattice $(LFLAGS) -std=c11 -O3 -g -march=native 

ClassGroupAction/libclassgroup.a: 
	(cd ClassGroupAction; make classgroup)

LatticeAction/liblattice.a: LatticeAction/params.h
	(cd LatticeAction; make liblattice)

keccaklib: 
	(cd XKCP; make Haswell/libkeccak.a)

.PHONY: clean
clean:
	rm -f PQCgenKAT_sign test debug test_offline intermediateValues.txt *.req *.rsp >/dev/null