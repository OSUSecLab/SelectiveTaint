# path to  dyninst binaries
DYNINST_ROOT = /usr/local

# path to libelf and libdwarf
DEPS_ROOT = /usr/local

# where to install
INSTALL_ROOT = /usr/local

CXX = g++
CXXFLAGS = -g -Wall -O3 -std=c++11
LIBFLAGS = -fpic -shared

CC = gcc
CFLAGS = -Wall -pedantic -g -std=gnu99

AR = ar
ARFLAGS = rcs

all: selectivetaint libtaint.a libtaintutils.so

# selectivetaint executable
selectivetaint: selectivetaint.o libtaint.a libtaintutils.so
	$(CXX) $(CXXFLAGS) \
		-o selectivetaint selectivetaint.o \
		-L. \
		-L$(DYNINST_ROOT)/lib \
		-L$(DEPS_ROOT)/lib \
		-I. \
		-I$(DEPS_ROOT)/include -I$(DYNINST_ROOT)/include \
		-ltaint \
		-ldyninstAPI -lparseAPI -lpatchAPI\
		-linstructionAPI -lsymtabAPI \
		-lsymLite -ldynDwarf -ldynElf -lelf -ldwarf \
		-lcommon -lcapstone


selectivetaint.o: selectivetaint.cpp
	$(CXX) $(CXXFLAGS) -c -o selectivetaint.o selectivetaint.cpp

# selective taint static library
libtaint.a: taint.o
	$(AR) $(ARFLAGS) libtaint.a taint.o


# taint main c file
taint.o: taint.cpp
	$(CXX) $(CXXFLAGS) -L$(DYNINST_ROOT)/lib \
		-L$(DEPS_ROOT)/lib \
		-I$(DEPS_ROOT)/include -I$(DYNINST_ROOT)/include \
		-c -fPIC -o taint.o taint.cpp \
		-ldyninstAPI -lparseAPI -lpatchAPI\
		-linstructionAPI -lsymtabAPI \
		-lsymLite -ldynDwarf -ldynElf -lelf -ldwarf \
		-lcommon -lcapstone


# taint utils library
libtaintutils.so: taintutils.cpp
	$(CXX) $(CXXFLAGS) $(LIBFLAGS) -I$(DEPS_ROOT)/include taintutils.cpp -lpthread -o libtaintutils.so

clean:
	rm -f selectivetaint *.a *.so *.o ./ls ls_1 thread thread_1 ./test test_1 debug_output ls_debug_output #result_output #nginx nginx_1

install: all
	install -d $(INSTALL_ROOT)/bin
	install -d $(INSTALL_ROOT)/lib
	install taint $(INSTALL_ROOT)/bin
	install libtaintutils.so $(INSTALL_ROOT)/lib	
