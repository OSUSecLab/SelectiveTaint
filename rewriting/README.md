# selectivetaint

0.set environment
. ./scripts/set_environment.sh

1.conveats:

Tested:
Ubuntu 14.04.6 TLS
kernel: 3.13.0-031300-generic

1.1 for instrumentation:

install dyninst-9.3.2

export DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)

make

Be careful not to sudo make install, otherwise anytime we change source code we need to install new headers and libs.


1.2 for analysis:
install archinfo, pyvex, claripy, cle, angr in order in ubuntu 14.04.6 TLS 32 bit
all in version 7.7.9.8

install capstone 4.0.2


1.3 for evaluation

install intel pin 2.14

for libdft, install our ported libdft


2.to test
./recompileandrun.sh 1
./recompileandrun.sh 2
./recompileandrun.sh 3
./recompileandrun.sh 4
./recompileandrun.sh 5
