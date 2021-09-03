#ifndef TAINT_H_
#define TAINT_H_

int taint_main(int argc, char **argv);
int taint_initialize(int argc, char **argv);
int taint_instrument();
int taint_finalize();

#endif
