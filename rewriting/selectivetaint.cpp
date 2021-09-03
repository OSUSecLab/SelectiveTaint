#include <stdio.h>
#include "taint.h"


int main(int argc, char **argv)
{
	taint_initialize(argc, argv);
	taint_instrument();
	taint_finalize();
	return 0;
}
