#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>



//#define	MAP_HUGETLB	0x40000	/* architecture specific */ // does not work

using namespace std;

// each bit tags a byte
//uint8_t *bitmap;
uint8_t bitmap[512*1024*1024] = {0};

// 2^index array for quick lookup
//int twosqures[32] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000, 0x1000000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, int(0x80000000)};




// for each VPU we only use least 4 bits for each register although here we have 32 bits for each regsiter
// order:
// eax, ebx, ecx, edx, edi, esi, esp, ebp
//uint32_t gpr[8] = {0x9,0,2,0xb,4,5,6,7};
uint32_t gpr[8] = {0};


uint32_t twosquare[8] = {0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80};
uint32_t squarevalue = 1;

int testvar = 0;

int local_repeat_time = 0;
int local_effective_address = 0;
int local_reg_value_before = 0;
int local_reg_value_after = 0;
int local_insn_addr = 0;
int local_op0_value = 0;
int local_op1_value = 0;
int local_tmp_tag = 0;
int local_op0_tag = 0;
int local_op1_tag = 0;
int local_first_bytes = 0;


std::string index_to_register(int index)
{
	switch(index)
	{
		case 0:
			return string("eax");
		case 1:
			return string("ebx");
		case 2:
			return string("ecx");
		case 3:
			return string("edx");
		case 4:
			return string("edi");
		case 5:
			return string("esi");
		case 6:
			return string("esp");
		case 7:
			return string("ebp");
		default:
			return string("INVALID");
	}
}

void readmemaddr(unsigned long addr)
{
	cout << "readmemaddr: addr: 0x" << hex << addr << endl;
}

void printint(int a)
{
	cout << "printint(): " << hex << a << endl;

	/*ofstream myfile;
	myfile.open ("/tmp/selectiveTaintLog.txt", fstream::in | fstream::out | fstream::app);
	myfile << hex << a << endl;
	myfile.close();
	*/

}


void debug_printf(const char *fmt, ...)
{

	va_list args;
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	//cout << "bitmap addr: " << hex << &bitmap << endl;
	//cout << hex << 0x91234567 * 0x2 << endl;

	/*
	FILE *fp = fopen("hi", "a");
	va_list args;
	va_start(args, fmt);
	vfprintf(fp, fmt, args);
	va_end(args);
	fclose(fp);
	*/
}

void debug_fprintf(const char *fmt, ...)
{
	FILE *fp = fopen("/home/sec/artifact/selectivetaint/debug_output", "a");
	va_list args;
	va_start(args, fmt);
	vfprintf(fp, fmt, args);
	va_end(args);
	fflush(fp);
	fclose(fp);
}

void result_fprintf(const char *fmt, ...)
{
	FILE *fp = fopen("/home/sec/artifact/selectivetaint/result_output", "a");
	va_list args;
	va_start(args, fmt);
	vfprintf(fp, fmt, args);
	va_end(args);
	fflush(fp);
	fclose(fp);
	sleep(2);
}

void result_test(unsigned long addr)
{
	cout << "readmemaddr: addr: 0x" << hex << addr << endl;
}

