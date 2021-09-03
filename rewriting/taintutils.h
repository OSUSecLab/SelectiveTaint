#ifndef TAINT_UTILS_H_
#define TAINT_UTILS_H_

std::string index_to_register(int index);
void readmemaddr(unsigned long addr);
void printint(int a);
void debug_printf(const char *fmt, ...);
void my_fprintf(const char *fmt, ...);
void result_fprintf(const char *fmt, ...);
void result_test(unsigned long addr);
#endif
