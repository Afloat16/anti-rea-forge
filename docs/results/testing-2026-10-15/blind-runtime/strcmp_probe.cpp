#include <unistd.h>
#include <stddef.h>
static void line(const char* p) { size_t n = 0; while(p[n] && n < 4096) ++n; write(2,p,n); write(2,"\n",1); }
extern "C" int strcmp(const char* a,const char* b) { write(2,"strcmp lhs: ",12); line(a); write(2,"strcmp rhs: ",12); line(b); while(*a && *a == *b) { ++a; ++b; } return (unsigned char)*a-(unsigned char)*b; }
