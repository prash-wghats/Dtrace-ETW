#include <sys/sdt.h>

void
bagnoogle()
{
	DTRACE_PROBE(doogle, bagnoogle);
}
