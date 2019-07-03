#include <sys/sdt.h>

void
doogle()
{
	DTRACE_PROBE(doogle, knows);
}
