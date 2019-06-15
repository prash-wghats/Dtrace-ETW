#include <unistd.h>
#include <sys/sdt.h>

static void
foo(void)
{
	DTRACE_PROBE(test_prov, probe1);
	DTRACE_PROBE(test_prov, probe2);
}

int
main(int argc, char **argv)
{
	DTRACE_PROBE(test_prov, probe1);
	DTRACE_PROBE(test_prov, probe2);
	foo();
}
