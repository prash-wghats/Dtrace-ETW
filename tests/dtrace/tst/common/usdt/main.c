#if 1
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <unistd.h>
#include <stdio.h>

static void
foo(void)
{
	(void) close(-1);
}

int
main(int argc, char **argv)
{
	void *live;
#if 0
	if ((live = dlopen("./livelib.so", RTLD_LAZY | RTLD_LOCAL)) == NULL) {
		printf("dlopen of livelib.so failed: %s\n", dlerror());
		return (1);
	}

	(void) dlclose(live);
#else
	if ((live = LoadLibrary("./livelib.so")) == NULL) {
		printf("dlopen of livelib.so failed: %s\n", GetLastError());
		return (1);
	}

	(void) FreeLibrary(live);
#endif
	foo();

	return (0);
}
