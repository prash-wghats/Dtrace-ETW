
struct delay {
	uint32_t flags;
	uint32_t delayms;
	uint32_t inms;
	uint32_t oldms;
	wchar_t *class;
	wchar_t *tclass;
	wchar_t *path;
	uint32_t id;
	uint64_t par;
};

Microsoft-Windows-Win32k:::win_ResponseTime
/arg0 == 38/
{
	s = (struct delay *) arg2;
	wclass = wstringof((wchar_t *) &s->class);
	tclass = (uintptr_t) &s->class + ((wstrlen((wchar_t *) &s->class) + 1)) * 2;
	wtclass = wstringof((wchar_t *) tclass);
	path = (uintptr_t) tclass + ((wstrlen((wchar_t *) tclass) + 1)) * 2;
	wpath = wstringof((wchar_t *) path);
	printf("%d ", s->delayms);
	
	printf("probe (%s)-(%s)\n\t length of packet %d\n\t delay - %dms\n\t class name - %s\n\t TopLevelClassName - %s\n\t ImagePath - %s\n\t", 
		probeprov, probename, arg4, s->delayms, wstringof((wchar_t *) &s->class), wtclass, wpath);
	printf(" pid - %d, tid - %d, timestamp (nsec) - %d, time %Y\n\n", pid, tid, timestamp,
		walltimestamp);
}

