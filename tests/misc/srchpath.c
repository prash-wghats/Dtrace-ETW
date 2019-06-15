#include <stdio.h>
#include <string.h>

#define MAX_PATH 1024
char _NT_SYMBOL_PATH0[]= "srv*c:\\symbols*http://msdl.microsoft.com/download/symbols;e:\\sym;cache*//share1/dir;d:\\my\\symms";
char pdbdir[] = "\\Debug\\bin\\test.dll";
int main()
{
	char *SYMPATH = _NT_SYMBOL_PATH0;//getenv("_NT_SYMBOL_PATH");
	char fn[MAX_PATH];
	char *tmp1 = SYMPATH, *tmp0, *s0, *s1, *symdir = NULL;
	int fnd = 0;
	size_t r = 0;
	char env[MAX_PATH];
	
	if (getenv_s(&r, env, MAX_PATH, "_NT_SYMBOL_PATH") == 0) {
	
		printf("envs %s\n", env);
	}
	do {
		tmp0 = tmp1;
		tmp1 = strchr(tmp1, ';');
		if (tmp1 != NULL) {
			*tmp1 = 0;
			++tmp1;
		}
		if (strstr(tmp0, "cache")) {
			continue;
		}
		if (strstr(tmp0, "srv")) {
			s0 = strchr(tmp0, '*');
			s1 = strchr(++s0, '*');
			if (s1 != NULL) {
				s1[0] = 0;
			}
			
			symdir = s0;
			
		} else {
			s0 = tmp0;
		}
		strcpy(fn, s0);
		strcpy(fn+strlen(s0), pdbdir);	
		
		printf("%s %s\n", s0, fn);
	} while (tmp1!= NULL);
	
	
	return 0;
}