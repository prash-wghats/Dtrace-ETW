

#pragma D option strsize=4048

/*
 * debug\amd64\bin\dtrace.exe -s .\tests\misc\t_cs_args.d -c .\debug\amd64\obj\t_cs_str.exe
 */
char *s;

pid$target:t_cs_str:Strings.Program.Function1:entry
{
	off = arg0+8;
	len = *((int *) copyin(off, 4));
	off += 4;
	s = (char *) copyin(off, (len+1)*2);
	printf("arg0 %s len %d\n", wstringof(copyin(off, (len+1)*2)), len);
	
	/*tracemem(copyin(off, (len+1)*2), 4048, len*2 );
	ustack();*/
}