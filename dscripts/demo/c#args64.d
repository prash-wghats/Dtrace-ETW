pid$target:t_cs_str:Strings.Program.Function1:entry
{
	off = arg0+8;
	len = *((int *) copyin(off, 4));
	off += 4;
	printf("arg0 %s len %d\n", wstringof(copyin(off, (len+1)*2)), len);
}