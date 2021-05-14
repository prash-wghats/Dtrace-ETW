
sample-999
{
	@p[execname, tid] = count();
	printa(@p);
	i++;
	exit(0)
}
END {
	printf("%d", i);
}