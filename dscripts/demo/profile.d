
sample-999
/ucaller || caller/
{
	@proc[pid, execname, ucaller ? ucaller : caller] = count();
	@stack[ustack()] = count();
}
profile:::tick-1sec
/i++ > 10/
{
	exit(0);
}

END
{
	printf("%-8s %-40s %-16s %s\n", "PID", "CMD", "CALLER", "COUNT");
	printa("%-8d %-40s %-16x %@d\n", @proc);
	trunc(@stack, 4);
}