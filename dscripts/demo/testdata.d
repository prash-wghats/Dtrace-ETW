
sample-999
{
	@stack[ustack()] = count();
}
sched:::on-cpu,
sched:::wakeup
{
	@stack[ustack()] = count();
}

profile:::tick-1sec
/i++ > 10/
{
	exit(0);
}

END { trunc(@stack, 5); }