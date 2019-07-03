
/* http://dtrace.org/guide/chp-sched.html */
/* dtrace -s wakeup.d firefox.exe */

#pragma D option quiet

dtrace:::BEGIN
{
	start = timestamp;
}

sched:::wakeup
/stringof(args[1]->pr_fname) == $$1/
{
	@[execname] = lquantize((timestamp - start) / 1000000000, 0, 10);
}

profile:::tick-1sec
/++x == 10/
{
	exit(0);
}