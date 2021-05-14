/* dtrace -s ustack.d firefox.exe [-E <etlfile>] */
sample-999
/execname == $1/
{
	@[ustack()]=count();
}

tick-1sec
/i++ >= 10/
{
	exit(0);
}

END {
	trunc(@,10);
}