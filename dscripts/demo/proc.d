
#pragma D option strsize=2048

proc:::start
{
	printf("Start Process (%s), Parent (%s), args (%s) \n", args[0]->pr_fname,
	    curpsinfo->pr_fname, args[0]->pr_psargs);
}

proc:::exit
{
	printf("Process (%s) exiting (%d), (%s)\n", curpsinfo->pr_fname, args[0], curpsinfo->pr_psargs);
}

proc:::lwp-start
{
	printf("thread Begin (%s) tid (%d) name (%s)\n", args[1]->pr_fname, args[0]->pr_lwpid, args[0]->pr_tname);
}

proc:::lwp-exit
{
	printf("Thread exit (%s) tid (%d) name (%s)\n", curpsinfo->pr_fname, curlwpsinfo->pr_lwpid, threadname);
}


proc:::module-load
{
	printf("pid (%d) Loading (%s) at (%x)\n", pid, wstringof(args[0]), args[1]);
}

proc:::module-unload
{
	printf("pid (%d) UnLoading (%s) from (%x)\n", pid, wstringof(args[0]), args[1]);
}

tick-1s
/i++ == 5/
{
	printf("Existing after (%d) seconds \n", i);
	exit(0);
}
