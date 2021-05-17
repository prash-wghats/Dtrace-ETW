
/* http://dtrace.org/guide/chp-sched.html */

#pragma D option strsize=2048
#pragma D option quiet

proc:::start
{
	printf("Start Process (%s), Parent (%s), args (%s) \n", args[0]->pr_fname,
	    curpsinfo->pr_fname, args[0]->pr_psargs);
}

