#pragma D option quiet
proc:::start
{
	printf("parent %s\n proc %s\n", curpsinfo->pr_psargs, args[0]->pr_psargs);
}