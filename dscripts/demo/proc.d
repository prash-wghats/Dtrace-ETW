

proc:::start
/execname == "grep.exe"/
{
	self->pstart = timestamp;
}


proc:::start
{
	printf("%s, %s, start, %s\n", args[0]->pr_fname,
	    curpsinfo->pr_fname, args[0]->pr_psargs);
}

proc:::exit
{
	printf("%s, %s, exit, %s, %d\n", curpsinfo->pr_fname,
	    "", curpsinfo->pr_psargs, arg0);
}

proc:::lwp-start
{
	printf("%s %s %Y\n", args[1]->pr_fname, threadname, walltimestamp);
}

proc:::lwp-exit
{
	printf("%s %Y\n", curpsinfo->pr_fname, walltimestamp);
}