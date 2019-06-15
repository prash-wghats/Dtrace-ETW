/* dtrace -s ustack.d firefox.exe */
sample-999
/execname == $1/
{
	@[ustack()]=count();
}

END {
	trunc(@,100);
}