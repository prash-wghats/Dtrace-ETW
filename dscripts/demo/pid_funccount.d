pid$target:a.out::entry
{
	@[probefunc, probemod] = count();
}

END {
	trunc(@, 10);
}