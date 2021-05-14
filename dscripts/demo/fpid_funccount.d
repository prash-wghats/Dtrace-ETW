fpid$target:::entry
{
	@[probefunc, probemod] = count();
}

END {
	trunc(@, 10);
}