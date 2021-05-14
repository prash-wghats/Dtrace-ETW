pid$target:a.out::entry,
pid$target:a.out::return
{
	@[probefunc, probemod, ustack()] = count();
}

END {
	trunc(@, 10);
}