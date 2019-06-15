pid$target:a.out::entry,
pid$target:a.out::return
{
	@[ustack()] = count();
}

END {
	trunc(@, 10);
}