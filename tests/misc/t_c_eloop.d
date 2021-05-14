

fpid$target:a.out::entry
{
	@func[probemod, probefunc, probename] = count();
	@us[ustack()] = count();

	i++;
}

END {
	trunc(@func, 10);
	trunc(@us, 5);
	printf("Total call %d", i);
}