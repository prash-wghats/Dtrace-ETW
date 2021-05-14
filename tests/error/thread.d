
int i;
sample-999
{
	i++;
	@[ustack()] = count();
}
END {
	printf("%d", i);
	trunc(@, 5);
}