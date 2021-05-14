
int i;
:::
{
	i++;
	@[ustack()] = count();
	@c[umod(ucaller)] = count();
}

END {
	printf("%d", i);
	trunc(@, 20);
	trunc(@c, 20);
}