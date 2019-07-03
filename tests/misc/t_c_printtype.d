/* printtype.exe */
pid$target::ff_getgameid:entry
/next == 0/
{
	print(*args[0]);

	printf("\n");
	next = 1;
}

pid$target::ff_getpartysize:entry
/next == 1/
{
	print(*args[0]);
	printf("\n");
	next = 2;
}

pid$target::ff_getsummons:entry
/next == 2/
{
	print(*args[0]);
	printf("\n");
	exit(0);
}