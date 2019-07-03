
/*
 * traces all events not processed.
 */
diag:::events
{
	@[stringof(arg0), arg1, arg2] = count();
}
END {
	printf("\n\t\t\tGUID\t\t\t\t\tEvent No\tOpcode\t\t\tCount\n");
	printa(@);
}