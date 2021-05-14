/*
 * traces all events not processed.
 */
int i, u, k, z, zk, t;
uint64_t ts;
diag:::missed-stack
{
	k++;
	@kk[stack()] = count();
	@ku[ustack()] = count();
}

diag:::missed-ustack
{
	@uk[stack()] = count();
	@uu[ustack()] = count();
	u++;
}

diag:::missed-dnet-stack
{
	@dk[stack()] = count();
	@du[ustack()] = count();
	dnet++;
}

:systemtrace::,
:::events
{
	/*@allk[stack()] = count();
	@allu[ustack()] = count();*/
	all++;
}

diag:::events
{
	@events[stringof(arg0), arg1] = count();
	diag_all++;
}

diag:::ignored
{
	/*@ignored[stringof(arg0)] = count();*/
	ii++;
}

END {
	printf("Total Events %d\n", diag_all);
	printf("ignored Events %d\n", ii);
	printf("Missed kernel stack\n");
	trunc(@kk, 0);
	trunc(@ku, 0);
	printf("\tKernel");
	printa(@kk);
	printf("\tUser");
	printa(@ku);

	printf("\nMissed user stack\n");
	trunc(@uk, 0);
	trunc(@uu, 0);
	printf("\tKernel");
	printa(@uk);
	printf("\tUser");
	printa(@uu);

	printf("\nMissed .net stack\n");
	trunc(@dk, 0);
	trunc(@du, 0);
	printf("\tKernel");
	printa(@dk);
	printf("\tUser");
	printa(@du);

	printf("\n\t\t\tGUID\t\t\t\t\t\t\t\t\tCount\n");
	printa(@events);
	/*trunc(@allk, 10);
	trunc(@allu, 10);*/
}
