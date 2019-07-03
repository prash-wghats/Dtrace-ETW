
profile-1234hz
/arg0 != 0/
{
	@mk[mod(arg0)] = count();
}

profile-1234hz
/arg1 != 0/
{
	@mu[umod(arg1)] = count();
}

profile-1234hz
/arg0 != 0/
{
	@sk[sym(arg0)] = count();
}

profile-1234hz
/arg1 != 0/
{
	@su[usym(arg1)] = count();
}

tick-100ms
/i++ == 20/
{
	exit(0);
}
tick-100ms
{
}

END {
	trunc(@mk, 5);
	trunc(@mu, 5);
	trunc(@sk, 5);
	trunc(@su, 5);
}
/*profile-1234hz
/arg1 != 0/
{
	@mu[umod(arg1)] = count();
}
profile-1234hz
/arg0 != 0/
{
	@mk[mod(arg0)] = count();
}
profile-1234hz
/arg1 != 0/
{
	@su[usym(arg1)] = count();
}
profile-1234hz
/arg0 != 0/
{
	@sk[sym(arg0)] = count();
}
tick-100ms
/i++ == 20/
{
	exit(0);
}
tick-100ms
{
}

END {
	trunc(@mk, 5);
	trunc(@mu, 5);
	trunc(@sk, 5);
	trunc(@su, 5);
}
*/