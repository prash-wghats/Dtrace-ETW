pf:::hardflt
{
	@["hardflt", execname] = count();
	/*printf("pf %s f %s va %p tm %d off %d tid %d\n", probefunc, wstringof((wchar_t *)arg0),
		arg1, arg2, arg3, arg4); */
}

pf:::valloc,
pf:::vfree
{
	@["virtual fault", execname] = count();
	/*printf("pf %s va %p pid %d size %d flags %d\n", probefunc, arg0, arg1, arg2, arg3);*/
}

pf:::imgload
{
	@["imgload fault", execname] = count();
	/*printf("pf imgload fn %s flags %d dev %d ch %d\n", wstringof((wchar_t *)arg0), arg1, arg2, arg3);*/
}

pf:::trans_flt,
pf:::dzero_flt,
pf:::cow_flt,
pf:::gp_flt,
pf:::hp_flt,
pf:::av_flt
{
	@["pageflt", execname] = count();
	/*printf("pf %s va %p pc %p\n", probefunc, arg0, arg1);*/
}
