#pragma D option bufsize=30m
/*
 * arg0 0 = entry 1 = return
 * arg1 func address
 * arg2 arg3 arg4 - func parameters for entry
 * arg2 return status for return
 */
diag:::fpid
{
    @tid[tid] = count();
	@func[usym(arg1)] = count();
	@us[ustack()] = count();
}
END {
	trunc(@func, 10);
	trunc(@us, 10);
}