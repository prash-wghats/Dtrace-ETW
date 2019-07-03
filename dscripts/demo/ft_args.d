/*
 * pid provider: function arguments and return value
 */

#pragma D option quiet

pid$target:t_c_args:str:entry 
{
	printf("\n%s()-%s\t: args (char*) [%s], (wchat_t*) [%s]\n", 
		probefunc, probename, copyinstr(arg0), wstringof(copyin(arg1, 256)));
}

pid$target:t_c_args:str:return 
{
	printf("%s()-%s\t: offset [%d], value (wchar_t*) [%s]\n", probefunc, probename, 
		arg0, wstringof(copyin(arg1, 256)));
}

pid$target:t_c_args:args:entry 
{
	printf("%s()-%s\t: args [%d],[%d],[%d],[%d],[%d]\n",
		probefunc, probename, arg0, arg1, arg2, arg3, (int) arg4);
}

pid$target:t_c_args:args:return 
{
	printf("%s()-%s\t: offset [%d], value [%d]\n", probefunc, probename, arg0, arg1);
}