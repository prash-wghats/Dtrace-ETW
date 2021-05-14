/*
 * fpid provider: function arguments and return value
 */


fpid$target:t_c_args:args:entry 
{
	printf("%s()-%s\t: args [%d],[%d],[%d],[%d],[%d]\n",
		probefunc, probename, arg0, arg1, arg2, arg3, (int) arg4);
}

fpid$target:t_c_args:args:return 
{
	printf("%s()-%s\t: offset [%d], value [%d]\n", probefunc, probename, arg0, arg1);
}