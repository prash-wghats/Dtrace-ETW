pid$target:t_c_args:str:entry 
{
	printf("func (%s)- (%s) arg0 (char*) (%s), arg1 (wchat_t*) (%s)\n", 
		probefunc, probename, copyinstr(arg0), wstringof(copyin(arg1, 256)));
}

pid$target:t_c_args:str:return 
{
	printf("func (%s)-(%s) off (%d) ret (wchar_t*) (%s)\n", probefunc, probename, 
		arg0, wstringof(copyin(arg1, 256)));
}

pid$target:t_c_args:args:entry 
{
	printf("func (%s)-(%s), arg0 (%d), arg1 (%d), arg2 (%d), arg3 (%d), arg4 (%d)\n",
		probefunc, probename, arg0, arg1, arg2, arg3, (int) arg4);
}

pid$target:t_c_args:args:return 
{
	printf("func (%s)-(%s) off %d ret %d\n", probefunc, probename, arg0, arg1);
}