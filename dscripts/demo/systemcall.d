dpc:::thread,
dpc:::timer,
dpc:::dpc
{
	@dpc[probename, sym(arg1)] = count(); 
}

isr:::isr
{
	@isr[probename, sym(arg1), arg2, arg3] = count(); 
}

syscall:::entry
{
	@syscall[sym(arg0)] = count();
}
syscall:::return
{
	@ntstatus[arg0] = count();
}
tick-1s
/i++ == 5/
{
	exit(0);
}