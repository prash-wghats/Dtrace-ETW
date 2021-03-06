/*
 * userland ctf example
 *
 * debug\amd64\bin\dtrace.exe -s tests\misc\t_c_userctf.d -c debug\amd64\obj\t_c_sim.exe
 */
 
pid$target::RtlHashUnicodeString:entry
{
	this->p = (userland pid`UNICODE_STRING *)arg0;
	print(*(this->p));
	printf("len %d string (%s)\n", this->p->Length, 
	    wstringof(copyin((uintptr_t) this->p->Buffer, (int) this->p->Length+2)));
	exit(0);
}

pid$target::arrayfunc:entry
{
	print(*args[0]);
	print(*args[1]);
}

pid$target::dummyfunc:entry
{
	this->pp = (userland pid`_TEB *)arg0;
	print(*(this->pp));
}