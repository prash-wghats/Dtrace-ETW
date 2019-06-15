fpid$target:::entry,
fpid$target:::return
{
	@[probemod, probefunc, ustack()] = count();
}


/*fpid$target:mscorlib::
{
	@[ustack()] = count();
}
fpid$target:a.out::
{
	@[ustack()] = count();
}
fpid$target:System.C*::
{
	@[ustack()] = count();
}

fpid$target:System::
{
	@[ustack()] = count();
}

fpid$target:System.Drawing::
{
	@[ustack()] = count();
}

fpid$target:System.Windows.Forms::
{
	@[ustack()] = count();
}
fpid$target:System.Xml::
{
	@[ustack()] = count();
}
*/
END {
	trunc(@, 10);
}