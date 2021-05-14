
pid$target::loopsdll*:entry
{
	@func[probemod, probefunc] = count();
}
