
/* http://dtrace.org/guide/chp-sched.html */

sched:::on-cpu
/tid != 0/
{
	self->ts = timestamp;
}

sched:::off-cpu
/self->ts/
{
	@[cpu] = quantize(timestamp - self->ts);
	self->ts = 0;
}


