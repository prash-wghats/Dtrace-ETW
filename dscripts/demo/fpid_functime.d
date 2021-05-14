


fpid$target:::entry
/self->ts == 0/
{
	self->ts = timestamp;
}

fpid$target:::return
/self->ts/
{
	@[probefunc] = quantize(timestamp - self->ts);

	self->ts = 0;
}
