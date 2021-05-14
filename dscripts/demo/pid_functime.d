
/*
 * time spent in a function
 */
#pragma D option quiet

BEGIN
{
        evtcnt = 0;
}

pid$target::SleepEx:entry
{
        self->pstart = timestamp;
}

pid$target::SleepEx:return
/self->pstart/
{
        t = timestamp - self->pstart;
        printf("evtcnt=%d t=%dms\n", ++evtcnt, (t*1000)/1000000000);
        self->pstart = 0;
}