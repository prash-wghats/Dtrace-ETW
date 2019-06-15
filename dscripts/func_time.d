BEGIN
{
        evtcnt = 0;
}

pid$target::SleepEx:entry
{
        self->pstart = vtimestamp;
}

pid$target::SleepEx:return
/self->pstart/
{
        t = vtimestamp - self->pstart;
        printf("evtcnt=%d t=%dms\n", ++evtcnt, (t*1000)/1000000000);
        self->pstart = 0;
}