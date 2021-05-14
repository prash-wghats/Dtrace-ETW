/*
 * https://randomascii.wordpress.com/2012/05/05/xperf-wait-analysisfinding-idle-time/
 *
 * https://github.com/randomascii/bigfiles/blob/master/ETWTraces/2015-09-25_20-56-25%20VS%20F8%20short%20hang.zip
 *
 * dtrace.exe -s randomascii.d -E "2015-09-25_20-56-25 VS F8 short hang.etl"
 */
#pragma D option quiet

/*
Id          : 38
Version     : 0
LogLink     : System.Diagnostics.Eventing.Reader.EventLogLink
Level       : System.Diagnostics.Eventing.Reader.EventLevel
Opcode      : System.Diagnostics.Eventing.Reader.EventOpcode
Task        : System.Diagnostics.Eventing.Reader.EventTask
Keywords    : {, win:ResponseTime, UIUnresponsiveness}
Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                <data name="Flags" inType="win:UInt32" outType="win:HexInt32"/>
                <data name="DelayTimeMs" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="TimeSinceInputRemoveMs" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="TimeSinceOldestInputMs" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="ClassName" inType="win:UnicodeString" outType="xs:string"/>
                <data name="TopLevelClassName" inType="win:UnicodeString" outType="xs:string"/>
                <data name="ImagePath" inType="win:UnicodeString" outType="xs:string"/>
                <data name="MessageId" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="WParam" inType="win:UInt64" outType="xs:unsignedLong"/>
              </template>
*/
struct delay {
	uint32_t flags;
	uint32_t delayms;
	uint32_t inms;
	uint32_t oldms;
	wchar_t *class;
	wchar_t *tclass;
	wchar_t *path;
	uint32_t id;
	uint64_t par;
};

microsoft-windows-win32k:::win_responsetime
/arg0 == 38/
{
	s = (struct delay *) arg2;
	wclass = wstringof((wchar_t *) &s->class);
	tclass = (uintptr_t) &s->class + ((wstrlen((wchar_t *) &s->class) + 1)) * 2;
	wtclass = wstringof((wchar_t *) tclass);
	path = (uintptr_t) tclass + ((wstrlen((wchar_t *) tclass) + 1)) * 2;
	wpath = wstringof((wchar_t *) path);
	
	printf("probe (%s)-(%s)\n\t length of packet %d\n\t delay - %dms\n\t class name - %s\n\t TopLevelClassName - %s\n\t ImagePath - %s\n\t", 
		probeprov, probename, arg4, s->delayms, wstringof((wchar_t *) &s->class), wtclass, wpath);
	printf(" pid - %d, tid - %d, timestamp (nsec) - %d, time %Y\n\n", pid, tid, timestamp,
		walltimestamp);
}

sched:::off-cpu
/* /tid > 4/ */
 /tid == 10364/ 
{
	self->ts = timestamp;
	gtid = tid;
	gts = timestamp;
}

sched:::wakeup
/gtid && args[0]->pr_lwpid == gtid && (timestamp - gts) > 4000000000/
{
	t0 = ((timestamp - gts) * 1000)/1000000000;
	printf("probe (%s-%s)\n\t process (%s) pid (%d) tid (%d) wokeup thread (%d) after (%d)ms\n\n",
		probeprov, probename, execname, pid, tid, args[0]->pr_lwpid, t0);
	printf("the following stack doesnt contain any symbols, because this etw trace contains the module load rundown in the end\n");
	stack();
	@[ustack(), stack(), probeprov, probename, pid, tid, execname, "wakeup", t0, "ms" ] = count();
}

sched:::on-cpu
/self->ts && (timestamp - self->ts) > 5000000000/
{
	t = ((timestamp - self->ts) * 1000)/1000000000;
	@[ustack(), stack(), probeprov, probename, pid, tid, execname, "delay", t, "ms"] = count();
	self->ts = 0;
	gtid = 0;
	gts = 0;
}

sched:::on-cpu
/self->ts/
{
	self->ts = 0;
	gtid = 0;
	gts = 0;
}

fsinfo:::create
/tid > 4/
/* /tid == 10364/ */ 
{
	self->fname = args[0]->fi_pathname; 
	self->tss = timestamp;
	self->irp = args[0]->fi_irp;
	self->wall = walltimestamp;
}

fsinfo:::done
/* /self->tss && (timestamp - self->tss) > 5000000000/ */
/self->irp && (timestamp - self->tss) > 5000000000/
{
	t = timestamp - self->tss;
	printf("probe (%s)-(%s)\n\t pid %d, tid %d, process %s, delay %dms, \n\t start time %Y, end time %Y,\n\t filename %s\n\n", 
		probeprov, probename, pid, tid, execname, (t*1000)/1000000000, self->wall, walltimestamp, self->fname);
	self->tss = 0;
	self->irp = 0;
	self->fname = 0;
	self->wall = 0;
}

fsinfo:::done
/* /self->tss/ */
/self->irp/
{
	self->tss = 0;
	self->irp = 0;
	self->fname = 0;
	self->wall = 0;
}