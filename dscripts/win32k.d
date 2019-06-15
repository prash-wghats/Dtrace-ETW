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

Microsoft-Windows-Win32k:::win_ResponseTime
/arg0 == 38/
{
	s = (struct delay *) arg2;
	wclass = wstringof((wchar_t *) &s->class);
	tclass = (uintptr_t) &s->class + ((wstrlen((wchar_t *) &s->class) + 1)) * 2;
	wtclass = wstringof((wchar_t *) tclass);
	path = (uintptr_t) tclass + ((wstrlen((wchar_t *) tclass) + 1)) * 2;
	wpath = wstringof((wchar_t *) path);
	printf("pid - %d, tid - %d, timestamp (nsec) - %d, time %Y\n", pid, tid, timestamp,
		walltimestamp);
	printf("length of packet %d\n delay - %dms\n class name - %s\n TopLevelClassName - %s\n ImagePath - %s\n", 
		arg4, s->delayms, wstringof((wchar_t *) &s->class), wtclass, wpath);
}