/*
 * ETW event information can be extracted using powershell.
 * For example, to get information about Microsoft-Windows-DNS-Client providers 
 * events, use the following command in powershell.
 * => Get-WinEvent -ListProvider *DNS-Client).events
 *
 * following is an extract from the command about event no 3006
 *
 * Id          : 3006
 * Version     : 0
 * LogLink     : System.Diagnostics.Eventing.Reader.EventLogLink
 * Level       : System.Diagnostics.Eventing.Reader.EventLevel
 * Opcode      : System.Diagnostics.Eventing.Reader.EventOpcode
 * Task        : System.Diagnostics.Eventing.Reader.EventTask
 * Keywords    : {}
 * Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
 *                 <data name="QueryName" inType="win:UnicodeString" outType="xs:string"/>
 *                 <data name="QueryType" inType="win:UInt32" outType="xs:unsignedInt"/>
 *                 <data name="QueryOptions" inType="win:UInt64" outType="xs:unsignedLong"/>
 *                 <data name="ServerList" inType="win:UnicodeString" outType="xs:string"/>
 *                 <data name="IsNetworkQuery" inType="win:UInt32" outType="xs:unsignedInt"/>
 *                 <data name="NetworkQueryIndex" inType="win:UInt32" outType="xs:unsignedInt"/>
 *                 <data name="InterfaceIndex" inType="win:UInt32" outType="xs:unsignedInt"/>
 *                 <data name="IsAsyncQuery" inType="win:UInt32" outType="xs:unsignedInt"/>
 *               </template>
 *
 *	Description : DNS query is called for the name %1, type %2, query options %3, Server List %4, isNetwork query %5, 
 *            network index %6, interface index %7, is asynchronous query %8
 */

Microsoft-Windows-DNS-Client:::events 
/arg0 == 3006/
{
	off = arg2;
	qname =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	off = (uint64_t) off + l;
	qtype = *((uint32_t *) off);
	off = off + 4;
	qopt = *((uint64_t *) off);
	off = off + 8;
	serverlist = wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2; 
	off = (uint64_t) off + l;
	isq = *((uint32_t *) off);
	off = off + 4;
	netqind = *((uint32_t *) off);
	off = off + 4;
	intind = *((uint32_t *) off);
	off = off + 4;
	isasyn = *((uint32_t *) off);
	off = off + 4;
	printf("DNS query is called for the name (%s), type (%d), query options (%d), Server List (%s), ",
		qname, qtype, qopt, serverlist);
	
	printf("isNetwork query (%d), network index (%d), interface index (%d), is asynchronous query (%d)\n",
		isq, netqind, intind, isasyn);

	exit(0);
}