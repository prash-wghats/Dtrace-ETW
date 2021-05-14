/*
 * ETW event information can be extracted using powershell.
 * For example, to get information about Microsoft-Windows-PowerShell providers 
 * events, use the following command in powershell.
 * => Get-WinEvent -ListProvider *PowerShell).events
 *
 * following is an extract from the command about event no 7937
 *  Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
 *               <data name="ContextInfo" inType="win:UnicodeString" outType="xs:string"/>
 *               <data name="UserData" inType="win:UnicodeString" outType="xs:string"/>
 *               <data name="Payload" inType="win:UnicodeString" outType="xs:string"/>
 *             </template>
 * Description : %3
 *
 *            Context:
 *             %1
 *
 *            User Data:
 *             %2
 */
#pragma D option quiet
#pragma D option strsize=2048

microsoft-windows-powershell:::
/arg0 == 7937/
{
	off = arg2;
	cinfo =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	
	off = (uint64_t) off + l;
	udata =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	
	off = (uint64_t) off + l;
	pload =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	printf("Description: %s\n", pload);
	printf("\tContext:\n\t %s\n", cinfo);
	printf("\tUser Data\n\t %s\n", udata);
	exit(0);
}