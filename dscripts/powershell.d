/* 7937
   Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                <data name="ContextInfo" inType="win:UnicodeString" outType="xs:string"/>
                <data name="UserData" inType="win:UnicodeString" outType="xs:string"/>
                <data name="Payload" inType="win:UnicodeString" outType="xs:string"/>
              </template>
 */
#pragma D option strsize=2048

Microsoft-Windows-PowerShell:::
/arg0 == 7937/
{
	off = arg2;
	cinfo =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	printf("%d\n%s\n", l, cinfo);
	off = (uint64_t) off + l;
	udata =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	printf("%d\n%s\n", l, udata);
	off = (uint64_t) off + l;
	pload =  wstringof((wchar_t *) off);
	l = (wstrlen((wchar_t *) off)+1)*2;
	printf("%d\n%s\n", l, pload);

}