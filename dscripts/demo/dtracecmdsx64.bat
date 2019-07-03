debug\amd64\bin\dtrace.exe -s dscripts\demo\c#args64.d -c debug\amd64\obj\t_cs_str.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_args.d -c debug\amd64\obj\t_c_args.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_fustack.d -c debug\amd64\obj\t_c_win.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_ustack.d -c debug\amd64\obj\t_c_win.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_fustack.d -c debug\amd64\obj\t_cs_win.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_ustack.d -c debug\amd64\obj\t_cs_win.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_args.d -c debug\i386\obj\t_c_args.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_fustack.d -c debug\i386\obj\t_c_win.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_ustack.d -c debug\i386\obj\t_c_win.exe
#debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_fustack.d -p 12604
#debug\amd64\bin\dtrace.exe -s dscripts\demo\ft_ustack.d -p 12604
debug\amd64\bin\dtrace.exe -s dscripts\demo\prof_modsym.d
debug\amd64\bin\dtrace.exe -s dscripts\demo\prof_modsym.d -E "data\2015-09-25_20-56-25 VS F8 short hang.etl"
debug\amd64\bin\dtrace.exe -s dscripts\demo\prof_modsym.d -E data\PerfViewData.etl
debug\amd64\bin\dtrace.exe -s dscripts\demo\prof_modsym.d -E data\PerfViewData.etl
debug\amd64\bin\dtrace.exe -s dscripts\demo\dns.d
debug\amd64\bin\dtrace.exe -s dscripts\demo\func_time.d -c debug\amd64\obj\t_c_sim.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\powershell.d
debug\amd64\bin\dtrace.exe -s dscripts\demo\UIdelay.d
debug\amd64\bin\dtrace.exe -s dscripts\demo\UIdelay.d -E "data\2015-09-25_20-56-25 VS F8 short hang.etl"
debug\amd64\bin\dtrace.exe -s dscripts\demo\proc.d
debug\amd64\bin\dtrace.exe -s dscripts\demo\prof.d
debug\amd64\bin\dtrace.exe -32 -s dscripts\demo\userctf.d -c debug\i386\obj\t_c_sim.exe
debug\amd64\bin\dtrace.exe -s dscripts\demo\userctf.d -c debug\amd64\obj\t_c_sim.exe
debug\amd64\bin\dtrace.exe -s tests\misc\t_c_userland.d -c debug\amd64\obj\t_c_userland.exe

debug\amd64\bin\dtrace.exe -s dscripts\bin\ustack.d firefox.exe
debug\amd64\bin\dtrace.exe -s dscripts\bin\diag.d -E "data\PerfViewDataDN.etl"
debug\amd64\bin\dtrace.exe -s dscripts\bin\diag.d
debug\amd64\bin\dtrace.exe -s dscripts\bin\whererun.d firefox.exe
debug\amd64\bin\dtrace.exe -s dscripts\bin\wakeup.d firefox.exe
debug\amd64\bin\dtrace.exe -s dscripts\bin\whererun.d firefox.exe -E "data\PerfViewData.etl"
debug\amd64\bin\dtrace.exe -s dscripts\bin\wakeup.d firefox.exe -E "data\PerfViewData.etl"
c:\msys\1.0\bin\sh.exe dscripts\bin\iosnoop