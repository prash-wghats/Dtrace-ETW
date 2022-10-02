
REM will not work. fastcall calling convention ? ecx, edx, stack left to right ?
debug\i386\bin\dtrace32.exe -s tests\misc\t_cs_args.d -c debug\i386\obj\t_cs_str.exe
debug\i386\bin\dtrace32.exe -s tests\misc\t_c_args.d -c debug\i386\obj\t_c_args.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\fpid_ustack.d -c debug\i386\obj\t_c_win.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\fpid_functime.d -c debug\i386\obj\t_c_win.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\fpid_functime.d -c debug\i386\obj\t_cs_win.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\pid_ustack.d -c debug\i386\obj\t_c_win.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\fpid_ustack.d -c debug\i386\obj\t_cs_win.exe 
debug\i386\bin\dtrace32.exe -s dscripts\demo\pid_ustack.d -c debug\i386\obj\t_cs_win.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\fpid_args.d -c debug\i386\obj\t_c_args.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\pid_args.d -c debug\i386\obj\t_c_args.exe
mkdir data
del data\testfile.etl
debug\i386\bin\dtrace32.exe -s dscripts\demo\testdata.d -E data\testfile.etl 
debug\i386\bin\dtrace32.exe -s dscripts\demo\profile_syms.d
cd data
curl -LJO https://github.com/randomascii/bigfiles/raw/master/ETWTraces/2015-09-25_20-56-25%20VS%20F8%20short%20hang.zip
tar -xf "2015-09-25_20-56-25%20VS%20F8%20short%20hang.zip"
cd ..
debug\i386\bin\dtrace32.exe -s dscripts\demo\randomascii.d -E "data\2015-09-25_20-56-25 VS F8 short hang.etl"
debug\i386\bin\dtrace32.exe -s dscripts\demo\profile_syms.d -E data\testfile.etl
debug\i386\bin\dtrace32.exe -s dscripts\demo\dns.d
debug\i386\bin\dtrace32.exe -s dscripts\demo\pid_functime.d -c debug\i386\obj\t_c_sim.exe
debug\i386\bin\dtrace32.exe -s dscripts\demo\proc.d
debug\i386\bin\dtrace32.exe -s dscripts\demo\profile-resolution.d

debug\i386\bin\dtrace32.exe -s tests\misc\t_c_userctf.d -c debug\i386\obj\t_c_sim.exe
debug\i386\bin\dtrace32.exe -s tests\misc\t_c_userland.d -c debug\i386\obj\t_c_userland.exe

debug\i386\bin\dtrace32.exe -s dscripts\bin\diag.d -E "data\testfile.etl"
debug\i386\bin\dtrace32.exe -s dscripts\bin\sched.d -E "data\testfile.etl"
debug\i386\bin\dtrace32.exe -s dscripts\bin\whererun.d firefox.exe
debug\i386\bin\dtrace32.exe -s dscripts\bin\wakeup.d firefox.exe
debug\i386\bin\dtrace32.exe -s dscripts\bin\whererun.d firefox.exe -E "data\testfile.etl"
debug\i386\bin\dtrace32.exe -s dscripts\bin\wakeup.d firefox.exe -E "data\testfile.etl"
debug\i386\bin\dtrace32.exe -s dscripts\bin\ustacks_exe.d firefox.exe

debug\i386\bin\dtrace32.exe -s dscripts\demo\powershell.d