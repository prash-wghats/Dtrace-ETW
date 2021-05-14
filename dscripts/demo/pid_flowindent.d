/*  debug\amd64\bin\dtrace.exe -s .\dscripts\demo\pid_flowindent.d  -c .\debug\amd64\obj\t_c_sim.exe -x flowindent */
#pragma D option flowindent

pid$target:a.out::entry,
pid$target:a.out::return
{
}