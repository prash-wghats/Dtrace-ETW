#pragma D option aggsize=8m
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m

uint64_t bri, brmis, on, off, i_br, i_brmiss, i_tc, i_inst, sbi, sbri, tc, ir, migrations, taskclc, stime, etime;
int cpumig[pid_t];
uint64_t regs[int];

/* 
 *.\debug\amd64\bin\dtrace.exe -qs .\dscripts\demo\perf.d  -c E:\temp\etl\noploop.exe -gE e:\noploop.etl "noploop.exe"
 *.\debug\amd64\bin\dtrace.exe -qs .\dscripts\demo\perf.d  -E e:\noploop.etl "noploop.exe"
 */

BEGIN {
	i_br = -1;
	i_brmiss = -1;
	i_tc = -1;
	i_inst = -1;
	stime = walltimestamp;
}

sched::pmc:on-cpu-branchmispredictions
/execname == $1/
{	
		self->curbrmis = arg4;
}

sched::pmc:on-cpu-branchinstructions
/execname == $1/
{	
		self->curbri = arg4;
}

sched::pmc:on-cpu-totalcycles
/execname == $1/
{	
		self->curtc = arg4;
		/*printf("on tid %d arg %d cpu %d pid %d \n", tid, arg4, cpu, pid);*/
}

sched::pmc:on-cpu-instructionretired
/execname == $1/
{	
		self->curir = arg4;
}

sched::pmc:off-cpu-branchmispredictions
/execname == $1/
{	
		brmis += arg4 - self->curbrmis;
		self->curbrmis = 0;
}

sched::pmc:off-cpu-branchinstructions
/execname == $1/
{	
		bri += arg4 - self->curbri;
		self->curbri = 0;
}

sched::pmc:off-cpu-totalcycles
/execname == $1/
{	
		tc += arg4 - self->curtc;
		self->curtc = 0;
}

sched::pmc:off-cpu-instructionretired
/execname == $1/
{	
		ir += arg4 - self->curir;
		self->curir = 0;
}

proc:::start
{
	printf("start %s\n", stringof(args[0]->pr_fname));
}

proc:::exit
{
	printf("exit %s\n", stringof(curpsinfo->pr_fname));
}

proc:::lwp-start
/args[0]->pr_lwpid == $target/
{
	printf("start th %s %d\n", stringof(args[1]->pr_fname), args[0]->pr_lwpid);
}

proc:::lwp-exit
/curlwpsinfo->pr_lwpid == $target/
{
	printf("end th %s %d\n", stringof(curpsinfo->pr_fname), curlwpsinfo->pr_lwpid);
}
pf:::
/execname == $1/
{
	pageflts++;
	
}

sched::pmc:on-cpu
/execname == $1 && stime == 0/
{	
	stime = timestamp;
}

sched::event:on-cpu
/execname == $1/
{
	on++;
}
sched::pmc:on-cpu
/execname == $1/
{	
	rg = (uint64_t *) (arg4 + 8);
	co = (*(uint32_t *) (arg4 + 4)) / 8;
	self->reg0 = co > 0 ? rg[0] : 0;
	self->reg1 = co > 1 ? rg[1] : 0;
	self->reg2 = co > 2 ? rg[2] : 0;
	self->reg3 = co > 3 ? rg[3] : 0;

	co_sched++;
	migrations += cpumig[tid] == cpu ? 0 : 1;	
	self->oncputime = timestamp;
}

sched::pmc:off-cpu
/execname == $1/
{
	rg = (uint64_t *) (arg4 + 8);
	co = (*(uint32_t *) (arg4 + 4)) / 8;
	regs[0] += self->reg0 ? rg[0] - self->reg0 : 0;
	regs[1] += self->reg1 ? rg[1] - self->reg1 : 0;
	regs[2] += self->reg2 ? rg[2] - self->reg2 : 0;
	regs[3] += self->reg3 ? rg[3] - self->reg3 : 0;
	fail = rg[0] < self->reg0 ? 1 : 0;
	tmp = rg[0];
	
	self->reg0 = 0;
	self->reg1 = 0;
	self->reg2 = 0;
	self->reg3 = 0;

	cpumig[tid] = cpu;
	taskclc += self->oncputime > 0 ? timestamp - self->oncputime : 0;
	self->oncputime = 0;
	etime = timestamp;
}
sched::pmc:off-cpu
/fail/
{	
	printf("reg %d %d", tmp, self->reg0);
	exit(0);

}
pmc:::counter-src
/arg0 >= 1/
{
	str = wstringof(((wchar_t **)arg1)[0]);
	i_br = str == "branchinstructions" ? 0 : i_br;
	i_brmiss = str == "branchmispredictions" ? 0 : i_brmiss;
	i_tc = str == "totalcycles" ? 0 : i_tc;
	i_inst = str == "instructionretired" ? 0 : i_inst;
}

pmc:::counter-src
/arg0 >= 2/
{
	str = wstringof(((wchar_t **)arg1)[1]);
	i_br = str == "branchinstructions" ? 1 : i_br;
	i_brmiss = str == "branchmispredictions" ? 1 : i_brmiss;
	i_tc = str == "totalcycles" ? 1 : i_tc;
	i_inst = str == "instructionretired" ? 1 : i_inst;
}

pmc:::counter-src
/arg0 >= 3/
{
	str = wstringof(((wchar_t **)arg1)[2]);
	i_br = str == "branchinstructions" ? 2 : i_br;
	i_brmiss = str == "branchmispredictions" ? 2 : i_brmiss;
	i_tc = str == "totalcycles" ? 2 : i_tc;
	i_inst = str == "instructionretired" ? 2 : i_inst;
}

pmc:::counter-src
/arg0 >= 4/
{
	str = wstringof(((wchar_t **)arg1)[3]);
	i_br = str == "branchinstructions" ? 3 : i_br;
	i_brmiss = str == "branchmispredictions" ? 3 : i_brmiss;
	i_tc = str == "totalcycles" ? 3 : i_tc;
	i_inst = str == "instructionretired" ? 3 : i_inst;
}

END {
	cxtsws = co_sched;
	taskclc = taskclc / 1000000;

	cycles = tc;
	instructions = ir;
	branches = bri;
	branch_misses = brmis;
	cycles = cycles == 0 && i_tc >= 0 ? regs[i_tc] : cycles;
	branches = branches == 0 && i_br >= 0 ? regs[i_br] : branches;
	branch_misses = branch_misses == 0 && i_brmiss >= 0 ? regs[i_brmiss] : branch_misses;
	instructions = instructions == 0 && i_inst >= 0 ? regs[i_inst] : instructions;

	percen_cs = cxtsws * 1000 / taskclc;
	cs_str = percen_cs > 1000 ? "" : (percen_cs > 100 ? "0." : (percen_cs > 10 ? "0.0" :
		(percen_cs > 1 ? "0.00" : "0.000") ) );
	percen_cs = percen_cs > 1000 ? percen_cs / 1000 : (percen_cs > 100 ? percen_cs / 100 :
		(percen_cs > 10 ? percen_cs / 10 : (percen_cs > 1 ? percen_cs : 0)));

	printf("\n%20d		%-20s	#	\n", taskclc, "task-clock (msec)");
	printf("%20d		%-20s	#	%s%d K/sec\n", cxtsws, "context-switches", cs_str, percen_cs);
	
	percen_cs = migrations * 1000 / taskclc;
	cs_str = percen_cs > 1000 ? "" : (percen_cs > 100 ? "0." : (percen_cs > 10 ? "0.0" :
		(percen_cs > 1 ? "0.00" : "0.000")));
	percen_cs = percen_cs > 1000 ? percen_cs / 1000 : (percen_cs > 100 ? percen_cs / 100 :
		(percen_cs > 10 ? percen_cs / 10 : (percen_cs > 1 ? percen_cs : 0)));
	printf("%20d		%-20s	#	%s%d K/sec\n", migrations, "cpu-migrations", cs_str, percen_cs);

	percen_cs = pageflts * 1000 / taskclc;
	cs_str = percen_cs > 1000 ? "" : (percen_cs > 100 ? "0." : (percen_cs > 10 ? "0.0" :
		(percen_cs > 1 ? "0.00" : "0.000")));
	percen_cs = percen_cs > 1000 ? percen_cs / 1000 : (percen_cs > 100 ? percen_cs / 100 :
		(percen_cs > 10 ? percen_cs / 10 : (percen_cs > 1 ? percen_cs : 0)));
	printf("%20d		%-20s	#	%s%d K/sec\n", pageflts, "page-faults", cs_str, percen_cs);
}

END 
/cycles == 0/
{
	printf("%20s		%-20s\n", "<not configured>", "cycles");
}

END 
/cycles > 0/
{
	percen_cs = cycles / (taskclc * 1000);
	cs_str = percen_cs > 1000 ? "" : (percen_cs > 100 ? "0." : (percen_cs > 10 ? "0.0" :
		(percen_cs > 1 ? "0.00" : "0.000")));
	percen_cs = percen_cs > 1000 ? percen_cs / 1000 : (percen_cs > 100 ? percen_cs / 100 :
		(percen_cs > 10 ? percen_cs / 10 : (percen_cs > 1 ? percen_cs : 0)));

	printf("%20d		%-20s	#	%d.%d GHz\n", cycles, "cycles", percen_cs, (cycles % (taskclc * 1000))/1000);
}

END
/instructions == 0/
{
	printf("%20s		%-20s\n", "<not configured>", "instructions");
}
END
/instructions > 0 && cycles > 0/
{
	percen = instructions / cycles;
	percen_cs = (instructions % cycles) / 1000;
	cs_str = percen_cs > 1000 ? "." : (percen_cs > 100 ? ".0" : (percen_cs > 10 ? ".00" : ".000"));
	percen_cs = percen_cs > 1000 ? percen_cs / 1000 : (percen_cs > 100 ? percen_cs / 100 :
		(percen_cs > 10 ? percen_cs / 10 : 0));
	printf("%20d		%-20s	#	%d%s%d insns per cycle\n", instructions, "instructions", percen , cs_str, percen_cs);
}

END
/instructions > 0 && cycles == 0/
{
	printf("%20d		%-20s\n", instructions, "instructions");
}

END
/branches == 0/
{
	printf("%20s		%-20s\n", "<not configured>", "branches");
}

END
/branches > 0/
{
	percen = branches / taskclc;
	percen_cs = (branches % (taskclc)) / 1000;
	cs_str = percen_cs > 1000 ? "." : (percen_cs > 100 ? ".0" : (percen_cs > 10 ? ".00" : ".000"));
	percen_cs = percen_cs > 1000 ? percen_cs / 1000 : (percen_cs > 100 ? percen_cs / 100 :
		(percen_cs > 10 ? percen_cs / 10 : 0));
	printf("%20d		%-20s	#	%d%s%d M/sec\n", branches, "branches", percen/1000,cs_str, percen_cs);
}

END
/branch_misses == 0/
{
	printf("%20s		%-20s\n", "<not configured>", "branch_misses");
}

END
/branch_misses > 0/
{
	percen = branch_misses * 10000 / branches;
	percen_cs = percen;

	percen_cs = percen > 1000 ? percen % 1000 : (percen > 100 ? percen % 100 : percen % 10);
	cs_str = percen > 1000 ? "." : (percen > 100 ? "." : ".0");
	printf("%20d		%-20s	#	%d%s%d%% of all branches\n", branch_misses, "branch-misses", percen/100, cs_str, percen_cs);
}

 /*
 # perf stat ./noploop
^C./noploop: Interrupt

 Performance counter stats for './noploop':

       2418.149339      task-clock (msec)         #    1.000 CPUs utilized          
                 3      context-switches          #    0.001 K/sec                  
                 0      cpu-migrations            #    0.000 K/sec                  
                39      page-faults               #    0.016 K/sec                  
     6,245,387,593      cycles                    #    2.583 GHz                      (75.03%)
   <not supported>      stalled-cycles-frontend  
   <not supported>      stalled-cycles-backend   
    24,766,697,057      instructions              #    3.97  insns per cycle          (75.02%)
        14,738,991      branches                  #    6.095 M/sec                    (75.02%)
            24,744      branch-misses             #    0.17% of all branches          (75.04%)

       2.418826663 seconds time elapsed
*/

/*
TotalIssues
 8092        pmc                                                     branchinstructions
 8093        pmc                                                     cachemisses
 8094        pmc                                                     branchmispredictions
 8095        pmc                                                     totalcycles
 8096        pmc                                                     UnhaltedCoreCycles
 8097        pmc                                                     instructionretired
 8098        pmc                                                     UnhaltedReferenceCycles
 8099        pmc                                                     LLCReference (Last Level Cache)
 8100        pmc                                                     LLCMisses
 8101        pmc                                                     Branchinstructionretired
 8102        pmc                                                     BranchMispredictsRetired
 8103        pmc                                                     LbrInserts (Last Branch Record)
 */