 #pragma D option quiet

/* .\debug\amd64\bin\dtrace -x aggsortkey=0 -x aggpack -x aggzoom -s .\dscripts\demo\gpuview.d \"firefox.exe\" */

/* Device Queue */
/*submit*/
typedef struct dxgkrnl_178_v1 {
	uint64_t pcontext;
	uint32_t pkttype;	/*0 - gpu, 7 - present token */
	uint32_t subseq;
	uint64_t dmabufsz;
	uint32_t alloclstsz;
	uint32_t patloclstsz;
	uint32_t bprst;		/* true == 0 - gpu, present */
	uint32_t dmabuf[2];
	uint32_t qpkt[2];
	uint32_t prgfnval[2];
} dxgkrnl_178_v1_t;
/*complete*/
typedef struct dxgkrnl_180_v1 {
	uintptr_t pcontext;
	uint32_t pkttype;	/*0 - gpu */
	uint32_t subseq;
	uint32_t bpreempt;
	uint32_t btmout;
	uintptr_t qpkt;
} dxgkrnl_180_v1_t;

/*GPU Queue*/
/*complete by dpc */
typedef struct dxgkrnl_176_v1 {
	uint64_t pcontext;
	uint32_t pkttype;
	uint32_t cmplid0;
	uint32_t cmplid1;
	uint32_t qsubseq;
	uint32_t bpreempt;
} dxgkrnl_176_v1_t;

uint64_t stm,lastblktime, cputime;
inline int FPSMS = 17;
inline uint64_t MILLSEC = 1000000;

inline int AXISMS = 1000;
BEGIN {
	ptime = 0;
	stm = 0;
	curi = 0;
	aggi = 0;
	gpuqcount = 0;
	gpuqstart = 0;
	gpuqtime = 0;
	lastblktime = 0;
	c178 = 0;
	c180 = 0;
	cputime = 0;
	starttm = timestamp;
}


sched:::on-cpu
/execname == $1/
{
	cpusttime = timestamp - starttm;
}

sched:::off-cpu
/execname == $1/
{
	cputime += (timestamp - starttm) - cpusttime;
	cpusttime = 0;
}
microsoft-windows-dxgkrnl:::base
/arg0 == 178 && execname == $1/
{
	dxg178 = (dxgkrnl_178_v1_t *) arg2;
	prstpkt[dxg178->subseq] = dxg178->bprst;
	curtime = (timestamp - starttm) / MILLSEC;
	gpuqstart = gpuqcount == 0 ? curtime : gpuqstart;
	gpuqcountq[dxg178->subseq] = 1;
	gpuqcount++;
	c178 += 1;
}

microsoft-windows-dxgkrnl:::base
/arg0 == 180 && gpuqcountq[(dxg180 = (dxgkrnl_180_v1_t *) arg2)->subseq]/
{
	gpuqcountq[dxg180->subseq] = 0;
	gpuqcount--;
	curtime = (timestamp - starttm) / MILLSEC;
	gpuqtime += gpuqcount == 0 ? curtime - gpuqstart : 0;

	gpuqstart = gpuqcount == 0 ? 0 : gpuqstart;
	c180 += 1;
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq]/
{
	dxg176 = (dxgkrnl_176_v1_t *) arg2;
	curtime = (timestamp - starttm) / MILLSEC;

	clr = curtime - lastblktime >= AXISMS ? 1 : 0;
	tlastblktime = lastblktime;
	lastblktime = clr == 1 ? curtime : lastblktime;
	secco = curtime / AXISMS;
	tm = (curtime - ptime);
	fpsm = (tm / FPSMS) + 1 ;
	msgm = (gpuqtime / FPSMS);

	cputime += cpusttime == 0 ? 0 : ((timestamp - starttm) - cpusttime);
	cpusttime = cpusttime == 0 ? 0 : (timestamp - starttm);

	cpum = (cputime / (MILLSEC * FPSMS)) + 1;
	
	gpuqcount = 0;
	gpuqtime = 0;
	cputime = 0;
	tptime = ptime;
	ptime = curtime;
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && fpsm/
{	
	c = secco * AXISMS;
	@fps[c] = lquantize(tptime - c, 0, AXISMS, FPSMS);
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm > 5/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm--, 0, AXISMS, FPSMS);
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm == 5/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm == 4/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm == 3/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm == 2/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm == 1/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && msgm == 0/
{
	c = secco * AXISMS;
	@msg[c] = lquantize((tptime - c) + FPSMS * msgm, 0, AXISMS, FPSMS);
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum > 5/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum--, 0, AXISMS, FPSMS);
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum == 5/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum == 4/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum == 3/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum == 2/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum == 1/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum--, 0, AXISMS, FPSMS);
}
microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && cpum == 0/
{
	c = secco * AXISMS;
	@cpua[c] = lquantize((tptime - c) + FPSMS * cpum, 0, AXISMS, FPSMS);
}

microsoft-windows-dxgkrnl:::base
/arg0 == 176 && prstpkt[((dxgkrnl_176_v1_t *) arg2)->qsubseq] && clr == 1/
{
	clr = 0;
	secco++;
}
                   
microsoft-windows-dxgkrnl:::profiler,                     
microsoft-windows-dxgkrnl:::references,                   
microsoft-windows-dxgkrnl:::forcevsync,                   
microsoft-windows-dxgkrnl:::patch,                       
microsoft-windows-dxgkrnl:::cdd,                         
microsoft-windows-dxgkrnl:::resource,                     
microsoft-windows-dxgkrnl:::memory,                       
microsoft-windows-dxgkrnl:::dxgkrnl_statuschangenotify,   
microsoft-windows-dxgkrnl:::dxgkrnl_power,                
microsoft-windows-dxgkrnl:::driverevents,                 
microsoft-windows-dxgkrnl:::longhaul,                     
microsoft-windows-dxgkrnl:::stablepower,                  
microsoft-windows-dxgkrnl:::defaultoverride,              
microsoft-windows-dxgkrnl:::historybuffer,                
microsoft-windows-dxgkrnl:::gpuscheduler
{
}


END {
	printf("Count c178 %d  c180 %d\n", c178, c180);
}