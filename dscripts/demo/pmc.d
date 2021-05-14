
typedef struct etwext {
	uint32_t type;
	uint32_t size;
	char data[1];
} etwext_t;

typedef struct etw_pmcregs {
    uint32_t pmc_count;
    uint64_t *pmc_regs;
} etw_pmcregs_t;

translator etw_pmcregs_t < etwext_t *P > {
    pmc_count = P->size / sizeof(uint64_t);
	pmc_regs = (uint64_t *) P->data;
};

/* Limit to the counter enabled. testing pc 7 (sample + counter) */
int bmp_i, cm_i, bir_i, bmp, ucc, tc, ir, sc, s_ucc, s_ir, s_bir, s_bi, ir, i_bir, i_bi, sr, cm;

/* Sampling - PMC with Intervals */
pmc:::branchmispredictions
{
	bmp++;
}

pmc:::cachemisses
{
	cm++;
}

pmc:::unhaltedcorecycles
{
	ucc++;
}

pmc:::totalcycles
{
	tc++;
}

/* Counters - Events with PMC */
sched::pmc:off-cpu-instructionretired
{
		s_ir++;
}

sched::pmc:off-cpu-branchinstructions
{
		s_bi++;
}

sched::pmc:off-cpu-branchinstructionretired
{
		s_bir++;
}

isr::pmc:isr
/arg4/
{
	this->pmc = xlate <etw_pmcregs_t> ((etwext_t *) arg4);
	@[this->pmc.pmc_count] = count();
}

isr::pmc:isr-branchinstructions
{	
		i_bi++;
}

isr::pmc:isr-branchinstructionretired
{
		i_bir++;
}

isr::pmc:isr-instructionretired
{
		i_ir++;
}


pmc:::sample-src
{
	printf("sample src id %d new %d old %d name %s\n", arg0, arg2, arg3, stringof(arg1));
}
pmc:::counter-src
/args[0] >= 1/
{
	printf("counters:	%s", wstringof(args[1][0]));
}
pmc:::counter-src
/args[0] >= 2/
{
	printf("\t\t%s\n", wstringof(args[1][1]));
}
pmc:::counter-src
/args[0] >= 3/
{
	printf("\t\t%s\n", wstringof(args[1][2]));
}
pmc:::counter-src
/args[0] >= 4/
{
	printf("\t\t%s\n", wstringof(args[1][3]));
}

END {
	printf("\t\t\t\t\t\tPMC\n");
	printf("%50s		(%d)\n", "branchmispredictions", bmp);
	printf("%50s		(%d)\n", "unhaltedcorecycles", ucc);
	printf("%50s		(%d)\n", "totalcycles", tc);
	printf("%50s		(%d)\n", "cachemisses", cm);

	printf("\t\t\t\t\t\tPMC in Events\n");
	printf("%50s		(%d)\n", "off-cpu", sc);
	printf("%50s		(%d)\n", "off-cpu-unhaltedcorecycles", s_ucc);
	printf("%50s		(%d)\n", "off-cpu-instructionretired", s_ir);
	printf("%50s		(%d)\n", "off-cpu-branchinstructionretired", s_bir);
	printf("%50s		(%d)\n", "off-cpu-branchinstructions", s_bi);
	printf("%50s		(%d)\n", "isr", sr);
	printf("%50s		(%d)\n", "isr-branchinstructionretired", i_bir);
	printf("%50s		(%d)\n", "isr-branchinstructions", i_bi);
	printf("%50s		(%d)\n", "isr-instructionretired", i_ir);
}

/*
TotalIssues
 8092        pmc                                                     branchinstructions
 8093        pmc                                                     cachemisses
 8094        pmc                                                     branchmispredictions
 8095        pmc                                                     totalcycles
 8096        pmc                                                     unhaltedcorecycles
 8097        pmc                                                     instructionretired
 8098        pmc                                                     UnhaltedReferenceCycles
 8099        pmc                                                     LLCReference
 8100        pmc                                                     LLCMisses
 8101        pmc                                                     branchinstructionretired
 8102        pmc                                                     BranchMispredictsRetired
 8103        pmc                                                     LbrInserts
 */