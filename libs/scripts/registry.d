
/*#pragma D depends_on provider reg*/

typedef struct registry {
	int r_index;			/* The subkey index for the registry operation (such as EnumerateKey) */
	int r_status;			/* NTSTATUS value of the registry operation. */
	int64_t r_intime;		/* Initial time of the registry operation. */
	string r_rname;			/* Name of the registry key. */
} registry_t;

#pragma D binding "1.0" translator
translator registry_t < struct reginfo *R > {
	r_index = R->r_index;
	r_status = R->r_status;
	r_intime = R->r_time;
	r_rname = wstringof(R->r_name);
};