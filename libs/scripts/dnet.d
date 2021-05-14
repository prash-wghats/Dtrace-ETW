/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
inline int NET_GC_SMALL_OBJ_HEAP_ALLOC = 0x0;	/* Small object heap allocation. */
#pragma D binding "1.0" NET_GC_SMALL_OBJ_HEAP_ALLOC
inline int NET_GC_INDUCED = 0x1;
#pragma D binding "1.0" NET_GC_INDUCED
inline int NET_GC_LOW_MEMORY = 0x2;
#pragma D binding "1.0" NET_GC_LOW_MEMORY
inline int NET_GC_LARGE_OBJ_HEAP_ALLOC = 0x4;	/* Large object heap allocation. */
#pragma D binding "1.0" NET_GC_LARGE_OBJ_HEAP_ALLOC
inline int NET_GC_OOS_SMALL = 0x5;	/* Out of space (for small object heap) */
#pragma D binding "1.0" NET_GC_OOS_SMALL
inline int NET_GC_OOS_LARGE = 0x6;	/* Out of space (for large object heap) */
#pragma D binding "1.0" NET_GC_OOS_LARGE
inline int NET_GC_INDUCED_NFBLK = 0x7;	/* Induced but not forced as blocking. */
#pragma D binding "1.0" NET_GC_INDUCED_NFBLK

inline int NET_GC_TYPE_BLKING_O =
    0x0;	/* Blocking garbage collection occurred outside background garbage collection */
#pragma D binding "1.0" NET_GC_TYPE_BLKING_O
inline int NET_GC_TYPE_BG = 0x1;	/* Background garbage collection */
#pragma D binding "1.0" NET_GC_TYPE_BG
inline int NET_GC_TYPE_BLKING_D =
    0x2;	/* Blocking garbage collection occurred during background garbage collection */
#pragma D binding "1.0" NET_GC_TYPE_BLKING_D

inline int NET_GC_ALLOC_SMALL_OBJ = 0x0;	/* Small object heap allocation. */
#pragma D binding "1.0" NET_GC_ALLOC_SMALL_OBJ
inline int NET_GC_ALLOC_LARGE_OBJ = 0x1;	/* Large object heap allocation. */
#pragma D binding "1.0" NET_GC_ALLOC_LARGE_OBJ
inline int NET_GC_ALLOC_RD_ONLY = 0x3;	/* Read-only heap. */
#pragma D binding "1.0" NET_GC_ALLOC_RD_ONLY

inline int NET_GC_NATIVE_THR = 0x1;	/* native thread. */
#pragma D binding "1.0" NET_GC_NATIVE_THR
inline int NET_GC_MANG_THR = 0x0;	/* managed thread. */
#pragma D binding "1.0" NET_GC_MANG_THR

typedef struct netthrinfo {
    uint64_t clr_thrco;
    uint64_t clr_retireco;
    uint16_t clr_instid;
} netthrinfo_t;

#pragma D binding "1.0" translator
translator netthrinfo_t < char *p > {
    clr_thrco = *(uint32_t *) p;
    clr_retireco = *(uint32_t *) (p+4);
    clr_instid = *(uint16_t *) (p+8);
};

#pragma D binding "1.0" translator
translator netthrinfo_t < intptr_t p > {
    clr_thrco = *(uint32_t *) p;
    clr_retireco = *(uint32_t *) (p+4);
    clr_instid = *(uint16_t *) (p+8);
};

typedef struct netthr {
    uint64_t clr_thrid;
    uint64_t clr_appdmid;
    uint32_t clr_flgs;
    uint32_t clr_mngthrindex, clr_osthrid;
    uint16_t clr_instid;
} netthr_t;

#pragma D binding "1.0" translator
translator netthr_t < char *p > {
    clr_thrid = *(uint64_t *) p;
    clr_appdmid = *(uint64_t *) (p+8);
    clr_flgs = *(uint32_t *) (p+16);
    clr_mngthrindex = *(uint32_t *) (p+20);
    clr_osthrid = *(uint32_t *) (p+24);
    clr_instid = *(uint16_t *) (p+28);
};

typedef struct netlck {
    uint8_t lck_flags;
    uint16_t clr_instid;
} netlck_t;

#pragma D binding "1.0" translator
translator netlck_t < char *p > {
    lck_flags = *(uint8_t *) p;
    clr_instid = *(uint16_t *) (p+1);
};

typedef struct netgc {
    uint16_t clr_instid;
    uint32_t gc_count, gc_depth, gc_reason, gc_type;
    uint64_t gc_addr, gc_size;
} netgc_t;

#pragma D binding "1.0" translator
translator netgc_t < char *p > {
    clr_instid = *(uint16_t *) (p+(self->nettmp = *(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID), self->nettmp == 1 ? 16 : (self->nettmp == 9 ? 8 : 4)));
    gc_count = *(uint32_t *) (p + (*(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID) == 9 ? 4 : 0));
    gc_depth = *(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID) == 1 ? *(uint32_t *) (p+4) : 0;
    gc_reason = (self->nettmp = *(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID), self->nettmp == 13 ? 0 : (
        self->nettmp == 1 ? *(uint32_t *) (p + 8) : *(uint16_t *) (p)
        ));
    gc_type = *(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID) == 1 ? *(uint32_t *) (p+12) : 0;
};


typedef struct netgcseg {
    uint64_t gc_addr, gc_size;
    uint32_t gc_type;
    uint16_t clr_instid;
} netgcseg_t;

#pragma D binding "1.0" translator
translator netgcseg_t < char *p > {
    gc_addr = *(uint64_t *) (p);
    gc_size = *(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID) == 5 ? *(uint64_t *) (p+8) : 0;
    gc_type = *(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID) == 5 ? *(uint32_t *) (p+16) : 0;
    clr_instid = *(uint16_t *) (p+(*(uint8_t *) (p-SDT_MSGHDRLOC_SHORT_ID) == 5 ? 20 : 8));
};


typedef struct netgcalloctick {
    uint32_t gc_amt, gc_kind;
    uint16_t clr_instid;
    uint64_t gc_amt64;
    uint64_t gc_typeid;
    string gc_typename;
    uint32_t gc_heapindex;
    uint64_t gc_addr;
} netgcalloctick_t;

#pragma D binding "1.0" translator
translator netgcalloctick_t < char *p > {
    gc_amt = *(uint32_t *) (p);
    gc_kind = *(uint32_t *) (p+4);
    clr_instid = *(uint16_t *) (p+8);
    gc_amt64 = *(uint64_t *) (p+10);
    gc_typeid = *(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_ARCH) == 1 ? *(uint64_t *) (p+18) : *(uint32_t *) (p+18);
    gc_typename = wstringof((wchar_t *) (p+22+(*(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_ARCH))*4));
    gc_heapindex = *(uint32_t *) (p+24+(*(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_ARCH))*4+wstrlen((wchar_t *) (p+22+(*(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_ARCH))*4))*2);
    gc_addr = *(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_VERSION) <= 3 ? 0 : ((self->nettmp = *(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_ARCH)) ?
        *(uint64_t *) (p+wstrlen((wchar_t *) (p+26))*2+32) : *(uint32_t *) (p+wstrlen((wchar_t *) (p+22))*2+28)
    );
};

typedef struct netgcheapstat {
    uint64_t gc_gensz0, gc_totpromsize0, gc_gensz1, gc_totpromsize1, gc_gensz2,
             gc_totpromsize2, gc_gensz3, gc_totpromsize3,
             gc_finpromsz, gc_finpromcount;
    uint32_t gc_pinnedobjco, gc_sinkblkcount, gc_gchandcount;
    uint16_t clr_instid;
    uint64_t gc_gensz4, gc_totpromsize4;
} netgcheapstat_t;

#pragma D binding "1.0" translator
translator netgcheapstat_t < char *p > {
    gc_gensz0 = *(uint64_t *) (p);
    gc_totpromsize0 = *(uint64_t *) (p+8);
    gc_gensz1 = *(uint64_t *) (p+16);
    gc_totpromsize1 = *(uint64_t *) (p+24);
    gc_gensz2 = *(uint64_t *) (p+32);
    gc_totpromsize2 = *(uint64_t *) (p+40);
    gc_gensz3 = *(uint64_t *) (p+48);
    gc_totpromsize3 = *(uint64_t *) (p+56);
    gc_finpromsz = *(uint64_t *) (p+64);
    gc_finpromcount = *(uint64_t *) (p+72);

    gc_pinnedobjco = *(uint32_t *) (p+80);
    gc_sinkblkcount = *(uint32_t *) (p+84);
    gc_gchandcount = *(uint32_t *) (p+88);
    clr_instid = *(uint16_t *) (p+92);
    gc_gensz4 = *(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_VERSION) == 2 ? *(uint64_t *) (p+94) : 0;
    gc_totpromsize4 = *(uint8_t *) (p-SDT_MSGHDRLOC_CHAR_VERSION) == 2 ? *(uint64_t *) (p+102) : 0;

};


typedef struct netrt {
    uint16_t clr_instid;
    uint16_t clr_sku;
    uint16_t clr_msmaj,clr_msmin,clr_msbld,clr_msfix;
    uint16_t clr_clrmaj,clr_clrmin,clr_clrbld,clr_clrfix;
    uint32_t clr_startflags;
    uint8_t clr_startmode;
    string clr_cmdline;
    guid_t clr_guid;
    string clr_clrpath;
} netrt_t;

#pragma D binding "1.0" translator
translator netrt_t < char *p > {
    clr_instid = *(uint16_t *) p;
    clr_sku = *(uint16_t *) (p+2);
    clr_msmaj = *(uint16_t *) (p+4);
    clr_msmin = *(uint16_t *) (p+6);
    clr_msbld = *(uint16_t *) (p+8);
    clr_msfix = *(uint16_t *) (p+10);
    clr_clrmaj = *(uint16_t *) (p+12);
    clr_clrmin = *(uint16_t *) (p+14);
    clr_clrbld = *(uint16_t *) (p+16);
    clr_clrfix = *(uint16_t *) (p+18);
    clr_startflags = *(uint32_t *) (p+20);
    clr_startmode = *(uint8_t *) (p+24);
    clr_cmdline = wstringof((wchar_t *) (p+25));
    clr_guid = *(guid_t *) (p+26+wstrlen((wchar_t *) (p+25))*2);
    clr_clrpath = wstringof((wchar_t *) (p+43+wstrlen((wchar_t *) (p+25))*2));
};

typedef struct netexcp {
    string clr_excep, clr_excepmsg;
    char *dummy;
    intptr_t clr_ip;
    uint32_t clr_res;
    uint16_t clr_flags;
    uint16_t clr_instid;

} netexcp_t;

#pragma D binding "1.0" translator
translator netexcp_t < char *p > {
    clr_excep = wstringof((wchar_t *) p);
    clr_excepmsg = wstringof((wchar_t *) (p + 2 + wstrlen((wchar_t *) p) * 2));
    dummy = (dummy = p + 2 + wstrlen((wchar_t *) p) * 2, dummy = dummy + 2 + wstrlen((wchar_t *) dummy) * 2);
    clr_ip = *(intptr_t *) (dummy);
    clr_res = *(uint32_t *) (dummy + sizeof(intptr_t));
    clr_flags = *(uint16_t *) (dummy + sizeof(intptr_t) + 4);
    clr_instid = *(uint16_t *) (dummy + sizeof(intptr_t) + 4 + 2);
};

typedef struct netirop {
    uint16_t clr_modid;
    uint64_t clr_stubid, clr_stubflags;
    uint32_t clr_mngitoken;
    string clr_mim_namespace, clr_mim_name, clr_mim_sig, clr_nm_sig, clr_stub_sig,
           clr_stub_code;
    uint16_t clr_instid;
} netirop_t;

#pragma D binding "1.0" translator
translator netirop_t < char *p > {
    clr_modid = *(uint16_t *) p;
    clr_stubid = *(uint64_t *) (p+2);
    clr_stubflags = *(uint64_t *) (p+10);
    clr_mngitoken = *(uint32_t *) (p+22);
    clr_mim_namespace = wstringof((wchar_t *) (p+26));
    clr_mim_name = wstringof((wchar_t *) (
        p+28+wstrlen((wchar_t *) (p+26))*2
        )
    );
    clr_mim_sig = wstringof((wchar_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+26))*2 + 28, self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        ));
    clr_nm_sig = wstringof((wchar_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+26))*2 + 28,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
        ));

    clr_stub_sig = wstringof((wchar_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+26))*2 + 28,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
        )
        ));
    clr_stub_code =  wstringof((wchar_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+26))*2 + 28,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
        )
        )
        ));
    clr_instid =  *(uint16_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+26))*2 + 28,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        (self->nettmp = self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
        )
        )
        )
    );
};

typedef struct netappdom {
    uint64_t clr_appdomid;
    uint32_t clr_appdomflgs;
    string clr_appdomname;
    uint32_t clr_appdomindex;
    uint16_t clr_instid;
} netappdom_t;

#pragma D binding "1.0" translator
translator netappdom_t < char *p > {
    clr_appdomid = *(uint64_t *) p;
    clr_appdomflgs = *(uint32_t *) (p+8);
    clr_appdomname = wstringof((wchar_t *) (p+12));
    clr_appdomindex = *(uint32_t *) (p+14+ wstrlen((wchar_t *) (p+12))*2);
    clr_instid = *(uint16_t *) (p+18+ wstrlen((wchar_t *) (p+12))*2);
};

typedef struct netassm {
    uint64_t clr_assmid;
    uint64_t clr_appdmid;
    uint64_t clr_bindid;
    uint32_t clr_assmflgs;
    string clr_assmname;
    uint16_t clr_instid;
} netassm_t;

#pragma D binding "1.0" translator
translator netassm_t < char *p > {
    clr_assmid = *(uint64_t *) p;
    clr_appdmid = *(uint64_t *) (p+8);
    clr_bindid = *(uint64_t *) (p+16);
    clr_assmflgs = *(uint32_t *) (p+24);
    clr_assmname = wstringof((wchar_t *) (p+28));
    clr_instid = *(uint16_t *) (p+30+ wstrlen((wchar_t *) (p+28))*2);
};

typedef struct netmodule {
    uint64_t clr_modid;
    uint64_t clr_assmid;
    uint32_t clr_modflgs;
    uint32_t clr_reserved;
    string clr_modilpath;
    string clr_modnativepath;
    uint16_t clr_instid;
    guid_t clr_mngpdb_guid;
    uint32_t clr_mngpdb_age;
    string clr_mngpdb_path;
    guid_t clr_nativepdb_guid;
    uint32_t clr_nativepdb_age;
    string clr_nativepdb_path;
} netmodule_t;

#pragma D binding "1.0" translator
translator netmodule_t < char *p > {
    clr_modid = *(uint64_t *) p;
    clr_assmid = *(uint64_t *) (p+8);
    clr_modflgs = *(uint32_t *) (p+16);
    clr_modilpath = wstringof((wchar_t *) (p+24));
    clr_modnativepath = wstringof((wchar_t *) (
        p+26+wstrlen((wchar_t *) (p+24))*2
        )
    );
    clr_instid = *(uint16_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26, self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
    );
    clr_mngpdb_guid = *(guid_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26, self->nettmp + 4 + wstrlen((wchar_t *) (p+self->nettmp))*2)
    );
    clr_mngpdb_age = *(uint32_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26, self->nettmp + 20 + wstrlen((wchar_t *) (p+self->nettmp))*2)
    );
    clr_mngpdb_path = wstringof((wchar_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26, self->nettmp + 24 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
    );
    clr_nativepdb_guid = *(guid_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26,
        (self->nettmp = self->nettmp + 24 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 2 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
    );
    clr_nativepdb_age = *(uint32_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26,
        (self->nettmp = self->nettmp + 24 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 18 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
    );
    clr_nativepdb_path = wstringof((wchar_t *) (
        p + (self->nettmp = wstrlen((wchar_t *) (p+24))*2 + 26,
        (self->nettmp = self->nettmp + 24 + wstrlen((wchar_t *) (p+self->nettmp))*2,
        self->nettmp + 22 + wstrlen((wchar_t *) (p+self->nettmp))*2)
        )
        ));
};
