typedef struct {
	uint32_t cpu_mhz;
	uint32_t cpu_n;
	uint32_t cpu_memsz;
	uint32_t cpu_pagesz;
	uint32_t cpu_allocgranu;
	string cpu_compname;
	string cpu_domain;
	uint64_t cpu_hyperthrflgs;
	uint64_t cpu_highuseraddr;
	uint16_t cpu_arch;
	uint16_t cpu_level;
	uint16_t cpu_version;
	uint8_t cpu_ispae;
	uint8_t cpu_isnx;
	uint32_t cpu_memmhz;
} hwcpu_t;


/* arg1 = pl length, arg2 = arch, arg3 = version */
translator hwcpu_t < char *p > {
	cpu_mhz = *(uint32_t *) (p);
	cpu_n = *(uint32_t *) (p + 4);
	cpu_memsz = *(uint32_t *) (p + 8);
	cpu_pagesz = *(uint32_t *) (p + 12);
	cpu_allocgranu = *(uint32_t *) (p + 16);
	cpu_compname = wstringof((wchar_t *) (p + 20));
	cpu_domain = wstringof((wchar_t *) (p + 532));
	cpu_hyperthrflgs = arg3 == 0 ? 0 : arg2 ? *(uint64_t *) (p + 800) : *(uint32_t *) (p + 800);
	cpu_highuseraddr = arg3 < 3 ? 0 : arg2 ? *(uint64_t *) (p + 808) : *(uint32_t *) (p + 804);
	/* wo (uint16_t) 0, causes alignment error */
	cpu_arch = arg3 < 3 ? (uint16_t) 0 : *(uint16_t *) (p + (arg2 ? 816 : 808));
	cpu_level = arg3 < 3 ? (uint16_t)0 : *(uint16_t *) (p + (arg2 ? 818 : 810));
	cpu_version = arg3 < 3 ? (uint16_t)0 : *(uint16_t *) (p + (arg2 ? 820 : 812));
	cpu_ispae = arg3 < 3 ? (uint8_t)0 : *(uint8_t *) (p + (arg2 ? 822 : 814));
	cpu_isnx = arg3 < 3 ? (uint8_t)0 : *(uint8_t *) (p + (arg2 ? 823 : 815));
	cpu_memmhz = arg3 < 3 ? (uint8_t)0 : *(uint32_t *) (p + (arg2 ? 824 : 816));
};

typedef struct {
	uint32_t ser_pid;
	uint32_t ser_state;
	uint32_t ser_tag;
	string ser_name;
	string ser_dispn;
	string ser_procn;
	string ser_grpn;
	string ser_svcn;
} hwservice_t;

translator hwservice_t < char *p > {
	ser_pid = *(uint32_t *) (p);
	ser_state = *(uint32_t *) (p + 4);
	ser_tag = *(uint32_t *) (p + 8);
	ser_name = wstringof((wchar_t *) (p + 12));
	ser_dispn = (self->hwlen = wstrlen((wchar_t *) (p + 12)) * 2 + 14, wstringof((wchar_t *) (p + self->hwlen)));
	ser_procn = wstringof((wchar_t *) (p +
	    (self->hwlen = wstrlen((wchar_t *) (p + 12)) * 2 + 14, self->hwlen + 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2)
	    ));
	ser_grpn = arg3 < 3 ? "" : wstringof((wchar_t *) (p + (
	    self->hwlen = wstrlen((wchar_t *) (p + 12)) * 2 + 14, (
	    self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, self->hwlen + 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2

	    )
	    )));
	ser_svcn = arg3 < 3 ? "" : wstringof((wchar_t *) (p + (
	    self->hwlen = wstrlen((wchar_t *) (p + 12)) * 2 + 14, (
	    self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, (
	    self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, self->hwlen + 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2
	    )
	    )
	    )));
};

typedef struct {
	uint8_t vir_isvbs;
	uint8_t vir_ishvci;
	uint8_t vir_ishyperviser;
	uint8_t vir_res;
} hwvirt_t;

translator hwvirt_t < char *p > {
	vir_isvbs = *(uint8_t *) (p);
	vir_ishvci = *(uint8_t *) (p + 1);
	vir_ishyperviser = *(uint8_t *) (p + 2);
};

typedef struct {
	uint64_t irq_affn;
	uint16_t irq_grp;
	uint32_t irq_num;
	string irq_desc;
} hwirq_t;

translator hwirq_t < char *p > {
	irq_affn = *(uint64_t *) (p);
	irq_grp = arg3 < 3 ? 0 : *(uint16_t *) (p + 8);
	irq_num = *(uint32_t *) (p + (arg3 < 3 ? 8 : 12));
	irq_desc = wstringof((wchar_t *) (p + (arg3 < 3 ? 16 : 20)));
};

typedef struct {
	uint32_t vid_memsize;
	uint32_t vid_xres;
	uint32_t vid_yres;
	uint32_t vid_bpp;
	uint32_t vid_vrefresh;
	string vid_chip;
	string vid_dac;
	string vid_adpt;
	string vid_bios;
	string vid_devid;
	uint32_t vid_state;
} hwvideo_t;

translator hwvideo_t < char *p > {
	vid_memsize = *(uint32_t *) (p);
	vid_xres = *(uint32_t *) (p + 4);
	vid_yres = *(uint32_t *) (p + 8);
	vid_bpp = *(uint32_t *) (p + 12);
	vid_vrefresh = *(uint32_t *) (p + 16);
	vid_chip = wstringof((wchar_t *) (p + 20));
	vid_dac = wstringof((wchar_t *) (p + 532));
	vid_adpt = wstringof((wchar_t *) (p + 1044));
	vid_bios = wstringof((wchar_t *) (p + 1556));
	vid_devid = wstringof((wchar_t *) (p + 2068));
	vid_state = *(uint32_t *) (p + 2580);
};

typedef struct {
	uint32_t procs_index;
	uint32_t procs_feat;
	uint32_t procs_speed;
	string procs_name;
	string procs_vend;
	string procs_ids;
} hwprocs_t;

translator hwprocs_t < char *p > {
	procs_index = *(uint32_t *) (p);
	procs_feat = *(uint32_t *) (p + 4);
	procs_speed = *(uint32_t *) (p + 8);
	procs_name = wstringof((wchar_t *) (p + 12));
	procs_vend = wstringof((wchar_t *) (p + 140));
	procs_ids = wstringof((wchar_t *) (p + 172));
};
typedef struct {
	uint32_t dphy_diskno;
	uint32_t dphy_bytes_sector;
	uint32_t dphy_sectors_track;
	uint32_t dphy_tracks_cyl;
	uint64_t dphy_cylinders;
	uint32_t dphy_scsi_port;
	uint32_t dphy_scsi_path;
	uint32_t dphy_scsi_targ;
	uint32_t dphy_scsi_lun;
	uint32_t dphy_npartitions;
	uint8_t dphy_iswritecache;
	string dphy_manu;
	string dphy_drive;
} hwdphy_t;
translator hwdphy_t < char *p > {
	dphy_diskno = *(uint32_t *) (p);
	dphy_bytes_sector = *(uint32_t *) (p + 4);
	dphy_sectors_track = *(uint32_t *) (p + 8);
	dphy_tracks_cyl = *(uint32_t *) (p + 12);
	dphy_cylinders = *(uint64_t *) (p + 16);
	dphy_scsi_port = *(uint32_t *) (p + 24);
	dphy_scsi_path = *(uint32_t *) (p + 28);
	dphy_scsi_targ = *(uint32_t *) (p + 32);
	dphy_scsi_lun = *(uint32_t *) (p + 32);
	dphy_npartitions = *(uint32_t *) (p + 552);
	dphy_iswritecache = *(uint8_t *) (p + 556);
	dphy_manu = wstringof((wchar_t *) (p + 40));
	dphy_drive = wstringof((wchar_t *) (p + 558));
};

typedef struct {
	uint64_t dlog_startoffset;
	uint64_t dlog_partsize;
	uint32_t dlog_diskno;
	uint32_t dlog_size;
	uint32_t dlog_drvtype;
	uint32_t dlog_partno;
	uint32_t dlog_sectors_cluster;
	uint32_t dlog_bytes_sector;
	uint64_t dlog_free_clusters;
	uint64_t dlog_nclusters;
	uint32_t dlog_volext;
	string dlog_drive;
	string dlog_fs;
} hwdlog_t;
translator hwdlog_t < char *p > {
	dlog_startoffset = *(uint64_t *) (p);
	dlog_partsize = *(uint64_t *) (p + 8);
	dlog_diskno = *(uint32_t *) (p + 16);
	dlog_size = *(uint32_t *) (p + 20);
	dlog_drvtype = *(uint32_t *) (p + 24);
	dlog_partno = *(uint32_t *) (p + 40);
	dlog_sectors_cluster = *(uint32_t *) (p + 44);
	dlog_bytes_sector = *(uint32_t *) (p + 48);
	dlog_free_clusters = *(uint64_t *) (p + 56);
	dlog_nclusters = *(uint64_t *) (p + 64);
	dlog_volext = *(uint32_t *) (p + 104);
	dlog_drive = wstringof((wchar_t *) (p + 28));
	dlog_fs = wstringof((wchar_t *) (p + 72));
};
typedef struct {
	uint16_t opt_diskno;
	uint16_t opt_bustype;
	uint16_t opt_devtype;
	uint16_t opt_mediatype;
	uint64_t opt_startoffset;
	uint64_t opt_size;
	uint64_t opt_freeblks;
	uint64_t opt_totblks;
	uint64_t opt_nxtwrtaddr;
	uint32_t opt_nsession;
	uint32_t opt_ntracks;
	uint32_t opt_bytessector;
	uint16_t opt_status;
	uint16_t opt_sessstatus;
	string opt_drv;
	string opt_fs;
	string opt_devn;
	string opt_manu;
} hwopt_t;

translator hwopt_t < char *p > {
	opt_diskno = *(uint16_t *) (p);
	opt_bustype = *(uint16_t *) (p + 2);
	opt_devtype = *(uint16_t *) (p + 4);
	opt_mediatype = *(uint16_t *) (p + 6);
	opt_startoffset = *(uint64_t *) (p + 8);
	opt_size = *(uint64_t *) (p + 16);
	opt_freeblks = *(uint64_t *) (p + 24);
	opt_totblks = *(uint64_t *) (p + 32);
	opt_nxtwrtaddr = *(uint64_t *) (p + 40);
	opt_nsession = *(uint32_t *) (p + 48);
	opt_ntracks = *(uint32_t *) (p + 52);
	opt_bytessector = *(uint32_t *) (p + 56);
	opt_status = *(uint16_t *) (p + 60);
	opt_sessstatus = *(uint16_t *) (p + 62);
	opt_drv = wstringof((wchar_t *)(p + 64)); /*XXX*/
	opt_fs = (self->hwlen = 66 + wstrlen((wchar_t *) (p + 64)) * 2, wstringof((wchar_t *)(p + self->hwlen)));
	opt_devn = (self->hwlen = 66 + wstrlen((wchar_t *) (p + 64)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, stringof((char *)(p + self->hwlen)))
	);
	opt_manu = (self->hwlen = 66 + wstrlen((wchar_t *) (p + 64)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 1 + strlen((char *) (p + self->hwlen)), stringof((char *)(p + self->hwlen)))
	    )
	);
};

typedef struct {
	uint32_t dev_status;
	uint32_t dev_pblm;
	string dev_id;
	string dev_desc;
	string dev_frndn;
	string dev_pbon;
	string dev_servn;
} hwpnp_t;

translator hwpnp_t < char *p > {
	dev_id = (self->hwlen = arg3 <= 3 ? 12 :
	    arg3 == 4 ? 24 : 32,
	    wstringof((wchar_t *) (p + self->hwlen)));
	dev_desc = (self->hwlen = arg3 <= 3 ? 12 : arg3 == 4 ? 24 : 32,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	);
	dev_frndn = (self->hwlen = arg3 <= 3 ? 12 : arg3 == 4 ? 24 : 32,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	    )
	);
	dev_pbon = arg3 < 4 ? "" : (self->hwlen = arg3 <= 3 ? 12 : arg3 == 4 ? 24 : 32,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	    )
	    )
	);
	dev_servn = arg3 < 4 ? "" : (self->hwlen = arg3 <= 3 ? 12 : arg3 == 4 ? 24 : 32,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	    )
	    )
	    )
	);
};

typedef struct {
	uint32_t dpi_mach;
	uint32_t dpi_user;
} hwdpi_t;

translator hwdpi_t < char *p > {
	dpi_mach = *(uint32_t *) (p);
	dpi_user = *(uint32_t *) (p + 4);
};

typedef struct {
	uint32_t nw_tcbtblpart;
	uint32_t nw_hashtblsz;
	uint32_t nw_maxusrport;
	uint32_t nw_tcpdelay;
} hwnw_t;

translator hwnw_t < char *p > {
	nw_tcbtblpart = *(uint32_t *) (p);
	nw_hashtblsz = *(uint32_t *) (p + 4);
	nw_maxusrport = *(uint32_t *) (p + 8);
	nw_tcpdelay = *(uint32_t *) (p + 12);
};

typedef struct {
	uint64_t nic_hwaddr;
	uint32_t nic_len;
	uint32_t nic_ipv4_index;
	uint32_t nic_ipv6_index;
	string nic_desc;
	string nic_ips;
	string nic_dnss;
} hwnic_t;

translator hwnic_t < char *p > {
	nic_hwaddr = arg3 < 2 ? 0 : *(uint64_t *) p;
	nic_len = arg3 < 2 ? *(uint32_t *) (p + 516) : *(uint32_t *) (p + 8);
	nic_ipv4_index = arg3 < 2 ? *(uint32_t *) (p + 512) : *(uint32_t *) (p + 12);
	nic_ipv6_index = arg3 < 2 ? 0 : *(uint32_t *) (p + 16);
	nic_desc = arg3 < 2 ? wstringof((wchar_t *) p) : wstringof((wchar_t *) (p + 20));
	nic_ips = arg3 < 2 ? "" :
	(self->hwlen = 22 + wstrlen((wchar_t *) (p + 20)) * 2, wstringof((wchar_t *) (p + self->hwlen)));
	nic_dnss = arg3 < 2 ? "" :
	(self->hwlen = 22 + wstrlen((wchar_t *) (p + 20)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	);

};

typedef struct {
	string plat_manun;
	string plat_prodn;
	string plat_biosdaten;
	string plat_biosvers;
} hwplat_t;

translator hwplat_t < char *p > {
	plat_manun = wstringof((wchar_t *) p);
	plat_prodn = (self->hwlen = 2 + wstrlen((wchar_t *) p) * 2, wstringof((wchar_t *) (p + self->hwlen)));
	plat_biosdaten = (self->hwlen = 2 + wstrlen((wchar_t *) p) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	);
	plat_biosvers = (self->hwlen = 2 + wstrlen((wchar_t *) p) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2,
	    (self->hwlen += 2 + wstrlen((wchar_t *) (p + self->hwlen)) * 2, wstringof((wchar_t *) (p + self->hwlen)))
	    )
	);
};

hwconfig:::disk-phy,
hwconfig:::disk-log,
hwconfig:::video,
hwconfig:::disk-optical,
hwconfig:::platform,
hwconfig:::nic,
hwconfig:::pnp,
hwconfig:::cpu,
hwconfig:::network,
hwconfig:::dpi,
hwconfig:::service,
hwconfig:::processor,
hwconfig:::irq,
hwconfig:::virtualization
{
	print(*args[0]);
	@[probename] = count();
}