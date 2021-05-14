
#pragma D option switchrate=10hz
#pragma D option bufsize=10m


enum ndis_enum {
    _WIFI_ADP = 1,
    _ETH_ADP = 0,
    Native802_11 = 0x10000,
    Ethernet802_3 = 1,
    _IP_FORMAT = 0x0800,
    _IPV6_FORMAT = 0x86dd,
    _ARP_FORMAT = 0x0806,
    _LLDP_FORMAT = 0x88cc,
    TypePPP = 0x880b,
    TypeSNMP = 0x814c,
    _RARP_FORMAT = 0x835,
    _ICMPV6_HDR = 0x3a,
    _TCP_FORMAT = 6,
    _UDP_FORMAT = 17,
    _SNAP_FORMAT = 257,
    _UN_FORMAT = -1,
    _LLCUN_FORMAT = -2,
    _LLC_FORMAT = 258,
    _ETH_LEN = 259,
    _MDNS_PORT = 5353,
    _DNS_PORT = 53,
    _HTTPS_PORT = 443,
    _MODBUS_PORT = 502,
    _HTTP_PORT = 80,
    _SSDP_PORT = 1900,
    _WSDiscovey_PORT = 3702,
    _NBTNS_PORT = 137,
    _LLMNR_PORT = 5355,
    _SMB_PORT = 445,
    _NBTDS_PORT = 138,
    _IEC104_PORT = 2404,
    _SMTP_PORT = 25,
    _FTP_PORT = 20,
    _FTP_SIG_PORT = 21,
    _TELNET_PORT = 23,
    _IMAP_PORT = 143,
    _RDP_PORT = 3389,
    _SSH_PORT = 22,
    _DHCP_CLIENT_PORT = 67,
    _DHCP_SERVER = 68,
    _POP3_PORT = 110,
    _UN_PORT = -3,
    _FINISH = 0xffff
};


typedef struct ndis_1001 {
    uint32_t ndis_if_mp;
    uint32_t ndis_if_low;
    uint32_t ndis_fragsz;
    uint64_t ndis_frag;
} ndis_1001_t;
translator ndis_1001_t < char *p > {
    ndis_if_mp = *(uint32_t *) p;
    ndis_if_low = *(uint32_t *) (p+4);
    ndis_fragsz = *(uint32_t *) (p+8);
    ndis_frag =  (uint64_t) (p+12);
};

typedef struct ndis_1002 {
    uint32_t ndis_if_mp;
    uint32_t ndis_if_low;
    uint32_t ndis_metasz;
    uint64_t ndis_meta;
} ndis_1002_t;
translator ndis_1002_t < char *p > {
    ndis_if_mp = *(uint32_t *) p;
    ndis_if_low = *(uint32_t *) (p+4);
    ndis_metasz = *(uint32_t *) (p+8);
    ndis_meta =  (uint64_t) (p+12);
};

/*
 * MAC 802.11 management frame header
 */

struct a {
    int fr_pv : 2;
    int fr_type : 2;
    int fr_sub : 4;
    int fr_toDS : 1;
    int fr_frmDS : 1;
    int fr_mrfrag : 1;
    int fr_retry : 1;
    int fr_pwr : 1;
    int fr_mrdata : 1;
    int fr_prtfr : 1;
    int fr_order : 1;
} mac_frctl;

typedef struct {
    uint8_t mac_addr[6];
} mac_addr_t;
typedef struct {
    uint8_t mac_addr[3];
} osi_code_t;

typedef struct mac80211_mgt {
    uint8_t mac_frctl0;
    uint8_t mac_frctl1;
    uint16_t mac_dura;
    mac_addr_t mac_addr0;
    mac_addr_t mac_addr1;
    mac_addr_t mac_addr2;
    uint16_t mac_seqctrl;
    uint16_t mac_qosctrl;
    uint16_t mac_htctrl;
    /*
     * uint8_t mac_addr3[6]; optional
     * data
     * uint32_t mac_fcs
     */

} mac80211_mgt_t;

translator mac80211_mgt_t < char *p > {
    mac_frctl0 = *(uint8_t *) p;
    mac_frctl1 = *(uint8_t *) (p+1);
    mac_dura = *(uint16_t *) (p+2);
    mac_addr0 = *(mac_addr_t *) (p+4);
    mac_addr1 = *(mac_addr_t *) (p+10);
    mac_addr2 = *(mac_addr_t *) (p+16);
    mac_seqctrl = *(uint16_t *) (p+22);

};
/*
 * 802.2 Frame Format (LLC)
 * llc_ctrl 0xXXXXXX,X0 - I Frame
 *					 ,01 - Supervisory frame
 *					 ,11 - Unnumbered frame
 */
typedef struct llc8022_ff {
    uint8_t llc_dsap;
    uint8_t llc_ssap;
    uint8_t llc_ctrl;
} llc8022_ff_t;

translator llc8022_ff_t < char *p > {
    llc_dsap = *(uint8_t *) p;
    llc_ssap = *(uint8_t *) (p+1);
    llc_ctrl = *(uint8_t *) (p+2);
};

/*
 * IEEE 802.3 SNAP Frame Format
 */
typedef struct snap8023_ff {
    uint8_t snap_org[3];
    uint16_t snap_type;
} snap8023_ff_t;

translator snap8023_ff_t < char *p > {
    snap_type = ((snap_org[0] = *p, snap_org[1] = *(p+1),snap_org[2] = *(p+2)), ntohs(*(uint16_t *) (p+3)));
};
/*
 * Ethernet Frame Format - ethernet802.3
 */
typedef struct ether_ff {
    mac_addr_t eth_dest;
    mac_addr_t eth_src;
    uint16_t eth_lenty;
    /* data 46-1500 bytes
     * crc 4 bytes */
} ether_ff_t;

translator ether_ff_t < char *p > {
    eth_dest = *(mac_addr_t *) (p);
    eth_src = *(mac_addr_t *) (p+6);
    eth_lenty =  ntohs(*(uint16_t *) (p+12));
};

/*
 * ARP
 */
typedef enum arp_enum {
    ARP_HW_ETH10MB = 1,
    ARP_HW_IEEE802 = 6,
    ARP_HW_ARCNET = 7,
    ARP_HW_FRMRELAY = 15,
    ARP_HW_ATM = 16,
    ARP_HW_HDLC = 17,
    ARP_HW_FIBRECH = 18,
    ARP_HW_ATM1 = 19,
    ARP_HW_SERIAL = 20
} arp_enum_t;

/* Ethernet ARP packet from RFC 826 */
typedef struct arp_ether {
    arp_enum_t arp_htype;   /* Format of hardware address */
    uint16_t arp_ptype;   /* Format of protocol address */
    uint8_t arp_hlen;    /* Length of hardware address */
    uint8_t arp_plen;    /* Length of protocol address */
    uint16_t arp_op;    /* ARP opcode (command) */
    /* ether, ip type */
    mac_addr_t arp_sha;  /* Sender hardware address */
    uint32_t arp_spa;   /* Sender IP address */
    mac_addr_t arp_tha;  /* Target hardware address */
    uint32_t arp_tpa;   /* Target IP address */
} arp_ether_t;

translator arp_ether_t < char *p > {
    arp_htype = *(uint16_t *) (p);
    arp_ptype = *(uint16_t *) (p+2);
    arp_hlen = *(uint8_t *) (p+4);
    arp_plen = *(uint8_t *) (p+5);
    arp_op = *(uint16_t *) (p+6);
    arp_sha = *(mac_addr_t *) (p+8);
    arp_spa = *(uint32_t *) (p+14); /* alignment ?? */
    arp_tha = *(mac_addr_t *) (p+18);
    arp_tpa = *(uint32_t *) (p+22);
};

/*
 * IP Header
 */
typedef struct iphdr
{
    uint8_t   ip_verlen;   /* Header version and length (dwords). */
    uint8_t   ip_serv;    /* Service type. */
    uint16_t  ip_len;     /* Length of datagram (bytes). */
    uint16_t  ip_id;      /* Unique packet identification. */
    uint16_t  ip_frag;   /* Flags; Fragment offset. */
    uint8_t   ip_ttl; /* Packet time to live (in network). */
    uint8_t   ip_proto;   /* Upper level protocol (UDP, TCP). */
    uint16_t  ip_crc;   /* IP header checksum. */
    string  ip_saddr;   /* Source IP address. */
    string  ip_daddr;  /* Destination IP address. */

} iphdr_t;

translator iphdr_t < char *p > {
    ip_verlen = *(uint8_t *) (p);
    ip_serv = *(uint8_t *) (p+1);
    ip_len = ntohs(*(uint16_t *) (p+2));
    ip_id = ntohs(*(uint16_t *) (p+4));
    ip_frag = ntohs(*(uint16_t *) (p+6));
    ip_ttl = *(uint8_t *) (p+8);
    ip_proto = *(uint8_t *) (p+9);
    ip_crc = ntohs(*(uint16_t *) (p+10));
    ip_saddr = inet_ntoa ((ipaddr_t *) (p+12));
    ip_daddr = inet_ntoa ((ipaddr_t *) (p+16));
};

/*
 * IPv6 Header
 */
typedef struct iphdrv6
{
    uint32_t ip6_ver_tc_fl;
    uint16_t ip6_len;
    uint8_t ip6_proto_nxt;
    uint8_t ip6_hoplmt;
    string ipv6_saddr;
    string ipv6_daddr;
} iphdrv6_t;

translator iphdrv6_t < char *p > {
    ip6_ver_tc_fl = *(uint32_t *) (p);
    ip6_len = ntohs(*(uint16_t *) (p+4));
    ip6_proto_nxt = *(uint8_t *) (p+6);
    ip6_hoplmt = *(uint8_t *) (p+7);
    ipv6_saddr = inet_ntoa6((struct in6_addr *)(p+8));
    ipv6_daddr = inet_ntoa6((struct in6_addr *)(p+8+sizeof(struct in6_addr)));

};
/*
 * TCP Header
 */
typedef struct tcphdr {
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seqno;
    uint32_t tcp_ackno;
    uint8_t tcp_offset;
    uint8_t tcp_flags;
    uint16_t tcp_wnd;
    uint16_t tcp_crc;
    uint16_t tcp_urgp;
    uint32_t tcp_opts;
} tcphdr_t;

translator tcphdr_t < char *p > {
    tcp_sport = ntohs(*(uint16_t *) (p));
    tcp_dport = ntohs(*(uint16_t *) (p+2));
    tcp_seqno = ntohl(*(uint32_t *) (p+4));
    tcp_ackno = ntohl(*(uint32_t *) (p+8));
    tcp_offset = *(uint8_t *) (p+12);
    tcp_flags = *(uint8_t *) (p+13);
    tcp_wnd = ntohs(*(uint16_t *) (p+14));
    tcp_crc = ntohs(*(uint16_t *) (p+16));
    tcp_urgp = ntohs(*(uint16_t *) (p+18));
    /*tcp_opts = *(uint32_t *) (p+20);*/
};
/*
 * UDP Header
 */
typedef struct udphdr {
    uint16_t udp_sport;
    uint16_t udp_dport;
    uint16_t udp_len;
    uint16_t udp_crc;
} udphdr_t;

translator udphdr_t < char *p > {
    udp_sport = ntohs(*(uint16_t *) (p));
    udp_dport = ntohs(*(uint16_t *) (p+2));
    udp_len = ntohs(*(uint16_t *) (p+4));
    udp_crc = ntohs(*(uint16_t *) (p+6));
};
/*
 * NdisEtwMetaData
 */
typedef struct metadata_1002 {
    uint8_t md_type;
    uint8_t md_rev;
    uint8_t md_size;
    uint32_t md_recvfl;
    uint32_t md_phyid;
    uint32_t md_chcenfq;
    uint32_t md_MPDUr;
    int32_t md_lRSSI;
    uint32_t md_datart;
    uint32_t md_szmediasp;
    uint64_t md_infomediasp;
    uint64_t md_ts;
} metadata_1002_t;

translator metadata_1002_t < char *p > {
    md_type = *(uint8_t *) p;
    md_rev = *(uint8_t *) (p+1);
    md_size = *(uint8_t *) (p+2);
    md_recvfl = *(uint32_t *) (p+4);
    md_phyid = *(uint32_t *) (p+8);
    md_chcenfq = *(uint32_t *) (p+12);
    md_MPDUr = *(uint32_t *) (p+16);
    md_lRSSI = *(uint32_t *) (p+20);
    md_datart = *(uint32_t *) (p+24);
    md_szmediasp = *(uint32_t *) (p+28);
    md_infomediasp = *(uint64_t *) (p+32);
    md_ts = *(uint64_t *) (p+40);
};

string protocols[int];
char HEX[int];

BEGIN {
    protocols[_DNS_PORT] = "DNS";
    protocols[_MDNS_PORT] = "mDNS";
    protocols[_ARP_FORMAT] = "ARP";
    protocols[_HTTPS_PORT] = "HTTPS";
    protocols[_HTTP_PORT] = "HTTP";
    protocols[_ICMPV6_HDR] = "ICMPV6";
    protocols[_IEC104_PORT] = "IEC104";
    protocols[_IPV6_FORMAT] = "IPV6";
    protocols[_IP_FORMAT] = "IP";
    protocols[_LLC_FORMAT] = "LLC";
    protocols[_LLDP_FORMAT] = "LLDP";
    protocols[_MODBUS_PORT] = "MODBUS";
    protocols[_NBTDS_PORT] = "NBTDS";
    protocols[_NBTNS_PORT] = "NBTNS";
    protocols[_RARP_FORMAT] = "RARP";
    protocols[_SNAP_FORMAT] = "SNAP";
    protocols[_SSDP_PORT] = "SSDP";
    protocols[_TCP_FORMAT] = "TCP";
    protocols[_UDP_FORMAT] = "IP";
    protocols[_WSDiscovey_PORT] = "WSDiscovey";
    protocols[_SMB_PORT] = "SMB";
    protocols[_UN_FORMAT] = "UNKNOWN";
    protocols[_SMTP_PORT] = "SMTP";
    protocols[_TELNET_PORT] = "TELNET";
    protocols[_SSH_PORT] = "SSH";
    protocols[_IMAP_PORT] = "IMAP";
    protocols[_POP3_PORT] = "POP3";
    protocols[_FTP_PORT] = "FTP";
    protocols[_FTP_PORT] = "FTP Signalling";
    protocols[_RDP_PORT] = "RDP";
    protocols[_LLMNR_PORT] = "LLMNR";
    protocols[_DHCP_CLIENT_PORT] = "DHCP CLient";
    protocols[_DHCP_SERVER] = "DHCP Server";
    protocols[_FINISH] = "";
    HEX[0] = '0';
    HEX[1] = '1';
    HEX[2] = '2';
    HEX[3] = '3';
    HEX[4] = '4';
    HEX[5] = '5';
    HEX[6] = '6';
    HEX[7] = '7';
    HEX[8] = '8';
    HEX[9] = '9';
    HEX[10] = 'a';
    HEX[11] = 'b';
    HEX[12] = 'c';
    HEX[13] = 'd';
    HEX[14] = 'e';
    HEX[15] = 'f';
}

microsoft-windows-ndis-packetcapture:::native802.11
/arg0 == 1002/
{
    @[probename, arg0] = count();
    @mk[execname, probeprov] = count();

    this->d1002 = (ndis_1002_t *) arg2;
    this->wi = xlate <metadata_1002_t> ((char *) arg2);

    i_1002++;
}

microsoft-windows-ndis-packetcapture:::ethernet802.3
/arg0 == 1002/
{
    printf("%s : %s", probeprov, probename);
    exit(0);
}

microsoft-windows-ndis-packetcapture:::native802.11,
          microsoft-windows-ndis-packetcapture:::ethernet802.3
          /arg0 == 1001/
{
    this->hlp_pos = arg2;
    this->d1001 = (ndis_1001_t *) ((char *) (this->hlp_pos));
    this->hlp_pos += 12;

    this->hlp_fraglen = this->d1001->ndis_fragsz;
    this->hlp_fragend = this->hlp_pos + this->hlp_fraglen;
    this->count = 0;
}

microsoft-windows-ndis-packetcapture:::native802.11
/arg0 == 1001/
{
    this->mac = xlate <mac80211_mgt_t> ((char *) (this->hlp_pos));
    this->hlp_pos += 22 + 2 + ((this->mac.mac_frctl0 & 0xc) == 8 && (this->mac.mac_frctl0 & 0x80) == 0x80 ? 2 : 0);
    this->hlp_type = _LLC_FORMAT;
    this->adp = _WIFI_ADP;
    this->hdr = "Wifi";
    this->hdstr[this->count++] = "Wifi";
}
this string hdstr[10];
microsoft-windows-ndis-packetcapture:::ethernet802.3
/arg0 == 1001/
{
    this->ether = xlate <ether_ff_t> ((char *) (this->hlp_pos));
    this->hlp_type = this->ether.eth_lenty <= 0x05dc ? _ETH_LEN : (
        this->ether.eth_lenty
    );
    this->adp = _ETH_ADP;
    this->hdr = "Ethernet";
    this->hdstr[this->count++] = "Ethernet";
}

microsoft-windows-ndis-packetcapture:::native802.11
/arg0 == 1001 && this->hlp_type == _LLC_FORMAT/
{
    this->llc = xlate <llc8022_ff_t> ((char *) (this->hlp_pos));
    this->hlp_type = this->llc.llc_dsap == 0xaa && this->llc.llc_dsap == 0xaa ? _SNAP_FORMAT : _LLCUN_FORMAT;
    this->hlp_pos += 3;
    this->hdr = strjoin(this->hdr, "-> LLC");
    this->hdstr[this->count++] = ":LLC";
}

microsoft-windows-ndis-packetcapture:::native802.11
/arg0 == 1001 && this->hlp_type == _SNAP_FORMAT/
{
    this->snap = xlate <snap8023_ff_t> ((char *) this->hlp_pos);

    this->hlp_type = this->snap.snap_type;
    this->hlp_pos = this->hlp_pos + 5;
    this->hdr = strjoin(this->hdr, "-> SNAP");
    this->hdstr[this->count++] = ":SNAP";
}

this char sp[20], dp[20];
microsoft-windows-ndis-packetcapture:::native802.11,
          microsoft-windows-ndis-packetcapture:::ethernet802.3
          /arg0 == 1001 && this->hlp_type == _ARP_FORMAT/
{

    this->arp = xlate <arp_ether_t> ((char *) (this->hlp_pos));

    /* printf("%s -> ARP\n", this->hdr); */

    /*printf("\t\tSender - HW [%x:%x:%x:%x:%x:%x] ; IP [%s]\n\t\tTarget - HW [%x:%x:%x:%x:%x:%x] ; IP [%s]\n",
    	this->arp.arp_sha.mac_addr[0], this->arp.arp_sha.mac_addr[0], this->arp.arp_sha.mac_addr[0],
    	this->arp.arp_sha.mac_addr[0], this->arp.arp_sha.mac_addr[0], this->arp.arp_sha.mac_addr[0],
    	inet_ntoa(( ipaddr_t *) &this->arp.arp_spa),
    	this->arp.arp_tha.mac_addr[0], this->arp.arp_tha.mac_addr[0], this->arp.arp_tha.mac_addr[0],
    	this->arp.arp_tha.mac_addr[0], this->arp.arp_tha.mac_addr[0], this->arp.arp_tha.mac_addr[0],
    	inet_ntoa(( ipaddr_t *) &this->arp.arp_tpa));
    this->hlp_type = _FINISH;*/
    arp++;

    this->sp[0] = HEX[this->arp.arp_sha.mac_addr[0] / 16]; this->sp[1] = HEX[this->arp.arp_sha.mac_addr[0] % 16]; this->sp[2] = '-';
    this->sp[3] = HEX[this->arp.arp_sha.mac_addr[1] / 16]; this->sp[4] = HEX[this->arp.arp_sha.mac_addr[1] % 16]; this->sp[5] = '-';
    this->sp[6] = HEX[this->arp.arp_sha.mac_addr[2] / 16]; this->sp[7] = HEX[this->arp.arp_sha.mac_addr[2] % 16]; this->sp[8] = '-';
    this->sp[9] = HEX[this->arp.arp_sha.mac_addr[3] / 16]; this->sp[10] = HEX[this->arp.arp_sha.mac_addr[3] % 16]; this->sp[11] = '-';
    this->sp[12] = HEX[this->arp.arp_sha.mac_addr[4] / 16]; this->sp[13] = HEX[this->arp.arp_sha.mac_addr[4] % 16]; this->sp[14] = '-';
    this->sp[15] = HEX[this->arp.arp_sha.mac_addr[5] / 16]; this->sp[16] = HEX[this->arp.arp_sha.mac_addr[5] % 16]; this->sp[17] = '\0';

    this->dp[0] = HEX[this->arp.arp_tha.mac_addr[0] / 16]; this->dp[1] = HEX[this->arp.arp_tha.mac_addr[0] % 16]; this->dp[2] = '-';
    this->dp[3] = HEX[this->arp.arp_tha.mac_addr[1] / 16]; this->dp[4] = HEX[this->arp.arp_tha.mac_addr[1] % 16]; this->dp[5] = '-';
    this->dp[6] = HEX[this->arp.arp_tha.mac_addr[2] / 16]; this->dp[7] = HEX[this->arp.arp_tha.mac_addr[2] % 16]; this->dp[8] = '-';
    this->dp[9] = HEX[this->arp.arp_tha.mac_addr[3] / 16]; this->dp[10] = HEX[this->arp.arp_tha.mac_addr[3] % 16]; this->dp[11] = '-';
    this->dp[12] = HEX[this->arp.arp_tha.mac_addr[4] / 16]; this->dp[13] = HEX[this->arp.arp_tha.mac_addr[4] % 16]; this->dp[14] = '-';
    this->dp[15] = HEX[this->arp.arp_tha.mac_addr[5] / 16]; this->dp[16] = HEX[this->arp.arp_tha.mac_addr[5] % 16]; this->dp[17] = '\0';

    /*printf("\t\tSender - HW [%s] ; IP [%s]\n\t\tTarget - HW [%s] ; IP [%s]\n", this->sp, inet_ntoa(( ipaddr_t *) &this->arp.arp_spa),
    	this->dp,inet_ntoa(( ipaddr_t *) &this->arp.arp_tpa)); */
    as = strjoin(" ", inet_ntoa(( ipaddr_t *) &this->arp.arp_tpa));
    as = strjoin(this->dp, as);
    as = strjoin(" -> T ", as);
    as = strjoin(inet_ntoa(( ipaddr_t *) &this->arp.arp_spa), as);
    as = strjoin(" ", as);
    as = strjoin(this->sp, as);
    as = strjoin(" : ARP S ", as);
    this->hdstr[this->count++] = as;

    this->hdr = as;
    this->hlp_type = _FINISH;
}

microsoft-windows-ndis-packetcapture:::native802.11,
microsoft-windows-ndis-packetcapture:::ethernet802.3
/arg0 == 1001 && this->hlp_type == _IP_FORMAT/
{
    this->ip = xlate <iphdr_t> ((char *) (this->hlp_pos));
    this->hlp_type = this->ip.ip_proto;
    this->hlp_fragend = this->hlp_pos + this->ip.ip_len;
    this->hlp_pos += 20;

    this->ipj = strjoin(" > ", this->ip.ip_daddr);
    this->ipj = strjoin(this->ip.ip_saddr, this->ipj);
    this->ipj = strjoin(" : IP ", this->ipj);
    /*printf("%s-> IP Src [%s] ; Dest [%s] ",this->hdr, this->ip.ip_saddr, this->ip.ip_daddr);*/

    this->hdr = "";
    this->hdstr[this->count++] = this->ipj;
}

microsoft-windows-ndis-packetcapture:::native802.11,
microsoft-windows-ndis-packetcapture:::ethernet802.3
/arg0 == 1001 && this->hlp_type == _UDP_FORMAT/
{
    this->udp = xlate <udphdr_t> ((char *) (this->hlp_pos));
    this->hlp_type = (this->junk = this->udp.udp_sport < this->udp.udp_dport ? this->udp.udp_sport : this->udp.udp_dport,
        this->junk < MAX_REG_PORT ? this->junk : _UN_PORT);
    /*printf("%s-> UDP Src [%x] ; Dest [%x] ", this->hdr, this->udp.udp_sport, this->udp.udp_dport);*/

    this->udps = strjoin(" > ", lltostr(this->udp.udp_dport));
    this->udps = strjoin(lltostr(this->udp.udp_sport), this->udps);
    this->udps = strjoin(" : UDP ", this->udps);
    this->hdstr[this->count++] = this->udps;
    this->hdr = "";

}
inline int MAX_REG_PORT = 0xC000; /*1024;*/

microsoft-windows-ndis-packetcapture:::native802.11,
          microsoft-windows-ndis-packetcapture:::ethernet802.3
          /arg0 == 1001 && this->hlp_type == _TCP_FORMAT/
{
    this->tcp = xlate <tcphdr_t> ((char *) (this->hlp_pos));


    this->hlp_pos += 20;
    this->hlp_type = (this->junk = this->tcp.tcp_sport < this->tcp.tcp_dport ? this->tcp.tcp_sport : this->tcp.tcp_dport,
        this->junk < MAX_REG_PORT ? this->junk : _UN_PORT);
    /*printf("%s-> TCP Src [%x] ; Dest [%x] ", this->hdr, this->tcp.tcp_sport, this->tcp.tcp_dport);*/

    this->tcps = strjoin(" > ", lltostr(this->tcp.tcp_dport));
    this->tcps = strjoin(lltostr(this->tcp.tcp_sport), this->tcps);
    this->tcps = strjoin(" : TCP ", this->tcps);
    this->hdstr[this->count++] = this->tcps;
    this->hdr = "";

}

microsoft-windows-ndis-packetcapture:::native802.11,
microsoft-windows-ndis-packetcapture:::ethernet802.3
/arg0 == 1001 && this->hlp_type == _IPV6_FORMAT/
{
    this->ip6 = xlate <iphdrv6_t> ((char *) (this->hlp_pos));

    this->hlp_type = this->ip6.ip6_proto_nxt;

    this->ipj6 = strjoin(" > ", this->ip6.ipv6_daddr);
    this->ipj6 = strjoin(this->ip6.ipv6_saddr, this->ipj6);
    this->ipj6 = strjoin(" : IPv6 ", this->ipj6);

    this->hdr = strjoin(this->hdr, "-> IPV6");
    this->hdstr[this->count++] = this->ipj6;

}

microsoft-windows-ndis-packetcapture:::native802.11,
microsoft-windows-ndis-packetcapture:::ethernet802.3
/arg0 == 1001/
{
    this->proto = protocols[this->hlp_type];
    this->proto = this->proto == "" ? this->proto :
    this->proto == NULL ? " : ??" :
    strjoin(" : ", this->proto);
    this->proto = (this->pl = this->hlp_fragend - this->hlp_pos) == 0 ? this->proto :
    strjoin(this->proto, strjoin(" payload(", strjoin(lltostr(this->pl), ")") ) );
    /*printf("%s -> %s (%x)\n", this->hdr, this->proto, this->hlp_fragend - this->hlp_pos);*/
    line = "";
    line = this->count-- == 0 ? line :
    (line = this->hdstr[0], this->count-- == 0 ? line :
        (line = strjoin(line, this->hdstr[1]), this->count-- == 0 ? line :
        (line = strjoin(line, this->hdstr[2]), this->count-- == 0 ? line :
        (line = strjoin(line, this->hdstr[3]), this->count-- == 0 ? line :
        (line = strjoin(line, this->hdstr[4]), this->count-- == 0 ? line :
        (line = strjoin(line, this->hdstr[5]), this->count-- == 0 ? line : line
        ))))));
    line = strjoin(line, this->proto);
    printf("%s\n", line);
    this->cc++;
    /*tracemem(this->hlp_pos, 256, this->hlp_fragend - this->hlp_pos);
     		print(*(this->d1002));
    print(this->wi);
    print(this->mac);
    print(this->llc);
    print(this->snap);
    print(this->ip);
    	print(this->udp);
    	print(this->tcp);
    print(this->ip6);
    print(this->arp);
    */
}

