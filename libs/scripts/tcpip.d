
/*
#pragma D depends_on provider tcpip
*/

inline int AF_INET = 2;
#pragma D binding "1.0" AF_INET
inline int AF_INET6 = 23;
#pragma D binding "1.0" AF_INET6

/* failure flags */
inline int ERROR_INSUFFICIENT_RESOURCES = 1;
#pragma D binding "1.0" ERROR_INSUFFICIENT_RESOURCES
inline int ERROR_TOO_MANY_ADDRESSES = 2;
#pragma D binding "1.0" ERROR_TOO_MANY_ADDRESSES
inline int ERROR_ADDRESS_EXISTS = 3;
#pragma D binding "1.0" ERROR_ADDRESS_EXISTS
inline int ERROR_INVALID_ADDRESS = 4;
#pragma D binding "1.0" ERROR_INVALID_ADDRESS
inline int ERROR_OTHER = 5;
#pragma D binding "1.0" ERROR_OTHER
inline int ERROR_TIMEWAIT_ADDRESS_EXIST = 6;
#pragma D binding "1.0" ERROR_TIMEWAIT_ADDRESS_EXIST


typedef struct ipinfo {
	uint8_t  ip_ver;		/* IP version (4, 6) */
	uint16_t ip_plength;		/* payload length */
	string   ip_saddr;		/* source address */
	string   ip_daddr;		/* destination address */
	uint32_t ip_connid;		/* A unique connection identifier to correlate events belonging to the same connection.*/
	uint64_t ip_stime;		/* Start send request time. */
	uint32_t ip_etime;		/* End send request time. */
} ipinfo_t;

#pragma D binding "1.0" translator
translator ipinfo_t < struct tcpip_msg *T > {
	ip_ver = T->ti_ver;
	ip_plength = T->ti_size;
	ip_saddr = (T->ti_ver == AF_INET) ? inet_ntoa(&T->ti_addr.ip4.saddr):
		inet_ntoa6(&T->ti_addr.ip6.saddr);
	ip_daddr = (T->ti_ver == AF_INET) ? inet_ntoa(&T->ti_addr.ip4.daddr):
		inet_ntoa6(&T->ti_addr.ip6.saddr);
	ip_connid = T->ti_connid;
	ip_stime = T->ti_starttime;
	ip_etime = T->ti_endtime;
};

typedef struct tcpinfo {
	uint16_t tcp_sport;	/* source port */
	uint16_t tcp_dport;	/* destination port */
	uint32_t tcp_seq;	/* sequence number */
	uint32_t tcp_ack;	/* acknowledgement number */
	uint8_t tcp_offset;	/* data offset, in bytes */
	uint8_t tcp_flags;	/* flags */
	uint16_t tcp_window;	/* window size */
	uint16_t tcp_checksum;	/* checksum */
	uint16_t tcp_urgent;	/* urgent data pointer */
	struct tcphdr *tcp_hdr;	/* raw TCP header */
	uint16_t tcp_mss;			/* Maximum segment size. */
	uint16_t tcp_sackopt;		/* Selective Acknowledgment (SACK) option in TCP header. */
	uint16_t tcp_tsopt;			/* Time Stamp option in TCP header. */
	uint16_t tcp_wsopt;			/* Window Scale option in TCP header. */
	uint16_t tcp_rcvws;			/* TCP Receive Window Scaling factor. */
	uint16_t tcp_sndws;			/* TCP Send Window Scaling factor. */
} tcpinfo_t;

#pragma D binding "1.0" translator
translator tcpinfo_t < struct tcpip_msg *T > {
	tcp_sport = T->ti_sport;
	tcp_dport = T->ti_dport;
	tcp_seq = T->ti_seqnum;
	tcp_ack = 0;
	tcp_offset = 0;
	tcp_flags = 0;
	tcp_window = T->ti_rcvwin;
	tcp_checksum = 0;
	tcp_urgent = 0;
	tcp_hdr = 0;
	tcp_mss = T->ti_mss;
	tcp_sackopt = T->ti_sackopt;
	tcp_tsopt = T->ti_tsopt;
	tcp_wsopt = T->ti_wsopt;
	tcp_rcvws = T->ti_rcvwinscale;
	tcp_sndws = T->ti_sndwinscale;
};
/*
 * udpinfo contains stable UDP details.
 */
typedef struct udpinfo {
	uint32_t udp_connid;
	uint32_t udp_seq;
	uint16_t udp_plength;
	uint16_t udp_sport;		/* local port */
	uint16_t udp_dport;		/* remote port */
	string udp_saddr;		/* local address, as a string */
	string udp_daddr;		/* remote address, as a string */
} udpinfo_t;

#pragma D binding "1.0" translator
translator udpinfo_t < struct udpip_msg *U > {
	udp_connid = U->ui_connid;
	udp_seq = U->ui_seqnum;
	udp_plength = U->ui_size;
	udp_sport = U->ui_sport;
	udp_dport = U->ui_dport;
	udp_saddr = (U->ui_ver == AF_INET) ? inet_ntoa(&U->ui_addr.ip4.saddr):
		inet_ntoa6(&U->ui_addr.ip6.saddr);
	udp_daddr = (U->ui_ver == AF_INET) ? inet_ntoa(&U->ui_addr.ip4.daddr):
		inet_ntoa6(&U->ui_addr.ip6.saddr);
};

