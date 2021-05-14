tcpip:::receive 
{
	@pkts[pid, execname, args[0]->ip_daddr, args[1]->tcp_sport] = count();
}

tcpip:::accept
{ 
	@[args[1]->tcp_dport] = count();
}