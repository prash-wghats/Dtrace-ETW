
int u;

dnet::event:runtime,
dnet::event:excp,
dnet::loader:appdomain-load,
dnet::loader:assembly-load,
dnet::loader:module-load,
dnet::gc:heapstat,
dnet::gc:allocate-tick,
dnet::gc:finalizer-end,
dnet::gc:suspend-start,
dnet::gc:gc-start,
dnet::gc:seg-create,
dnet::gc:seg-free,
dnet::lock:lck-wait,
dnet::lock:lck-done,
dnet::thread:thr-start
{
	printf("%s\n", execname);
	print(*args[0]);
}
