

typedef struct lmagic {
	int a;
	int b;
	int d;
	char *h;
	char f[10];
	wchar_t c[10];
} lmagic_t;

pid$target::magic_func:entry
{
		this->p0 = (userland struct pid`magic *)arg0;
		this->p1 = (userland pid`magic_t *)arg0;

		this->p2 = (userland lmagic_t *)arg0;
		this->p3 = (userland struct lmagic *)arg0;
		
        print(*this->p0);
        print(*this->p1);
        print(*this->p2);
        print(*this->p3);	
        print(*args[0]);
}
pid$target::print_head:entry
{
	print(*args[0])
}