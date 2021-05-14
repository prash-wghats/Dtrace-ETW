char name[10]; 
wchar_t wname[10];
BEGIN {
	name[0] = 'h';
	name[1] = 'w';
	wname[0] = 'h';
	wname[1] = 'w';
	printf("%s %ws", name, wname);
}