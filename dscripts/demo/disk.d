io:::start
{
	printf("start io %s\n",args[2]->fi_pathname);
	/*print(*args[2]);*/
}

io:::done
{
	printf("done io %s\n",args[2]->fi_pathname);
}
