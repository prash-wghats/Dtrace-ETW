fsinfo:::cleanup
{
	printf("start io %s\n",args[0]->fi_pathname);
}

fsinfo:::close
{
	printf("done io %s\n",args[0]->fi_pathname);
}

fsinfo:::read
{
	printf("start io %s\n",args[0]->fi_pathname);
}

fsinfo:::write
{
	printf("done io %s\n",args[0]->fi_pathname);
}

fsinfo:::setinfo
{
	printf("start io %s\n",args[0]->fi_pathname);
}

fsinfo:::delete
{
	printf("done io %s\n",args[0]->fi_pathname);
}

fsinfo:::rename
{
	printf("start io %s\n",args[0]->fi_pathname);
}

fsinfo:::direnum
{
	printf("done io %s\n",args[0]->fi_pathname);
}

fsinfo:::flush
{
	printf("done io %s\n",args[0]->fi_pathname);
}

fsinfo:::queryinfo
{
	printf("start io %s\n",args[0]->fi_pathname);
}

fsinfo:::fscontrol
{
	printf("done io %s\n",args[0]->fi_pathname);
}

fsinfo:::done
{
	printf("start io %s\n",args[0]->fi_pathname);
}

fsinfo:::dirnotify
{
	printf("done io %s\n",args[0]->fi_pathname);
}


/*
fsinfo  MSNT_SystemTrace                             event create
 8156     fsinfo  MSNT_SystemTrace                             event cleanup
 8157     fsinfo  MSNT_SystemTrace                             event close
 8158     fsinfo  MSNT_SystemTrace                             event read
 8159     fsinfo  MSNT_SystemTrace                             event write
 8160     fsinfo  MSNT_SystemTrace                             event setinfo
 8161     fsinfo  MSNT_SystemTrace                             event delete
 8162     fsinfo  MSNT_SystemTrace                             event rename
 8163     fsinfo  MSNT_SystemTrace                             event direnum
 8164     fsinfo  MSNT_SystemTrace                             event flush
 8165     fsinfo  MSNT_SystemTrace                             event queryinfo
 8166     fsinfo  MSNT_SystemTrace                             event fscontrol
 8167     fsinfo  MSNT_SystemTrace                             event done
 8168     fsinfo  MSNT_SystemTrace                             event dirnotify
 */