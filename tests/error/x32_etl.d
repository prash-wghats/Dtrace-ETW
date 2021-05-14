
 sample-999
 {
	 @[execname] = count();
	 i++;
 }

 END {
	 printf("total perf %d", i);
 }