BEGIN {
	time = timestamp;
	printf("%Y %Y\n", walltimestamp, etwwalltimestamp);
}

diag:::events
{
	i++;
}
diag:::events
/"{68fdd900-4a3e-11d1-84f40000f80464e3}" == stringof(arg0) && arg1 == 0 && arg2 == 0/
{
	time = walltimestamp;
	pt = ( ((int64_t) 27111902 << 32) + (int64_t) 3577643008 );
	te = (uint64_t *) (arg4 + (4 * 66)); /*62 boottime, 66 starttime*/
	test = (uint32_t *) (arg4 + (4 * 3)); /*62 boottime, 66 starttime*/
	dm = *te;
	dm = (dm - pt) * 100UL;
	printf("World %d %d time %Y %d %Y\n", *te, i, dm, dm, time);
}
END {
	printf("%d %Y\n", time, time);
}