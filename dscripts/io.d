
io:::done
{
	printf("%s %d %s %s %s", execname, args[0]->b_edev, args[1]->dev_statname, args[2]->fi_name, args[2]->fi_dirname);
}


/*
fsinfo:::create
/tid == 10364/
{
	s = args[0]->fi_pathname; 
	self->ts = timestamp;
	self->irp = args[0]->fi_irp;
}
fsinfo:::done
/self->ts && (timestamp-self->ts) > 5000000000/
{
	t = timestamp - self->ts;
	printf("%d %d ts %d  %s\n", pid, tid, t, s);
	self->ts = 0;
	self->irp = 0;
}
fsinfo:::done
/self->ts/
{
	self->ts = 0;
	self->irp = 0;
}
*/