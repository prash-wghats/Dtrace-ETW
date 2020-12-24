for i in `du -a | grep "\.out"`
do
	unix2dos $i
done
