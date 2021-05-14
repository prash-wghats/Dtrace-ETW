
 io:::start

 {

	printf("%d %d", args[0]->b_edev, args[0]->b_addr);
 }
io:::done
{
	printf("%d %d", args[0]->b_edev, args[0]->b_addr);
}