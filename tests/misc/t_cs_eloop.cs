// C# program to illustrate the
// concept of multithreading
using System;
using System.Threading;

////csc /platform:x64 /target:exe /debug+ /debug:full  /optimize- /out:loopscs.exe ..\..\internal\loops.cs
// csc /platform:x86 /target:exe /debug+ /debug:full  /optimize- /out:loopscs32.exe ..\..\internal\loops.cs
public class GFG {
	public static int LOOPS = 1000, MAXTHREADS = 200;
	public static void Func()
	{
		int i = LOOPS;
		while (i > 0) {
			call_1(0);
			call_2();
			call_3();
			i--;
		}
	}
	public static int
	call_1(int d)
	{
		int i;
		i = 1000;
		//Sleep(i);

		//printf("call_10\n");
		return 0;
	}

	public static void
	call_2()
	{

		//Sleep(1030);
		int i = 9;
		i = i + 6;
		//printf("call_2\n");
	}
	public static void
	call_3()
	{
		//Sleep(100);
		//printf("call_3\n");
		int i = 9;
		i = i + 6;

	}

	// Main Method
	static public void
	Main()
	{

		int i = LOOPS;
		Thread[] thrs = new Thread[MAXTHREADS];
		for (int j = 0; j < MAXTHREADS; j++) {
			thrs[j] = new Thread(Func);
			thrs[j].Start();
		}
		while(i > 0) {
			call_1(1);
			//Sleep(1000);
			call_2();
			//Sleep(1000);
			call_3();
			//Sleep(1000);
			i--;
		}
		for (int j = 0; j < MAXTHREADS; j++) {
			thrs[j].Join();
		}
	}
}
