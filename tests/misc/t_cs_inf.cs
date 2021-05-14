// C# program to illustrate the
// concept of multithreading
using System;
using System.Threading;
using System.Diagnostics;

//csc /platform:x64 /target:exe /debug+ /debug:full  /optimize- /out:forevercs.exe ..\..\internal\forever.cs

public class GFG {
	public static int LOOPS = 1000;
	public static int
	call_1(int d)
	{
		int i;
		i = 1000;
		
		return 0;
	}

	public static void
	call_2()
	{
		int i = 9;
		i = i + 6;
	}
	public static void
	call_3()
	{
		int i = 9;
		i = i + 6;
	}

	// Main Method
	static public void
	Main()
	{
		int i = 0;
		Process currentProcess = Process.GetCurrentProcess();
  
		Console.WriteLine("PID {0}", currentProcess.Id);
		
		while(true) {
			call_1(1);
			Thread.Sleep(1000);
			call_2();
			Thread.Sleep(1000);
			call_3();
			Thread.Sleep(1000);

			i++;
		}
	}
}
