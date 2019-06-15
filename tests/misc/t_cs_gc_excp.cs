using System;
using System.Diagnostics;

class MyGCCollectClass
{
   private const int maxGarbage = 3;

   static void Main()
   {
      // Put some objects in memory.
     // Console.WriteLine("Sleeping for 20 sec PID {0}\n", Process.GetCurrentProcess().Id);
		//System.Threading.Thread.Sleep(10000);
		//Console.WriteLine("Finished Sleeping\n");
		//System.Threading.Thread.Sleep(15000);
      
     for (int i = 0; i < 2145000000; i++) {
     	int a, b=0;
     	a = b + 2;
    }
    MakeSomeGarbage();
      /*Console.WriteLine("Memory used before collection:       {0:N0}", 
                        GC.GetTotalMemory(false));
      
      // Collect all generations of memory.*/
      MakeSomeGarbage();
      //GC.Collect();
      /*Console.WriteLine("Memory used after full collection:   {0:N0}", 
                        GC.GetTotalMemory(true));*/
      Console.WriteLine("Done");
   }
	static int[] array;
	
   static void MakeSomeGarbage()
   {
      Version vt;
		array = new int[2];
      // Create objects and release them to fill up memory with unused objects.
      for(int i = 0; i < 5; i++) {
         int j = MakeSomeGarbage0();
         for (;j > 0; j--) {
         	int k = array[j];	
        }
      }
   }
   
    static int  MakeSomeGarbage0()
   {
      Version vt;
		GC.Collect();
      // Create objects and release them to fill up memory with unused objects.
      /*for(int i = 0; i < maxGarbage; i++) {
         vt = new Version();
      }*/
      array = new int[4];
      return 4-1;
   }
   
}
// The output from the example resembles the following:
//       Memory used before collection:       79,392
//       Memory used after full collection:   52,640