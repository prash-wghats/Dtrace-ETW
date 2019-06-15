
/* 
csc /platform:x64 /target:exe /debug+ /debug:full  /optimize- /define:MAIN /out:loopass.exe ..\..\internal\loopsass.cs
csc /platform:x64 /target:library /debug+ /debug:full  /optimize- /define:TESTAS0 /out:t_cs_dyndll0.dll ..\..\internal\loopsass.cs
csc /platform:x64 /target:library /debug+ /debug:full  /optimize- /define:TESTAS1 /out:t_cs_dyndll1.dll ..\..\internal\loopsass.cs
csc /platform:x64 /target:library /debug+ /debug:full  /optimize- /define:TESTAS2 /out:t_cs_dyndll2.dll ..\..\internal\loopsass.cs
csc /platform:x64 /target:library /debug+ /debug:full  /optimize- /define:TESTAS3 /out:t_cs_dyndll3.dll ..\..\internal\loopsass.cs
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Threading;

#if (MAIN)
namespace test {
class Program {
	public static int LOOPS = 1000;

	public static void
	method1(object co)
	{
		int coi = (int) co;
		Assembly myassembly;
		Type type = null;

		if (coi == 0) {
			myassembly = Assembly.LoadFrom("t_cs_dyndll0.dll");
			type = myassembly.GetType("t_cs_dyndll0.Class1");
		} else  if (coi == 1) {
			myassembly = Assembly.LoadFrom("t_cs_dyndll1.dll");
			type = myassembly.GetType("t_cs_dyndll1.Class1");
		} else  if (coi == 2) {
			myassembly = Assembly.LoadFrom("t_cs_dyndll2.dll");
			type = myassembly.GetType("t_cs_dyndll2.Class1");
		} else  if (coi == 3) {
			myassembly = Assembly.LoadFrom("t_cs_dyndll3.dll");
			type = myassembly.GetType("t_cs_dyndll3.Class1");
		}

		object instance = Activator.CreateInstance(type);

		MethodInfo[] methods = type.GetMethods();
		object res = null;
		for (int i = 0 ; i < LOOPS; i++) {
			res = methods[0].Invoke(instance, new object[] {5, 3});
		}

		Console.WriteLine(res.ToString());

	}
	static void
	Main (string[] args)
	{
		// Creating and initializing threads
		Thread thr1 = new Thread(method1);
		Thread thr2 = new Thread(method1);
		Thread thr3 = new Thread(method1);
		Thread thr4 = new Thread(method1);
		thr1.Start(0);
		thr2.Start(1);
		thr3.Start(2);
		thr4.Start(3);

		//Console.ReadLine();
	}
}
}

#elif (TESTAS0)

namespace t_cs_dyndll0 {
public class Class1 {
	public int
	sum(int a, int b)
	{
		return a + b;
	}
}
}
#elif (TESTAS1)

namespace t_cs_dyndll1 {
public class Class1 {
	public int
	sum(int a, int b)
	{
		return a + b;
	}
}
}
#elif (TESTAS2)

namespace t_cs_dyndll2 {
public class Class1 {
	public int
	sum(int a, int b)
	{
		return a + b;
	}
}
}
#elif (TESTAS3)

namespace t_cs_dyndll3 {
public class Class1 {
	public int
	sum(int a, int b)
	{
		return a + b;
	}
}
}
#endif