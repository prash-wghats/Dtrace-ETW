using System;
using System.IO;
using System.Text;

namespace Strings {

class Program {
	static string
	Function0(string str)
	{
		return str;
	}

	static String
	Function1(String str)
	{
		return str;
	}

	static void
	Main(string[] args)
	{
		System.String str0;
		string str1 = "String 2";
		// String made of an Integer
		System.String fn = null;
		Encoding utf8 = new UTF8Encoding(true);
		var rass = System.Reflection.Assembly.GetExecutingAssembly();
		foreach (var name in rass.GetManifestResourceNames()) {
			if (name.Contains("UTF8.txt")) {
				fn = name;
			}
		}
		Stream fs = rass.GetManifestResourceStream(fn);
		Byte[] bytes = new Byte[fs.Length];
		fs.Read(bytes, 0, (int)fs.Length);
		fs.Close();

		str0 = utf8.GetString(bytes);

		Function0(str1);
		Function1(str0);
	}
}
}