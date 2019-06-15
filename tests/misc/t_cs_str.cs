using System;  
namespace Strings  
{  
    class Program  
    {  
		static string Function0(string str)
		{
			return str;
		}

		static String Function1(String str)
		{
			return str;
		}

        static void Main(string[] args)  
        {  
            System.String str0 = "String 1";  
			string str1 = "String 2";
            // String made of an Integer  
            System.String age = "33";  
  
            // String made of a double  
           	Function0(str1);
			Function1(str0);
        }  
    }  
}  