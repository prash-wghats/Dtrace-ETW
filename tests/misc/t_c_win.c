//ex. dtrace -n "pid$target:ntdll::entry {@[probefunc]=count();}" -c win32.exe
//cl.exe /Zi /Fewin[64/32].exe win.c user32.lib gdi32.lib
//gcc -o win win.c mwindows

#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
const char g_szClassName[] = "myWindowClass";

#define IDC_MAIN_EDIT	101
HINSTANCE GetHInstance() { 
        // Passing null to GetModuleHandle returns the HMODULE of 
        // the file used to create the calling process. This is the same value 
        // as the hInstance passed in to WinMain. The main use of this value 
        // is by RegisterClassEx, which uses it to get the full address of the 
        // user's WndProc. 
        return GetModuleHandleW(NULL); 
    } 
 
    // Returns the value that would be passed to the second wWinMain HINSTANCE parameter. 
    // This function always returns null as per the WinMain documentation. 
    HINSTANCE GetHPrevInstance() { 
        return NULL; 
    } 
 
    // Returns the value that would be passed to the wWinMain LPWSTR parameter. If there 
    // are no command line parameters, this returns a valid pointer to a null terminator 
    // character (i.e. an empty string). 
    // Note: The caller must not free the returned value. Attempting to free it will cause undefined 
    // behavior. 
    LPWSTR GetLPCmdLine() { 
        // The first argument is the program name. To allow it to have spaces, it can be surrounded by 
        // quotes. We must track if the first argument is quoted since a space is also used to separate 
        // each parameter. 
        BOOL isQuoted = FALSE; 
        const wchar_t space = L' '; 
        const wchar_t quote = L'\"'; 
        const wchar_t nullTerminator = L'\0'; 
 
        LPWSTR lpCmdLine = GetCommandLineW(); 
       
 
        // The lpCmdLine in a WinMain is the command line as a string excluding the program name. 
        // Program names can be quoted to allow for space characters so we need to deal with that. 
        while (*lpCmdLine <= space || isQuoted) { 
            if (*lpCmdLine == quote) { 
                isQuoted = !isQuoted; 
            } 
            lpCmdLine++; 
        } 
 
        // Get past any additional whitespace between the end of the program name and the beginning 
        // of the first parameter (if any). If we reach a null terminator we are done (i.e. there are 
        // no arguments and the pointer itself is still properly valid). 
        while (*lpCmdLine <= space && *lpCmdLine != nullTerminator) { 
            lpCmdLine++; 
        } 
 
        // This will now be a valid pointer to either a null terminator or to the first character of 
        // the first command line parameter after the program name. 
        return lpCmdLine; 
    } 
 
    // Returns the value that would be passed to the wWinMain int parameter. 
     int GetNCmdShow() { 
        // It's possible that the process was started with STARTUPINFOW that could have a value for 
        // show window other than SW_SHOWDEFAULT. If so we retrieve and return that value. Otherwise 
        // we return SW_SHOWDEFAULT. 
        STARTUPINFOW startupInfo; 
        GetStartupInfoW(&startupInfo); 
        if ((startupInfo.dwFlags & STARTF_USESHOWWINDOW) != 0) { 
            return startupInfo.wShowWindow; 
        } 
        return SW_SHOWDEFAULT; 
    } 
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg) {
	case WM_CREATE: {
		HFONT hfDefault;
		HWND hEdit;

		hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
		        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
		        0, 0, 100, 100, hwnd, (HMENU)IDC_MAIN_EDIT, GetModuleHandle(NULL), NULL);
		if(hEdit == NULL)
			MessageBox(hwnd, "Could not create edit box.", "Error", MB_OK | MB_ICONERROR);

		hfDefault = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
		SendMessage(hEdit, WM_SETFONT, (WPARAM)hfDefault, MAKELPARAM(FALSE, 0));
	}
	break;
	case WM_SIZE: {
		HWND hEdit;
		RECT rcClient;

		GetClientRect(hwnd, &rcClient);

		hEdit = GetDlgItem(hwnd, IDC_MAIN_EDIT);
		SetWindowPos(hEdit, NULL, 0, 0, rcClient.right, rcClient.bottom, SWP_NOZORDER);
	}
	break;
	case WM_CLOSE:
		DestroyWindow(hwnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

/*int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{

	if(AllocConsole()) {
		freopen("CONOUT$", "wt", stdout);
		SetConsoleTitle("Debug Console");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

	}
*/
int main()
{

HINSTANCE hInstance = GetHInstance(); 
    HINSTANCE hPrevInstance = GetHPrevInstance(); 
    LPWSTR lpCmdLine = GetLPCmdLine(); 
    int nCmdShow = GetNCmdShow(); 

	printf("hello world %d", GetCurrentProcessId());
	WNDCLASSEX wc;
	HWND hwnd;
	MSG Msg;

	wc.cbSize		 = sizeof(WNDCLASSEX);
	wc.style		 = 0;
	wc.lpfnWndProc	 = WndProc;
	wc.cbClsExtra	 = 0;
	wc.cbWndExtra	 = 0;
	wc.hInstance	 = hInstance;
	wc.hIcon		 = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor		 = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
	wc.lpszMenuName  = NULL;
	wc.lpszClassName = g_szClassName;
	wc.hIconSm		 = LoadIcon(NULL, IDI_APPLICATION);

	if(!RegisterClassEx(&wc)) {
		MessageBox(NULL, "Window Registration Failed!", "Error!",
		    MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	hwnd = CreateWindowEx(
	        0,
	        g_szClassName,
	        "theForger's Tutorial Application",
	        WS_OVERLAPPEDWINDOW,
	        CW_USEDEFAULT, CW_USEDEFAULT, 480, 320,
	        NULL, NULL, hInstance, NULL);

	if(hwnd == NULL) {
		MessageBox(NULL, "Window Creation Failed!", "Error!",
		    MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);

	while(GetMessage(&Msg, NULL, 0, 0) > 0) {
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}
	return Msg.wParam;
}
