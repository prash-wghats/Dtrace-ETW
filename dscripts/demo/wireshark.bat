
@echo off
if exist "%~dp0"..\..\debug\amd64\bin\dtrace.exe (
	set DTRACE=%~dp0\..\..\debug\amd64\bin\dtrace.exe
) else (
	set DTRACE=dtrace.exe
)
if "%~1" == "" (
	echo %DTRACE% -qs %~dp0\networkanalyzer.d "online"
	%DTRACE% -qs %~dp0\networkanalyzer.d "online"
) else (
	echo %DTRACE% -qs %~dp0\networkanalyzer.d -E "%~1"
	%DTRACE% -qs %~dp0\networkanalyzer.d -E "%~1"
)
