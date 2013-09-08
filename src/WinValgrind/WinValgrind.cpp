// WinValgrind.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "WinValgrind.h"
#include "WinValgrindCtrl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

const std::string sUsage = "\nusage: winvalgrind [-gc] | [-sm <PID>]\n\n\t-gc\tGenerate the config file template.\n\t-sm\tstart monitoring the process.\n";
// The one and only application object

CWinApp theApp;

using namespace std;

// Method to enable debug privilages
static void EnableDebugPriv(  )
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;

    if( ! OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
    {
        return;
    }
    if ( ! LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &sedebugnameValue ) )
    {
        CloseHandle( hToken );
        return;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges( hToken, FALSE, &tkp, sizeof tkp, NULL, NULL );
    CloseHandle( hToken );
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	HANDLE hMutex = CreateMutex( 0, 0, _T("leak_detector_injector_evt_"));
    if( GetLastError() == ERROR_ALREADY_EXISTS )
    {
        _tprintf( _T("Only one instance of WinValgrind can be run at a time"));
        CloseHandle( hMutex );
        return FALSE;
    }

	int nRetCode = 0;
	EnableDebugPriv();
	HMODULE hModule = ::GetModuleHandle(NULL);

	if (hModule != NULL)
	{
		// initialize MFC and print and error on failure
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			_tprintf(_T("Fatal Error: MFC initialization failed\n"));
			nRetCode = 1;
		}
		else
		{
				
			if(argc < 2)
			{
				_tprintf(_T("The syntax of the command is incorrect.\n"));
				_tprintf(sUsage.c_str());
				nRetCode = 1;
			}
			else
			{
				int pid;
				CWinValgrindCtrl ctrlObj;
				if ((_tcsncmp(argv[1],"-gc",3) == 0))
				{
					ctrlObj.GenerateDefaultConfigTemplate();
				}
				else
				if ((_tcsncmp(argv[1],"-sm",3) == 0) && argc == 3 && (pid =atoi(argv[2]))!=0)
				{
					ctrlObj.InjectParasite(pid);
				}
				else
				{
					_tprintf(_T("The syntax of the command is incorrect.\n"));
					_tprintf(sUsage.c_str());
					nRetCode = 1;
				}
			}
			
				
		}
	}
	else
	{
		
		_tprintf(_T("Fatal Error: GetModuleHandle failed\n"));
		nRetCode = 1;
	}

	return nRetCode;
}
