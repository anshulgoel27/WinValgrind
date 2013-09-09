#include "stdafx.h"
#include "WinValgrindCtrl.h"
#include <string>

using namespace std;

struct Th_Data
{
	int Pid;
	DWORD hLibModule;
	HINSTANCE hKernel32;
	HANDLE hProcess;
	void* pLibRemote;
	int libLen;
};

DWORD WINAPI ConsoleUIThreadProc(LPVOID lpParam)
{
	int  Pid = *((int*)lpParam);
	wcout << _T("Montoring started for pid ")<<Pid<<L"\n\n";

	wstring command;
	wcout << _T("Command options\n\n");
	wcout << _T("-d  Dump the leak trace.\n");
	wcout << _T("-c  Clear leaks.\n");
	wcout << _T("-e  Exit.\n\n");
	while(1)
	{
		wcout << _T("> ");
		std::getline(std::wcin,command);

		if(command == L"-d")
		{
			wcout<< L"Dumping the leak trace.\n";
			HANDLE hDumpEvent = CreateEvent( 0, TRUE, FALSE, DUMP_EVENT );
			SetEvent( hDumpEvent );
			CloseHandle( hDumpEvent );
		}
		else
		if(command == L"-c")
		{
			HANDLE hMemRestEvent = CreateEvent( 0, TRUE, FALSE, CLEAR_LEAKS );
			SetEvent( hMemRestEvent );
			CloseHandle( hMemRestEvent );
		}
		else
		if(command == L"-e")
		{
			HANDLE hDumpEvent = CreateEvent( 0, TRUE, FALSE, DUMP_EVENT );
			SetEvent( hDumpEvent );
			CloseHandle( hDumpEvent );

			break;
		}
		else
		{
			continue;
		}
	}

	return 0;
	

}

bool CWinValgrindCtrl::GenerateDefaultConfigTemplate()
{
	pugi::xml_document doc;
	if (!doc.load(sConfigTemplate.c_str(), pugi::parse_default | pugi::parse_comments)) return false;
	
	pugi::xml_node pdb = doc.child("WinValgrind").child("PDBInfo");
	
	if(!pdb.child("PDBInfo1").attribute("path").set_value(m_csDllPath)) return false;
	if(!pdb.child("PDBInfo2").attribute("path").set_value(m_csSystemPath)) return false;
	if(!pdb.child("PDBInfo3").attribute("path").set_value(m_csSymbolPath)) return false;

	doc.save_file(L"config.xml");
	return true;
}

bool CWinValgrindCtrl::InjectParasite(int nPid)
{
	HANDLE hDuumpEvent = CreateEvent( 0, TRUE, FALSE, DUMP_EVENT );
    if( GetLastError() == ERROR_ALREADY_EXISTS)
    {
        _tprintf( _T("The parasite is already injected in one application.\nPlease close that one before trying to inject again\n"));
        CloseHandle( hDuumpEvent );
        return false;
    }
    CloseHandle( hDuumpEvent );

    

    CString csPath;
    LPSTR lpPath = csPath.GetBuffer( MAX_PATH );
    GetModuleFileName(0,lpPath, MAX_PATH );
    PathRemoveFileSpec( lpPath );
    csPath.ReleaseBuffer();    
    csPath += _T("\\parasite.dll");

     if( !PathFileExists( csPath ))
     {
         _tprintf( _T("parasite.dll not found in the path ") + csPath + _T("\n\nCannot continue!\n"));
         return false;
     }

    
    
    HANDLE hProcess =  OpenProcess( PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|
                                    PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ,
                                    FALSE, nPid );    
    if( !hProcess)
    {
		_tprintf( _T("Failed to open the process %d\n"),nPid);
        return false;
    }

    HINSTANCE hKernel32 = GetModuleHandleA( "Kernel32.dll" );    
    PROC pLoadLib = (PROC)GetProcAddress( hKernel32, "LoadLibraryA" );

	void* pLibRemote = ::VirtualAllocEx( hProcess, NULL, csPath.GetLength(),
                                         MEM_COMMIT, PAGE_READWRITE );
    ::WriteProcessMemory( hProcess, pLibRemote, (void*)csPath.operator LPCTSTR(),
                          csPath.GetLength(), NULL );
	HANDLE hThread;
    if( !(hThread = CreateRemoteThread( hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pLibRemote, 0, 0 )))
    {
        _tprintf( _T("Create Remote thread Failed") );
        ::VirtualFreeEx( hProcess, pLibRemote,csPath.GetLength(), MEM_RELEASE );
    }
	WaitForSingleObject(hThread,INFINITE);
	
	// Get handle of loaded module
	::CloseHandle( hThread );


	HANDLE hUIThread = CreateThread( NULL, 0, 
		ConsoleUIThreadProc,&nPid, 0, NULL);

	WaitForSingleObject(hUIThread,INFINITE);

	CloseHandle(hUIThread);

	return true;
}


