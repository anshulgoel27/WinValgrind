// parasite.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "parasite.h"
#include "ConfigLoader.h"


// CParasiteApp

BEGIN_MESSAGE_MAP(CParasiteApp, CWinApp)
END_MESSAGE_MAP()



//////////////////////////////////////////////////////////////////////////////////

CApiHookMgr*  CParasiteApp::sm_pHookMgr       = NULL;


// CParasiteApp construction

CParasiteApp::CParasiteApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CParasiteApp object

CParasiteApp theApp;

DWORD WINAPI CParasiteApp::DumpController( LPVOID pParam )
{
    AFX_MANAGE_STATE( AfxGetStaticModuleState());
	
	dlog("DumpController started")
	CConfigLoader ConfigLoad;
	if(!ConfigLoad.LoadConfig())
	{
		dlog("LoadConfig failed!")
		dlog("Continuing with default configuration...")
	}
    
	CParasiteApp* thisApp = (CParasiteApp*)pParam;
	sm_pHookMgr = new CApiHookMgr();
	
	//
	// Initially we must hook a few important functions
	//
	dlog("Hooking system functions.")
	if(sm_pHookMgr->HookSystemFuncs())
	{
		dlog("System API's hooked.")
	}
	

    if( HT_MEMORY == g_Config::g_HookType )
    {
        dlog("Starting memory leak detection.")
		dlog("Hooking memory allocation functions.")
		
		if(sm_pHookMgr->HookMemAllocFuncs())
		{
			dlog("Memory allocation API's hooked.")
		}
    }
    else if( HT_GDI == g_Config::g_HookType )
    {
		dlog("Starting GDI object leak detection.")
		dlog("Hooking GDI object allocation functions.")
    }
    else if( HT_HANDLE == g_Config::g_HookType )
    {
		dlog("Starting Handle leak detection.")
		dlog("Hooking Handle allocation functions.")

		if(sm_pHookMgr->HookHandleAllocFuncs())
		{
			dlog("Handle alloc API's hooked.")
		}
    }
    else
    {
		dlog("Invalid hook type.")
		dlog("Setting Handle API hooks.")

		g_Config::g_HookType = HT_HANDLE;
        if(sm_pHookMgr->HookHandleAllocFuncs())
		{
			dlog("Handle alloc API's hooked.")
		}
    }
 
	dlog_v("Hooked API count",sm_pHookMgr->HookedFunctionCount())
    
    HANDLE hDumpEvent	 = CreateEvent( 0, TRUE, FALSE, DUMP_EVENT );
    HANDLE hMemRestEvent = CreateEvent( 0, TRUE, FALSE, CLEAR_LEAKS );
    
    HANDLE hArray[2] = { hDumpEvent, hMemRestEvent };

    g_Config::g_bHooked = true; 
    while( 1 )
    {
        DWORD dwWait = WaitForMultipleObjects( 2, hArray, FALSE, INFINITE );
        CSingleLock lockObj( &g_Config::SyncObj, TRUE );
        g_Config::g_bTrack = false;
        lockObj.Unlock();
        if( dwWait == WAIT_OBJECT_0 )
        {
			dlog("Dumping leak trace")
            ResetEvent( hDumpEvent );
            DumpLeak();
			dlog("Leak trace dumped")
        }
        else if( dwWait == WAIT_OBJECT_0 + 1)
        {
            dlog("Clearing leak map")
			lockObj.Lock();
            EmptyLeakMap();
            lockObj.Unlock();
            ResetEvent( hMemRestEvent );
            
        }
        else
        {
			dlog("Exiting")
			break;
        }
        lockObj.Lock();
        g_Config::g_bTrack = true;
        lockObj.Unlock();
    }
	
    CloseHandle( hDumpEvent );
    CloseHandle( hMemRestEvent );
    return 0;
}

// CParasiteApp initialization

BOOL CParasiteApp::InitInstance()
{
	
	HMODULE hHookDll = GetModuleHandleA( _T("parasite.dll"));
    if( GetModuleFileNameA( hHookDll, g_Config::sDllPath.GetBuffer( MAX_PATH), MAX_PATH ))
    {
        g_Config::sDllPath.ReleaseBuffer();
        int nPos = g_Config::sDllPath.ReverseFind('\\');
        if( 0 < nPos )
        {
            g_Config::sDllPath = g_Config::sDllPath.Left( nPos + 1 );
        }
    }

	char* pDoLog = getenv ("WINVAL_LOG");
	if(pDoLog!=NULL)
		g_bLog = atoi(pDoLog);


	dlog("Parasite injected")
	HANDLE hThread = ::CreateThread(0,0,DumpController,this,0,0);
	CloseHandle(hThread);
	return CWinApp::InitInstance();
}

bool CParasiteApp::Cleanup()
{
	dlog("Cleanup")
	dlog("Unhooking all functions")
	sm_pHookMgr->UnHookAllFuncs();

	
	if(sm_pHookMgr)
		delete sm_pHookMgr;

    g_Config::g_bHooked = false;
    EmptyLeakMap();
	
	return true;
}
int CParasiteApp::ExitInstance() 
{
    try
    {   
        dlog("DLL_PROCESS_DETACH")

		// Restore the hooks
		Cleanup();
    }
    catch (...)
    {
        
    }
    return CWinApp::ExitInstance();
}

CString GetGDIHandleType( HGDIOBJ hObj, SIZE_T nType )
{
    CString csType;
    if( nType == IMAGE_ICON ) 
    {
        csType = _T("Icon");
        return csType;
    }
    else if( nType == IMAGE_CURSOR )
    {
        csType = _T("Cursor");
        return csType;
    }

    DWORD dwType = GetObjectType( hObj );
    switch( dwType )
    {
    case OBJ_BITMAP:
        csType = _T("Bitmap");
        break;
    case OBJ_BRUSH:
        csType = _T("Brush");
        break;
    case OBJ_COLORSPACE:
        csType = _T("Color space");
        break;
    case OBJ_DC:
        csType = _T( "Device context");
        break;
    case OBJ_ENHMETADC:
        csType = _T("Enhanced metafile DC");
        break;
    case OBJ_ENHMETAFILE:
        csType = _T("Enhanced metafile");
        break;
    case OBJ_EXTPEN:
        csType = _T("Extended pen");
        break;
    case OBJ_FONT:
        csType = _T("Font");
        break;
    case OBJ_MEMDC:
        csType = _T("Memory DC");
        break;
    case OBJ_METAFILE:
        csType = _T("Metafile");
        break;
    case OBJ_METADC:
        csType = _T("Metafile DC");
        break;
    case OBJ_PAL:
        csType = _T("Palette");
        break;
    case OBJ_PEN:
        csType = _T("Pen");
        break;
    case OBJ_REGION:
        csType = _T("Region");
        break;
    default:
        csType = _T("Unknown");
        break;
    }
    return csType;

}

CString GetHandleType( HGDIOBJ hObj, SIZE_T nType )
{
    CString csType;
    switch( nType)
    {
    case TYPE_EVENT_HANDLE:
        csType = _T("Event HANDLE");
        break;
    case TYPE_MUTEX_HANDLE:
        csType = _T("Mutex HANDLE");
        break;
    case TYPE_SEMAPHOR_HANDLE:
        csType = _T("Semaphore HANDLE");
        break;
    case TYPE_CRITICAL_SECTION_HANDLE:
        csType = _T("Critical section object");
        break;
    case TYPE_WAIT_TIMER_HANDLE:
        csType = _T("Waitable timer HANDLE");
        break;
    case TYPE_FILE_HANDLE:
        csType = _T("File HANDLE");
        break;
    case TYPE_TOKEN_HANDLE:
        csType = _T("Token HANDLE");
        break;
    case TYPE_CHANGE_NOFICATION_HANDLE:
        csType = _T("Change Notification HANDLE");
        break;
    case TYPE_MEMEORY_MAPPED_FILE_HANDLE:
        csType = _T("Memory mapped file HANDLE");
        break;
    case TYPE_MEMORY_HANDLE:
        csType = _T("Memory HANDLE");
        break;
    case TYPE_PROCESS_HANDLE:
        csType = _T("Process HANDLE");
        break;
    case TYPE_THREAD_HANDLE:
        csType = _T("Thread HANDLE");
        break;
    case TYPE_JOB_HANDLE:
        csType = _T("Job HANDLE");
        break;
    case TYPE_MAIL_SLOT_HANDLE:
        csType = _T("Mail Slot HANDLE");
        break;
    case TYPE_PIPE_HANDLE:
        csType = _T("Pipe HANDLE");
        break;
    case TYPE_REGISTRY_HANDLE:
        csType = _T("Registry HANDLE");
        break;
    case TYPE_TIMER_QUEUE:
        csType = _T("Timer queue HANDLE");
        break;
    default:
        csType = _T("unknown type");
        break;
    }
    return csType;
}

void DumpLeak()
{
	if( 0 == g_Config::m_MemMap.size())
    {
        AfxMessageBox( "No leak detected" );
        return;
    }
    CFileDialog dlg( FALSE, _T(".txt"), _T("Dump.txt"));
    if( IDOK != dlg.DoModal())
    {
        return;
    }

	DumpLeakToFile(dlg.GetPathName());
}
void DumpLeakToFile(CString fileName)
{
	CFile File;
    if( !File.Open( fileName, CFile::modeCreate|CFile::modeWrite ))
    {
        AfxMessageBox( "Failed to create file" );
        return;
    }
    HANDLE hProcess = GetCurrentProcess();
    DWORD64 dwDisplacement;

    BYTE SymBol[ sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN ] = {0};
    SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)SymBol;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = STACKWALK_MAX_NAMELEN;

    IMAGEHLP_LINE64 Line = {0};
    Line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );

    MEM_INFO stInfo;
    LPVOID lMem;
	map<LPVOID,MEM_INFO>::iterator pos = g_Config::m_MemMap.begin();
	while( pos!=g_Config::m_MemMap.end() )
    {
		lMem = pos->first;
		stInfo = pos->second;
		CString csLength;
        if( HT_MEMORY == g_Config::g_HookType )
        {
            csLength.Format( "-->Bytes allocated -- %d\r\n\r\n", stInfo.nMemSize );
        }
        else if( HT_GDI == g_Config::g_HookType )
        {
            CString csType = GetGDIHandleType( lMem, stInfo.nMemSize );
            csLength.Format( "-->%s -- 0x%x\r\n\r\n", csType, lMem );
            //csLength.Format( "Bytes allocated -- %d\r\n\r\n", stInfo.nMemSize );
        }
        else if( HT_HANDLE == g_Config::g_HookType )
        {
            CString csType = GetHandleType( lMem, stInfo.nMemSize );
            csLength.Format( "-->%s -- 0x%x\r\n\r\n", csType, lMem );
        }
        
        File.Write( csLength, csLength.GetLength());
		int nCount = (int)stInfo.parCallStack.size();
        for( int nIdx =1;nIdx< nCount;nIdx++ )
        {
			DWORD64 dwOffset = stInfo.parCallStack[nIdx];

            CString cs;
            CString csFunctionName;
            
            if( !SymFromAddr( hProcess, dwOffset, &dwDisplacement, pSymbol ))
            {
                /*csFunctionName = "Unknown";*/                
                MEMORY_BASIC_INFORMATION stMemoryInfo;                 
                HMODULE hModule = 0;
                // Get the information about the virtual address space of the calling process
                if( VirtualQuery( (void*)dwOffset, &stMemoryInfo, sizeof( stMemoryInfo ))
                                                                            != 0 )
                {            
                    hModule = reinterpret_cast<HMODULE>( 
                                                    stMemoryInfo.AllocationBase);
                }
                // Get the exe's or ddl's file name
                DWORD dwFileNameLength = GetModuleFileName( hModule, csFunctionName.GetBuffer( MAX_PATH ), MAX_PATH );
                csFunctionName.ReleaseBuffer();
            }
            else
            {
                csFunctionName = pSymbol->Name;
            }
            DWORD dwLine = 0;
            if( SymGetLineFromAddr64( hProcess, dwOffset, &dwLine, &Line ))
            {
                CString csFormatString;
                int n = 40 - csFunctionName.GetLength();
                csFormatString.Format( _T("%s%d%s"), _T("%s%"), n, _T("s%s(%d)"));
                cs.Format( csFormatString, csFunctionName, _T(" "), Line.FileName, Line.LineNumber );
            }
            else
            {
                cs = csFunctionName;
            }
//            CString cs = (*(stInfo.parCallStack)).GetAt( nIdx);
            cs += _T("\r\n");
            File.Write( cs, cs.GetLength());
        }        
        TCHAR tc[] = {"------------------------------------------------\r\n\r\n\r\n\r\n"};
        File.Write( tc, sizeof(tc) - 1);
		pos++;
    }
    File.Close();
}

void EmptyLeakMap()
{
    map<LPVOID,MEM_INFO>::iterator pos = g_Config::m_MemMap.begin();
	while( pos!=g_Config::m_MemMap.end() )
	{
		LPVOID lpMem = pos->first;
		MEM_INFO stInfo = pos->second;
        
        //delete stInfo.parCallStack;
		stInfo.parCallStack.clear();
        stInfo.parCallStack.~STACK_ARRAY();
    }
	g_Config::m_MemMap.clear();
}


void CopyStack(LPVOID lpExisting, LPVOID lpNew, int nType )
{
    CSingleLock lockObj( &g_Config::SyncObj, TRUE );
    if( g_Config::g_bHooked && g_Config::g_bTrack )
    {
        MEM_INFO stInfo;
        if( g_Config::m_MemMap.find(lpExisting)!=g_Config::m_MemMap.end())
        {
			stInfo = g_Config::m_MemMap[lpExisting];
            MEM_INFO stNew;
			stNew.nMemSize = nType;
		}

    }
}

/////////////////////////////////////////////////////////////////////////////////////

PARASITE_DLL_EXPORT bool IsLeakDetected( void* pObject )
{
    try
    {
        if( !pObject )
        {
            return false;
        }
        MEM_INFO stInfo;
        if( g_Config::m_MemMap.find(pObject)!=g_Config::m_MemMap.end())
        {
			stInfo = g_Config::m_MemMap[pObject];
            return true;
        }
    }
    catch(...)
    {
    }
    return false;
}

PARASITE_DLL_EXPORT void SetHookType(HOOK_TYPE_e eType )
{
    g_Config::g_HookType = eType;
}