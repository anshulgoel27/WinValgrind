#include "stdafx.h"
#include <Dbghelp.h>
#include <Shlwapi.h>
#include "parasite.h"
#include "ConfigLoader.h"
#include <algorithm>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;

bool CConfigLoader::LoadConfig()
{
	pugi::xml_document doc;

	m_csDllPath = g_Config::sDllPath;

   dlog("Loading config.xml...")
   if(!doc.load_file(m_csDllPath + "config.xml")) 
   {
	   dlog("Failed to load config.xml. Default config loaded.")

	   return LoadDLL();
   }

    pugi::xml_node pdb = doc.child("WinValgrind").child("PDBInfo");
	pugi::xml_node pdbinfo = pdb.child("PDBInfo1");
	int index = 2;
	
	do
	{
		if(pdbinfo==NULL)
			break;
		m_symbolVec.push_back(pdbinfo.attribute("path").value());
		std::string nextPath = "PDBInfo" + std::to_string (index++);
		pdbinfo = pdb.child(nextPath.c_str());

	}while(pdbinfo!=NULL);

	
	if(!LoadDLL()) return false;
	
	string monType = doc.child("WinValgrind").child("MonitorType").text().get();
	std::transform(monType.begin(), monType.end(),monType.begin(), ::toupper);
	
	if(monType.compare("MEMORY") == 0)
	{
		g_Config::g_HookType = HT_MEMORY;
	}
	else if (monType.compare("GDI") == 0)
	{
		g_Config::g_HookType = HT_GDI;
	}
	else
	{
		g_Config::g_HookType = HT_HANDLE;
	}

	return true;
}

bool CConfigLoader::LoadDLL()
{
	dlog("loading symbols...")
	HMODULE hModule = GetModuleHandle( _T("dbghelp.dll"));
    SymRefreshModuleListDef pSymRefreshModuleList;
    
    if( hModule )
    {
        pSymRefreshModuleList = (SymRefreshModuleListDef)GetProcAddress( hModule, _T("SymRefreshModuleList"));
        CString csLoadedDll;
        GetModuleFileName( hModule, csLoadedDll.GetBuffer(MAX_PATH), MAX_PATH );
        csLoadedDll.ReleaseBuffer();
        if( !pSymRefreshModuleList )
        {
            dlog( "Your application has already loaded dbghelp.dll from " + csLoadedDll + "\n\nFor acqurate results, replace this dll with the latest version of dbghelp.dll coming with \"Debugging tools for windows\" or with the dll the application folder of this utility.");
        }
        else
        {
            dlog( "Your application has already loaded dbghelp.dll from " + csLoadedDll + " Please confirm that the symsrv.dll exists in th same folder. Otherwise symbol server will not work.");
        }
        
    }
    else 
    {
		dlog("loading dbghelp.dll...")

        m_csDllPath += _T("dbghelp.dll");
        
        hModule = LoadLibrary( m_csDllPath );
        if( !hModule)
        {
			dlog("loaded dbghelp.dll from system path")

            hModule = LoadLibrary(  _T("dbghelp.dll"));
            pSymRefreshModuleList = (SymRefreshModuleListDef)GetProcAddress( hModule, _T("SymRefreshModuleList"));
            if( !pSymRefreshModuleList )
            {
				dlog( "Failed to load the dbghelp.dll from the local directory\n\n The application will continue with the default dbghelp.dll. But some feature may be unavailable.")
            }
            
        }
        else
        {
			dlog(m_csDllPath+" loaded")
			
            pSymRefreshModuleList = (SymRefreshModuleListDef)GetProcAddress( hModule, _T("SymRefreshModuleList"));
        }
        
    }
	int nCount = m_symbolVec.size();
    m_csPath.Empty();
    for( int nId = 0;nId < nCount; nId++ )
    {
			CString csItem = m_symbolVec[nId].c_str();
            m_csPath += csItem + _T(";");            
    }

	dlog("symbol paths from config.xml "+m_csPath)

    SymCleanup(GetCurrentProcess());
    CString csWholePath = m_csPath;
    csWholePath.TrimRight( ';' );

	dlog("Going to load symbols from path "+csWholePath)

    DWORD dwOption = SymGetOptions();
    dwOption |= SYMOPT_CASE_INSENSITIVE|SYMOPT_LOAD_LINES|SYMOPT_FAIL_CRITICAL_ERRORS|
                SYMOPT_LOAD_ANYTHING|SYMOPT_UNDNAME;

    SymSetOptions( dwOption );
    CWinThread* pThread = AfxBeginThread( ThreadEntry, this );
    HANDLE hThread = pThread->m_hThread;
    
    
    BOOL fInvadeProcess = (0 == pSymRefreshModuleList)?TRUE:FALSE;
	
	if(fInvadeProcess)
	{
		dlog("symbol modules will be loaded for the process")
	}
    
    BOOL bRet = SymInitialize(GetCurrentProcess(), (LPTSTR)csWholePath.operator LPCTSTR() , fInvadeProcess );
    SymRegisterCallback64( GetCurrentProcess(),SymRegisterCallbackProc64,(ULONG64 )this );

    while( !m_ProgressDlg.m_hWnd )// wait untill the dialog is created
    {
        Sleep( 50 );
    }
	
    if( pSymRefreshModuleList )
    {
        dlog("refresing module symbol list")
		pSymRefreshModuleList( GetCurrentProcess());
    }
    
    m_ProgressDlg.SendMessage( WM_CLOSE );
    WaitForSingleObject( hThread, 10000 );
	return true;
}

BOOL CALLBACK CConfigLoader::SymRegisterCallbackProc64(HANDLE hProcess,
                                        ULONG ActionCode,
                                        ULONG64 CallbackData,
                                        ULONG64 UserContext
                                        )

{
    if( CBA_DEFERRED_SYMBOL_LOAD_START == ActionCode )
    {
        PIMAGEHLP_DEFERRED_SYMBOL_LOAD64 pSybolLoadInfo = (PIMAGEHLP_DEFERRED_SYMBOL_LOAD64)CallbackData;
        CConfigLoader* pDlg = (CConfigLoader*)UserContext;
        CString csLoadtext = _T("Loading symbol for file: ");
        csLoadtext += pSybolLoadInfo->FileName;

		dlog(csLoadtext)
        
		if (pDlg->m_ProgressDlg)
            pDlg->m_ProgressDlg.SetDlgItemText( IDC_LOAD_INFO, csLoadtext );
    }
    return FALSE;
}
UINT __cdecl CConfigLoader::ThreadEntry( LPVOID pParam )
{
    CConfigLoader* pDlg  = (CConfigLoader*)pParam;
    pDlg->ShowWaitDialog();
    return 0;
}

void CConfigLoader::ShowWaitDialog()
{
    m_ProgressDlg.DoModal();
}