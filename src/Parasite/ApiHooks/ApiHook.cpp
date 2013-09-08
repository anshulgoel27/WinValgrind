#include "..\stdafx.h"
#include "ApiHook.h"
#include "..\common.h"
#include "..\SysUtils.h"
#include "..\LockMgr.h"



//---------------------------------------------------------------------------
//
// File scope constants and typedefs
//
//---------------------------------------------------------------------------
typedef struct 
{
	char szCalleeModName[MAX_PATH]; 
	char szFuncName[MAX_PATH];	
} API_FUNC_ID;

const API_FUNC_ID MANDATORY_API_FUNCS[] =
{
	{"Kernel32.dll", "LoadLibraryA"},
	{"Kernel32.dll", "LoadLibraryW"},
	{"Kernel32.dll", "LoadLibraryExA"},
	{"Kernel32.dll", "LoadLibraryExW"},
	{"Kernel32.dll", "GetProcAddress"}
};

// This macro evaluates to the number of elements in MANDATORY_API_FUNCS
#define NUMBER_OF_MANDATORY_API_FUNCS (sizeof(MANDATORY_API_FUNCS) / sizeof(MANDATORY_API_FUNCS[0])) 

//---------------------------------------------------------------------------
//
// Static members
//
//---------------------------------------------------------------------------

CHookedFunctions* CApiHookMgr::sm_pHookedFunctions = NULL;
CCSWrapper        CApiHookMgr::sm_CritSec;

//---------------------------------------------------------------------------
// CApiHookMgr
// 
// Ctor
//---------------------------------------------------------------------------
CApiHookMgr::CApiHookMgr()
{
	//
	// Obtain the handle to the DLL which code executes
	//
	m_hmodThisInstance   = ModuleFromAddress(CApiHookMgr::MyGetProcAddress);
	//
	// No system functions have been hooked up yet
	//
	m_bSystemFuncsHooked = FALSE;

	m_bHandleFuncsHooked = FALSE;
	//
	// Create an instance of the map container
	//
	sm_pHookedFunctions  = new CHookedFunctions(this); 
}

//---------------------------------------------------------------------------
// ~CApiHookMgr
// 
// Dtor
//---------------------------------------------------------------------------

CApiHookMgr::~CApiHookMgr()
{
	UnHookAllFuncs();
	delete sm_pHookedFunctions;
}

//---------------------------------------------------------------------------
// HookSystemFuncs
// 
// Hook all needed system functions in order to trap loading libraries
//---------------------------------------------------------------------------
BOOL CApiHookMgr::HookSystemFuncs()
{
	BOOL bResult;

	if (TRUE != m_bSystemFuncsHooked)
	{
		bResult = HookImport(
			"Kernel32.dll", 
			"LoadLibraryA", 
			(PROC) CApiHookMgr::MyLoadLibraryA
			);
		bResult = HookImport(
			"Kernel32.dll", 
			"LoadLibraryW",
			(PROC) CApiHookMgr::MyLoadLibraryW
			) || bResult;
		bResult = HookImport(
			"Kernel32.dll", 
			"LoadLibraryExA",
			(PROC)CApiHookMgr::MyLoadLibraryExA
			) || bResult;
		bResult = HookImport(
			"Kernel32.dll", 
			"LoadLibraryExW",
			(PROC) CApiHookMgr::MyLoadLibraryExW
			) || bResult;
		bResult = HookImport(
			"Kernel32.dll", 
			"GetProcAddress",
			(PROC) CApiHookMgr::MyGetProcAddress
			) || bResult;
		m_bSystemFuncsHooked = bResult;
	} // if

	return m_bSystemFuncsHooked;
}

BOOL CApiHookMgr::HookHandleAllocFuncs()
{
	if (TRUE != m_bHandleFuncsHooked)
	{
		REGISTER_HOOK(CreateEventA,Kernel32);
		REGISTER_HOOK(CreateEventW,Kernel32 );
		REGISTER_HOOK(CreateEventExA,Kernel32 );
		REGISTER_HOOK(CreateEventExW,Kernel32 );
		REGISTER_HOOK(OpenEventA,Kernel32 );
		REGISTER_HOOK(OpenEventW,Kernel32 );
		REGISTER_HOOK(CreateMutexA,Kernel32 );
		REGISTER_HOOK(CreateMutexW,Kernel32 );
		REGISTER_HOOK(CreateMutexExA,Kernel32 );
		REGISTER_HOOK(CreateMutexExW,Kernel32 );
		REGISTER_HOOK(OpenMutexA,Kernel32 );
		REGISTER_HOOK(OpenMutexW,Kernel32 );
		REGISTER_HOOK(CreateSemaphoreA,Kernel32 );
		REGISTER_HOOK(CreateSemaphoreW,Kernel32 );
		REGISTER_HOOK(CreateSemaphoreExA,Kernel32 );
		REGISTER_HOOK(CreateSemaphoreExW,Kernel32 );
		REGISTER_HOOK(OpenSemaphoreA,Kernel32 );
		REGISTER_HOOK(OpenSemaphoreW,Kernel32 );
		REGISTER_HOOK(CreateWaitableTimerA,Kernel32 );
		REGISTER_HOOK(CreateWaitableTimerW,Kernel32 );
		REGISTER_HOOK(CreateWaitableTimerExA,Kernel32 );
		REGISTER_HOOK(CreateWaitableTimerExW,Kernel32 );
		REGISTER_HOOK(OpenWaitableTimerA,Kernel32 );
		REGISTER_HOOK(OpenWaitableTimerW,Kernel32 );
		REGISTER_HOOK(CreateFileA,Kernel32 );
		REGISTER_HOOK(CreateFileW,Kernel32 );
		REGISTER_HOOK(CreateFileTransactedA,Kernel32 );
		REGISTER_HOOK(CreateFileTransactedW,Kernel32 );
		REGISTER_HOOK(FindFirstFileA,Kernel32 );
		REGISTER_HOOK(FindFirstFileW,Kernel32 );
		REGISTER_HOOK(FindFirstFileExA,Kernel32 );
		REGISTER_HOOK(FindFirstFileExW,Kernel32 );
		REGISTER_HOOK(FindFirstFileExW,Kernel32 );
		REGISTER_HOOK(FindFirstFileNameW,Kernel32 );
		REGISTER_HOOK(FindFirstFileTransactedA,Kernel32 );
		REGISTER_HOOK(FindFirstFileTransactedW,Kernel32 );
		REGISTER_HOOK(FindFirstStreamTransactedW,Kernel32 );
		REGISTER_HOOK(FindFirstStreamW,Kernel32 );
		REGISTER_HOOK(FindClose,Kernel32 );
		REGISTER_HOOK(OpenFileById,Kernel32 );
		REGISTER_HOOK(ReOpenFile,Kernel32 );
		REGISTER_HOOK(CreateIoCompletionPort,Kernel32 );
		REGISTER_HOOK(CreateRestrictedToken,Advapi32 );
		REGISTER_HOOK(DuplicateToken,Advapi32 );
		REGISTER_HOOK(DuplicateTokenEx,Advapi32 );
		REGISTER_HOOK(OpenProcessToken,Advapi32 );
		REGISTER_HOOK(OpenThreadToken,Advapi32 );
		REGISTER_HOOK(FindFirstChangeNotificationA,Kernel32 );
		REGISTER_HOOK(FindFirstChangeNotificationW,Kernel32 );
		REGISTER_HOOK(FindCloseChangeNotification,Kernel32 );
		REGISTER_HOOK(CreateMemoryResourceNotification,Kernel32 );
		REGISTER_HOOK(CreateFileMappingA,Kernel32 );
		REGISTER_HOOK(CreateFileMappingW,Kernel32 );
		REGISTER_HOOK(CreateFileMappingNumaA,Kernel32 );
		REGISTER_HOOK(CreateFileMappingNumaW,Kernel32 );
		REGISTER_HOOK(OpenFileMappingA,Kernel32 );
		REGISTER_HOOK(OpenFileMappingW,Kernel32 );
		REGISTER_HOOK(HeapCreate,Kernel32 );
		REGISTER_HOOK(HeapDestroy,Kernel32 );
		REGISTER_HOOK(GlobalAlloc,Kernel32 );
		REGISTER_HOOK(GlobalReAlloc,Kernel32 );
		REGISTER_HOOK(GlobalFree,Kernel32 );
		REGISTER_HOOK(LocalAlloc,Kernel32 );
		REGISTER_HOOK(LocalReAlloc,Kernel32 );
		REGISTER_HOOK(LocalFree,Kernel32 );
		REGISTER_HOOK(CreateProcessA,Kernel32 );
		REGISTER_HOOK(CreateProcessW,Kernel32 );
		REGISTER_HOOK(CreateProcessAsUserA,Advapi32 );
		REGISTER_HOOK(CreateProcessAsUserW,Advapi32 );
		REGISTER_HOOK(CreateProcessWithLogonW,Advapi32 );
		REGISTER_HOOK(CreateProcessWithTokenW,Advapi32 );
		REGISTER_HOOK(OpenProcess,Kernel32 );
		REGISTER_HOOK(CreateThread,Kernel32 );
		REGISTER_HOOK(CreateRemoteThread,Kernel32 );
		REGISTER_HOOK(OpenThread,Kernel32 );
		REGISTER_HOOK(CreateJobObjectA,Kernel32 );
		REGISTER_HOOK(CreateJobObjectW,Kernel32 );
		REGISTER_HOOK(CreateMailslotA,Kernel32 );
		REGISTER_HOOK(CreateMailslotW,Kernel32 );
		REGISTER_HOOK(CreatePipe,Kernel32 );
		REGISTER_HOOK(CreateNamedPipeA,Kernel32 );
		REGISTER_HOOK(CreateNamedPipeW,Kernel32 );
		REGISTER_HOOK(RegCreateKeyExA,Advapi32 );
		REGISTER_HOOK(RegCreateKeyExW,Advapi32 );
		REGISTER_HOOK(RegCreateKeyTransactedA,Kernel32 );
		REGISTER_HOOK(RegCreateKeyTransactedW,Kernel32 );
		REGISTER_HOOK(RegOpenCurrentUser,Kernel32 );
		REGISTER_HOOK(RegOpenKeyA,Kernel32 );
		REGISTER_HOOK(RegOpenKeyW,Kernel32 );
		REGISTER_HOOK(RegOpenKeyExA,Kernel32 );
		REGISTER_HOOK(RegOpenKeyExW,Kernel32 );
		REGISTER_HOOK(RegOpenKeyTransactedA,Kernel32 );
		REGISTER_HOOK(RegOpenKeyTransactedW,Kernel32 );
		REGISTER_HOOK(RegOpenUserClassesRoot,Kernel32 );
		REGISTER_HOOK(RegCreateKeyA,Kernel32 );
		REGISTER_HOOK(RegCreateKeyW,Kernel32 );
		REGISTER_HOOK(RegCloseKey,Kernel32 );
		REGISTER_HOOK(DuplicateHandle,Kernel32 );
		REGISTER_HOOK(CloseHandle,Kernel32 );

		//////////////////////////////////v3 additions//////////////////////////////////////////////////
		//// Timers
		//REGISTER_HOOK(CreateTimerQueue,Kernel32 );
		//REGISTER_HOOK(CreateTimerQueueTimer,Kernel32 );
		//REGISTER_HOOK(DeleteTimerQueueTimer,Kernel32 );
		//REGISTER_HOOK(DeleteTimerQueueEx,Kernel32 );
		//REGISTER_HOOK(DeleteTimerQueue,Kernel32 );

		//REGISTER_HOOK(InitializeCriticalSection,Kernel32 );
		//REGISTER_HOOK(InitializeCriticalSectionEx,Kernel32 );
		//REGISTER_HOOK(InitializeCriticalSectionAndSpinCount,Kernel32 );
		//REGISTER_HOOK(DeleteCriticalSection,Kernel32 );
		m_bHandleFuncsHooked = TRUE;
	}
	return m_bHandleFuncsHooked;
}


//////////////////////////////////////////////////////////////////////////
// Handle functions
//////////////////////////////////////////////////////////////////////////

HANDLE WINAPI CApiHookMgr::MyGlobalAlloc( UINT uFlags, SIZE_T dwBytes )
{
    HANDLE hHandle =  GlobalAlloc( uFlags,  dwBytes );
    if ( g_Config::g_HookType == HT_MEMORY )
        CreateCallStack(hHandle, dwBytes);
    else
        CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
    return hHandle;
}

HANDLE WINAPI CApiHookMgr::MyGlobalReAlloc( HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags )
{
    HANDLE hHandle =  GlobalReAlloc( hMem, dwBytes, uFlags  );
    if( hHandle )
    {
        if ( g_Config::g_HookType == HT_MEMORY )
            CreateCallStack(hHandle, dwBytes);
        else
            CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
        RemovCallStack( hMem );
    }
    return hHandle;
}

HANDLE WINAPI CApiHookMgr::MyGlobalFree( HGLOBAL hMem )
{
    HANDLE hHandle =  GlobalFree( hMem );
    if ( hHandle == NULL )
        RemovCallStack( hMem );
    return hHandle;

}
HLOCAL WINAPI CApiHookMgr::MyLocalAlloc( UINT uFlags, SIZE_T uBytes )
{
    HLOCAL hHandle =  LocalAlloc( uFlags,  uBytes );
    if ( g_Config::g_HookType == HT_MEMORY )
        CreateCallStack(hHandle, uBytes);
    else
        CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
    return hHandle;
}

HLOCAL WINAPI CApiHookMgr::MyLocalReAlloc( HLOCAL hMem, SIZE_T uBytes, UINT uFlags )
{
    HLOCAL hHandle =  LocalReAlloc( hMem, uBytes, uFlags);
    if( hHandle )
    {
        if ( g_Config::g_HookType == HT_MEMORY )
            CreateCallStack(hHandle, uBytes);
        else
            CreateCallStack(hHandle, TYPE_MEMORY_HANDLE );
        RemovCallStack( hMem );
    }
    return hHandle;
}

HLOCAL WINAPI CApiHookMgr::MyLocalFree(HLOCAL hMem )
{
    HLOCAL hHandle =  LocalFree(hMem );
    if ( hHandle == NULL )
        RemovCallStack( hMem );
    return hHandle;
}


HANDLE WINAPI CApiHookMgr::MyCreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,LPCSTR lpName)
{
	dlog("In MyCreateEventA")
	HANDLE hHandle =  CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateEventW( LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,LPCWSTR lpName)
{
	HANDLE hHandle =  CreateEventW( lpEventAttributes, bManualReset, bInitialState, lpName);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateEventExA( LPSECURITY_ATTRIBUTES lpEventAttributes, LPCSTR lpName, DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateEventExA( lpEventAttributes,  lpName,  dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateEventExW( LPSECURITY_ATTRIBUTES lpEventAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess )
{
    HANDLE hHandle =  CreateEventExW( lpEventAttributes,  lpName,  dwFlags,  dwDesiredAccess );
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenEventA( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
    HANDLE hHandle =  OpenEventA( dwDesiredAccess,  bInheritHandle,  lpName);
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenEventW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName )
{
    HANDLE hHandle =  OpenEventW( dwDesiredAccess,  bInheritHandle,  lpName );
    CreateCallStack( hHandle, TYPE_EVENT_HANDLE );
    return hHandle;
}

HANDLE WINAPI CApiHookMgr::MyCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner, LPCSTR lpName )
{
    HANDLE hHandle =  CreateMutexA(lpMutexAttributes, bInitialOwner,  lpName );
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCWSTR lpName)
{
    HANDLE hHandle =  CreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateMutexExA(LPSECURITY_ATTRIBUTES lpEventAttributes,LPCSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateMutexExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateMutexExW(LPSECURITY_ATTRIBUTES lpEventAttributes,LPCWSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateMutexExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenMutexA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName)
{
    HANDLE hHandle =  OpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenMutexW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName)
{
    HANDLE hHandle =  OpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_MUTEX_HANDLE);
    return hHandle;
}

HANDLE WINAPI CApiHookMgr::MyCreateSemaphoreA( LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,LPCSTR lpName )
{
    HANDLE hHandle =  CreateSemaphoreA( lpSemaphoreAttributes,  lInitialCount,  lMaximumCount, lpName );
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName)
{
    HANDLE hHandle =  CreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateSemaphoreExA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateSemaphoreExA(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateSemaphoreExW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateSemaphoreExW(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenSemaphoreA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName)
{
    HANDLE hHandle =  OpenSemaphoreA(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenSemaphoreW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPWSTR lpName)
{
    HANDLE hHandle =  OpenSemaphoreW(dwDesiredAccess, bInheritHandle, lpName);
    CreateCallStack( hHandle, TYPE_SEMAPHOR_HANDLE );
    return hHandle;
}

HANDLE WINAPI CApiHookMgr::MyCreateWaitableTimerA( LPSECURITY_ATTRIBUTES lpTimerAttributes, BOOL bManualReset, LPCSTR lpTimerName)
{
    HANDLE hHandle =  CreateWaitableTimerA( lpTimerAttributes,  bManualReset,  lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes,BOOL bManualReset,LPCWSTR lpTimerName)
{
    HANDLE hHandle =  CreateWaitableTimerW(lpTimerAttributes, bManualReset, lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateWaitableTimerExA(LPSECURITY_ATTRIBUTES lpTimerAttributes,LPCSTR lpTimerName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateWaitableTimerExA(lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateWaitableTimerExW(LPSECURITY_ATTRIBUTES lpTimerAttributes,LPCWSTR lpTimerName,DWORD dwFlags,DWORD dwDesiredAccess)
{
    HANDLE hHandle =  CreateWaitableTimerExW(lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess); 
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenWaitableTimerA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpTimerName)
{
    HANDLE hHandle =  OpenWaitableTimerA(dwDesiredAccess, bInheritHandle, lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenWaitableTimerW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpTimerName)
{
    HANDLE hHandle =  OpenWaitableTimerW(dwDesiredAccess, bInheritHandle, lpTimerName);
    CreateCallStack( hHandle, TYPE_WAIT_TIMER_HANDLE );
    return hHandle;
}

// file function
HANDLE WINAPI CApiHookMgr::MyCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
    HANDLE hHandle =  CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
    HANDLE hHandle =  CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileTransactedA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile,HANDLE hTransaction,PUSHORT pusMiniVersion,PVOID  lpExtendedParameter)
{
    HANDLE hHandle =  CreateFileTransactedA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion,  lpExtendedParameter);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileTransactedW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile,HANDLE hTransaction,PUSHORT pusMiniVersion,PVOID  lpExtendedParameter )
{
    HANDLE hHandle =  CreateFileTransactedW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction, pusMiniVersion,  lpExtendedParameter );
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileA(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData)
{
    HANDLE hHandle =  FindFirstFileA(lpFileName, lpFindFileData);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileW(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData)
{
    HANDLE hHandle =  FindFirstFileW(lpFileName, lpFindFileData); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileExA(LPCSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags)
{
    HANDLE hHandle =  FindFirstFileExA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileExW(LPCWSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags)
{
    HANDLE hHandle =  FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileNameTransactedW (LPCWSTR lpFileName,DWORD dwFlags,LPDWORD StringLength,PWCHAR LinkName,HANDLE hTransaction)
{
    HANDLE hHandle =  FindFirstFileNameTransactedW (lpFileName, dwFlags, StringLength, LinkName, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileNameW (LPCWSTR lpFileName,DWORD dwFlags,LPDWORD StringLength,PWCHAR LinkName)
{
    HANDLE hHandle =  FindFirstFileNameW (lpFileName, dwFlags, StringLength, LinkName); 
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileTransactedA(LPCSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags,HANDLE hTransaction)
{
    HANDLE hHandle =  FindFirstFileTransactedA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstFileTransactedW(LPCWSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags,HANDLE hTransaction)
{
    HANDLE hHandle =  FindFirstFileTransactedW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstStreamTransactedW(LPCWSTR lpFileName,STREAM_INFO_LEVELS InfoLevel,LPVOID lpFindStreamData,DWORD dwFlags,HANDLE hTransaction)
{
    HANDLE hHandle =  FindFirstStreamTransactedW(lpFileName, InfoLevel, lpFindStreamData, dwFlags, hTransaction);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstStreamW( LPCWSTR lpFileName,STREAM_INFO_LEVELS InfoLevel,LPVOID lpFindStreamData,DWORD dwFlags)
{
    HANDLE hHandle =  FindFirstStreamW( lpFileName, InfoLevel, lpFindStreamData, dwFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
BOOL WINAPI CApiHookMgr::MyFindClose( HANDLE hFindFile)
{
    BOOL bRet  =  FindClose( hFindFile);
    if( bRet )
        RemovCallStack( hFindFile );
    return bRet;
}
HANDLE WINAPI CApiHookMgr::MyOpenFileById(HANDLE hFile,LPFILE_ID_DESCRIPTOR lpFileID,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwFlags)
{
    HANDLE hHandle =  OpenFileById(hFile, lpFileID, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyReOpenFile(HANDLE hOriginalFile,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwFlags)
{
    HANDLE hHandle =  ReOpenFile(hOriginalFile, dwDesiredAccess, dwShareMode, dwFlags);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateIoCompletionPort(HANDLE FileHandle,HANDLE ExistingCompletionPort,ULONG_PTR CompletionKey,DWORD NumberOfConcurrentThreads)
{
    HANDLE hHandle =  CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
    CreateCallStack( hHandle, TYPE_FILE_HANDLE );
    return hHandle;
}

//Authorization function
BOOL   WINAPI CApiHookMgr::MyCreateRestrictedToken(HANDLE ExistingTokenHandle,DWORD Flags,DWORD DisableSidCount,PSID_AND_ATTRIBUTES SidsToDisable,DWORD DeletePrivilegeCount,PLUID_AND_ATTRIBUTES PrivilegesToDelete,DWORD RestrictedSidCount,PSID_AND_ATTRIBUTES SidsToRestrict,PHANDLE NewTokenHandle)
{
    BOOL   bret =  CreateRestrictedToken(ExistingTokenHandle, Flags, DisableSidCount, SidsToDisable, DeletePrivilegeCount, PrivilegesToDelete, RestrictedSidCount, SidsToRestrict, NewTokenHandle);
    if( bret )
        CreateCallStack( *NewTokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyDuplicateToken(HANDLE ExistingTokenHandle,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,PHANDLE DuplicateTokenHandle)
{
    BOOL   bret =  DuplicateToken(ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle);
    if( bret )
        CreateCallStack( *DuplicateTokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyDuplicateTokenEx(HANDLE hExistingToken,DWORD dwDesiredAccess,LPSECURITY_ATTRIBUTES lpTokenAttributes,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,TOKEN_TYPE TokenType,PHANDLE phNewToken)
{
    BOOL   bret =  DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken);
    if( bret )
        CreateCallStack( *phNewToken, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyOpenProcessToken(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle)
{
    BOOL   bret =  OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
    if( bret )
        CreateCallStack( *TokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyOpenThreadToken(HANDLE ThreadHandle,DWORD DesiredAccess,BOOL OpenAsSelf,PHANDLE TokenHandle)
{
    BOOL   bret =  OpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle); 
    if( bret )
        CreateCallStack( *TokenHandle, TYPE_TOKEN_HANDLE );
    return bret;
}

//Directory management
HANDLE WINAPI CApiHookMgr::MyFindFirstChangeNotificationA(LPCSTR lpPathName,BOOL bWatchSubtree,DWORD dwNotifyFilter)
{
    HANDLE hHandle =  FindFirstChangeNotificationA(lpPathName, bWatchSubtree, dwNotifyFilter);
    CreateCallStack( hHandle, TYPE_CHANGE_NOFICATION_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyFindFirstChangeNotificationW(LPCWSTR lpPathName,BOOL bWatchSubtree,DWORD dwNotifyFilter)
{
    HANDLE hHandle =  FindFirstChangeNotificationW(lpPathName, bWatchSubtree, dwNotifyFilter); 
    CreateCallStack( hHandle, TYPE_CHANGE_NOFICATION_HANDLE );
    return hHandle;
}
BOOL   WINAPI CApiHookMgr::MyFindCloseChangeNotification(HANDLE hChangeHandle)
{
    BOOL   bRet =  FindCloseChangeNotification(hChangeHandle); 
    if( bRet )
        RemovCallStack( hChangeHandle );
    return bRet;

}

// File mapping
HANDLE WINAPI CApiHookMgr::MyCreateMemoryResourceNotification( MEMORY_RESOURCE_NOTIFICATION_TYPE NotificationType )
{
    HANDLE hHandle =  CreateMemoryResourceNotification( NotificationType );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName )
{
    HANDLE hHandle =  CreateFileMappingA( hFile,  lpFileMappingAttributes,  flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileMappingW( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName )
{
    HANDLE hHandle =  CreateFileMappingW( hFile, lpFileMappingAttributes, flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileMappingNumaA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName, DWORD nndPreferred )
{
    HANDLE hHandle =  CreateFileMappingNumaA( hFile,  lpFileMappingAttributes,  flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName,  nndPreferred );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateFileMappingNumaW( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName, DWORD nndPreferred )
{
    HANDLE hHandle =  CreateFileMappingNumaW( hFile,  lpFileMappingAttributes,  flProtect,  dwMaximumSizeHigh,  dwMaximumSizeLow,  lpName,  nndPreferred );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenFileMappingA( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName )
{
    HANDLE hHandle =  OpenFileMappingA( dwDesiredAccess,  bInheritHandle,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenFileMappingW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName )
{
    HANDLE hHandle =  OpenFileMappingW( dwDesiredAccess,  bInheritHandle,  lpName );
    CreateCallStack( hHandle, TYPE_MEMEORY_MAPPED_FILE_HANDLE );
    return hHandle;
}

//Memory
HANDLE WINAPI CApiHookMgr::MyHeapCreate( DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize )
{
    HANDLE hHandle =  HeapCreate( flOptions,  dwInitialSize,  dwMaximumSize );
    CreateCallStack( hHandle, TYPE_MEMORY_HANDLE );
    return hHandle;
}
BOOL   WINAPI CApiHookMgr::MyHeapDestroy(HANDLE hHeap )
{
    BOOL   bRet =  HeapDestroy(hHeap );
    if( bRet )
        RemovCallStack( hHeap );
    return bRet;

}

//Process and thread
BOOL   WINAPI CApiHookMgr::MyCreateProcessA( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    BOOL   bret =  CreateProcessA( lpApplicationName,  lpCommandLine,  lpProcessAttributes,  lpThreadAttributes,  bInheritHandles,  dwCreationFlags,  lpEnvironment,  lpCurrentDirectory,  lpStartupInfo,  lpProcessInformation );
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyCreateProcessW( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    BOOL   bret =  CreateProcessW( lpApplicationName,  lpCommandLine,  lpProcessAttributes,  lpThreadAttributes,  bInheritHandles,  dwCreationFlags,  lpEnvironment,  lpCurrentDirectory,  lpStartupInfo,  lpProcessInformation );
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyCreateProcessAsUserA(HANDLE hToken,LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret =  CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyCreateProcessAsUserW(HANDLE hToken,LPWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret =  CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyCreateProcessWithLogonW(LPCWSTR lpUsername,LPCWSTR lpDomain,LPCWSTR lpPassword,DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret =  CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
BOOL   WINAPI CApiHookMgr::MyCreateProcessWithTokenW(HANDLE hToken,DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL   bret =  CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation); 
    if( bret && lpProcessInformation )
    {
        CreateCallStack( lpProcessInformation->hProcess, TYPE_PROCESS_HANDLE );
        CopyStack( lpProcessInformation->hProcess, lpProcessInformation->hThread, TYPE_THREAD_HANDLE );
    }
    return bret;
}
HANDLE WINAPI CApiHookMgr::MyOpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId )
{
    HANDLE hHandle =  OpenProcess( dwDesiredAccess,  bInheritHandle,  dwProcessId );
    CreateCallStack( hHandle, TYPE_PROCESS_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    HANDLE hHandle =  CreateThread( lpThreadAttributes,  dwStackSize,  lpStartAddress,  lpParameter,  dwCreationFlags,  lpThreadId );
    CreateCallStack( hHandle, TYPE_THREAD_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateRemoteThread( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    HANDLE hHandle =  CreateRemoteThread( hProcess,  lpThreadAttributes,  dwStackSize,  lpStartAddress,  lpParameter,  dwCreationFlags,  lpThreadId );
    CreateCallStack( hHandle, TYPE_THREAD_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyOpenThread( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    HANDLE hHandle =  OpenThread( dwDesiredAccess,  bInheritHandle,  dwThreadId );
    CreateCallStack( hHandle, TYPE_THREAD_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateJobObjectA( LPSECURITY_ATTRIBUTES lpJobAttributes, LPCSTR lpName )
{
    HANDLE hHandle =  CreateJobObjectA( lpJobAttributes, lpName );
    CreateCallStack( hHandle, TYPE_JOB_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateJobObjectW( LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName )
{
    HANDLE hHandle =  CreateJobObjectW( lpJobAttributes, lpName );
    CreateCallStack( hHandle, TYPE_JOB_HANDLE );
    return hHandle;
}

// Mail slot
HANDLE WINAPI CApiHookMgr::MyCreateMailslotA( LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle =  CreateMailslotA( lpName,  nMaxMessageSize,  lReadTimeout,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_MAIL_SLOT_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateMailslotW( LPCWSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle =  CreateMailslotW( lpName,  nMaxMessageSize,  lReadTimeout,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_MAIL_SLOT_HANDLE );
    return hHandle;
}

// pipe
BOOL   WINAPI CApiHookMgr::MyCreatePipe( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize )
{
    BOOL   bret =  CreatePipe( hReadPipe,  hWritePipe,  lpPipeAttributes,  nSize ); 
    if( bret )
    {
        CreateCallStack( *hReadPipe, TYPE_PIPE_HANDLE );
        CreateCallStack( *hWritePipe, TYPE_PIPE_HANDLE );
    }
    return bret;
}
HANDLE WINAPI CApiHookMgr::MyCreateNamedPipeA( LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle =  CreateNamedPipeA( lpName,  dwOpenMode,  dwPipeMode,  nMaxInstances,  nOutBufferSize,  nInBufferSize,  nDefaultTimeOut,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_PIPE_HANDLE );
    return hHandle;
}
HANDLE WINAPI CApiHookMgr::MyCreateNamedPipeW( LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    HANDLE hHandle =  CreateNamedPipeW( lpName, dwOpenMode,  dwPipeMode,  nMaxInstances,  nOutBufferSize,  nInBufferSize,  nDefaultTimeOut,  lpSecurityAttributes );
    CreateCallStack( hHandle, TYPE_PIPE_HANDLE );
    return hHandle;
}

//Registry
LSTATUS WINAPI CApiHookMgr::MyRegCreateKeyExA( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition )
{
    LSTATUS hHandle =  RegCreateKeyExA( hKey, lpSubKey,  Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegCreateKeyExW ( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition )
{
    LSTATUS hHandle =  RegCreateKeyExW ( hKey,  lpSubKey,  Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegCreateKeyTransactedA( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle =  RegCreateKeyTransactedA( hKey,  lpSubKey,  Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition, hTransaction,   pExtendedParemeter );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegCreateKeyTransactedW( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle =  RegCreateKeyTransactedW( hKey, lpSubKey, Reserved,  lpClass,  dwOptions,  samDesired,   lpSecurityAttributes,  phkResult,  lpdwDisposition,  hTransaction,   pExtendedParemeter ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenCurrentUser( REGSAM samDesired, PHKEY phkResult )
{
    LSTATUS hHandle =  RegOpenCurrentUser( samDesired,  phkResult ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenKeyA ( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle =  RegOpenKeyA ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenKeyW ( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle =  RegOpenKeyW ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenKeyExA ( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult )
{
    LSTATUS hHandle =  RegOpenKeyExA ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenKeyExW ( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult )
{
    LSTATUS hHandle =  RegOpenKeyExW ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenKeyTransactedA ( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle =  RegOpenKeyTransactedA ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult,  hTransaction,   pExtendedParemeter );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenKeyTransactedW ( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult, HANDLE hTransaction, PVOID  pExtendedParemeter )
{
    LSTATUS hHandle =  RegOpenKeyTransactedW ( hKey,  lpSubKey,  ulOptions,  samDesired,  phkResult,  hTransaction,   pExtendedParemeter );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegOpenUserClassesRoot( HANDLE hToken, DWORD dwOptions, REGSAM samDesired, PHKEY  phkResult )
{
    LSTATUS hHandle =  RegOpenUserClassesRoot( hToken,  dwOptions,  samDesired,   phkResult ); 
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegCreateKeyA ( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle =  RegCreateKeyA ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegCreateKeyW ( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult )
{
    LSTATUS hHandle =  RegCreateKeyW ( hKey,  lpSubKey,  phkResult );
    if( phkResult )
        CreateCallStack( *phkResult, TYPE_REGISTRY_HANDLE );
    return hHandle;
}
LSTATUS WINAPI CApiHookMgr::MyRegCloseKey ( HKEY hKey )
{
    LSTATUS bRet =  RegCloseKey ( hKey ); 
    if( bRet )
        RemovCallStack( hKey );
    return bRet;
}

////////////////////////////////start - v3 additions//////////////////////////////////////////////////
// Timers
HANDLE WINAPI CApiHookMgr::MyCreateTimerQueue(void)
{
    HANDLE hHandle =  CreateTimerQueue();
    if( hHandle )
        CreateCallStack( hHandle, TYPE_TIMER_QUEUE );
    return hHandle;
}

BOOL   WINAPI CApiHookMgr::MyCreateTimerQueueTimer(PHANDLE phNewTimer,HANDLE TimerQueue,WAITORTIMERCALLBACK Callback,PVOID Parameter,DWORD DueTime,DWORD Period,ULONG Flags)
{
    BOOL bRet =  CreateTimerQueueTimer(phNewTimer,TimerQueue,Callback,Parameter,DueTime,Period,Flags);
    if( bRet && phNewTimer && *phNewTimer )
        CreateCallStack( *phNewTimer, TYPE_TIMER_QUEUE );
    return bRet;
}

BOOL   WINAPI CApiHookMgr::MyDeleteTimerQueueTimer(HANDLE TimerQueue,HANDLE Timer,HANDLE CompletionEvent)
{
    BOOL bRet =  DeleteTimerQueueTimer(TimerQueue,Timer,CompletionEvent);
    if( bRet )
        RemovCallStack( Timer );
    return bRet;
}

BOOL   WINAPI CApiHookMgr::MyDeleteTimerQueueEx(HANDLE TimerQueue,HANDLE CompletionEvent)
{
    BOOL bRet =  DeleteTimerQueueEx(TimerQueue,CompletionEvent);
    if( bRet )
        RemovCallStack( TimerQueue );
    return bRet;
}

BOOL WINAPI CApiHookMgr::MyDeleteTimerQueue(HANDLE TimerQueue)
{
    BOOL bRet =  DeleteTimerQueue(TimerQueue);
    if( bRet )
        RemovCallStack( TimerQueue );
    return bRet;
}

//Critical section
void WINAPI CApiHookMgr::MyInitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
{
     InitializeCriticalSection( lpCriticalSection );
    CreateCallStack( lpCriticalSection, TYPE_CRITICAL_SECTION_HANDLE );
}
BOOL WINAPI CApiHookMgr::MyInitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags)
{
    BOOL bRet =  InitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, Flags);
    if( bRet )
        CreateCallStack( lpCriticalSection, TYPE_CRITICAL_SECTION_HANDLE );
    return bRet;
}

BOOL WINAPI CApiHookMgr::MyInitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount)
{
    BOOL bRet =  InitializeCriticalSectionAndSpinCount(lpCriticalSection, dwSpinCount);
    if( bRet )
        CreateCallStack( lpCriticalSection, TYPE_CRITICAL_SECTION_HANDLE );
    return bRet;
}
void WINAPI CApiHookMgr::MyDeleteCriticalSection( LPCRITICAL_SECTION lpCriticalSection)
{
     DeleteCriticalSection(lpCriticalSection);
    RemovCallStack( lpCriticalSection );
    
}

////////////////////////////////end - v3 additions//////////////////////////////////////////////////

BOOL   WINAPI CApiHookMgr::MyDuplicateHandle(HANDLE hSourceProcessHandle,HANDLE hSourceHandle,HANDLE hTargetProcessHandle,LPHANDLE lpTargetHandle,DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwOptions)
{
    BOOL   bret =  DuplicateHandle(hSourceProcessHandle,hSourceHandle,hTargetProcessHandle, lpTargetHandle,dwDesiredAccess,bInheritHandle,dwOptions);
    
    if(DUPLICATE_CLOSE_SOURCE&dwOptions)
    {
        RemovCallStack( hSourceHandle );
    }
    
    if( bret )
        CreateCallStack( *lpTargetHandle, TYPE_UNKNOWN );
    return bret;
}

BOOL   WINAPI CApiHookMgr::MyCloseHandle( HANDLE hObject )
{
    BOOL   bRet =  CloseHandle( hObject );
    if( bRet )
        RemovCallStack( hObject );
    return bRet;

}


//---------------------------------------------------------------------------
// UnHookAllFuncs
// 
// Unhook all functions and restore original ones
//---------------------------------------------------------------------------
void CApiHookMgr::UnHookAllFuncs()
{
	if (TRUE == m_bSystemFuncsHooked)
	{
		CHookedFunction* pHook;
		CHookedFunctions::const_iterator itr;
		for (itr = sm_pHookedFunctions->begin(); 
			itr != sm_pHookedFunctions->end(); 
			++itr)
		{
			pHook = itr->second;
			pHook->UnHookImport();
			delete pHook;
		} // for
		sm_pHookedFunctions->clear();
		m_bSystemFuncsHooked = FALSE;
	} // if
}

//
// Indicates whether there is hooked function
//
BOOL CApiHookMgr::AreThereHookedFunctions()
{
	return (sm_pHookedFunctions->size() > 0);
}


//---------------------------------------------------------------------------
// HookImport
//
// Hook up an API function
//---------------------------------------------------------------------------
BOOL CApiHookMgr::HookImport(
	PCSTR pszCalleeModName, 
	PCSTR pszFuncName, 
	PROC  pfnHook
	)
{
	CLockMgr<CCSWrapper>  lockMgr(sm_CritSec, TRUE);
	
	BOOL                  bResult = FALSE;
	PROC                  pfnOrig = NULL;
	try
	{
		dlog(pszFuncName)
		if (!sm_pHookedFunctions->GetHookedFunction(
				pszCalleeModName, 
				pszFuncName
				))
		{
			pfnOrig = GetProcAddressWindows(
				::GetModuleHandleA(pszCalleeModName),
				pszFuncName
				);
			//
			// It's possible that the requested module is not loaded yet
			// so lets try to load it.
			//
			if (NULL == pfnOrig)
			{
				HMODULE hmod = ::LoadLibraryA(pszCalleeModName);
				if (NULL != hmod)
					pfnOrig = GetProcAddressWindows(
						::GetModuleHandleA(pszCalleeModName),
						pszFuncName
						);
			} // if
			if (NULL != pfnOrig)
				bResult = AddHook(
					pszCalleeModName, 
					pszFuncName, 
					pfnOrig,
					pfnHook
					);
		} // if
	}
	catch(...)
	{

	} // try..catch

	return bResult;
}

//---------------------------------------------------------------------------
// UnHookImport
//
// Restores original API function address in IAT
//---------------------------------------------------------------------------
BOOL CApiHookMgr::UnHookImport(
	PCSTR pszCalleeModName, 
	PCSTR pszFuncName
	)
{
	CLockMgr<CCSWrapper>  lockMgr(sm_CritSec, TRUE);

	BOOL bResult = TRUE;
	try
	{
		bResult = RemoveHook(pszCalleeModName, pszFuncName);
	}
	catch (...)
	{
	}
	return bResult;
}

//---------------------------------------------------------------------------
// AddHook
//
// Add a hook to the internally supported container
//---------------------------------------------------------------------------
BOOL CApiHookMgr::AddHook(
	PCSTR pszCalleeModName, 
	PCSTR pszFuncName, 
	PROC  pfnOrig,
	PROC  pfnHook
	)
{
	BOOL             bResult = FALSE;
	CHookedFunction* pHook   = NULL;

	if (!sm_pHookedFunctions->GetHookedFunction(
			pszCalleeModName, 
			pszFuncName
			))
	{
		pHook = new CHookedFunction(
			sm_pHookedFunctions,
			pszCalleeModName, 
			pszFuncName, 
			pfnOrig,
			pfnHook
			);
		// We must create the hook and insert it in the container
		pHook->HookImport();
		bResult = sm_pHookedFunctions->AddHook(pHook);
	} // if

	return bResult;
}

//---------------------------------------------------------------------------
// RemoveHook
//
// Remove a hook from the internally supported container
//---------------------------------------------------------------------------
BOOL CApiHookMgr::RemoveHook(
	PCSTR pszCalleeModName, 
	PCSTR pszFuncName
	)
{
	BOOL             bResult = FALSE;
	CHookedFunction *pHook   = NULL;

	pHook = sm_pHookedFunctions->GetHookedFunction(
		pszCalleeModName, 
		pszFuncName
		);
	if ( NULL != pHook )
	{
		bResult = pHook->UnHookImport();
		if ( bResult )
		{
			bResult = sm_pHookedFunctions->RemoveHook( pHook );
			if ( bResult )
				delete pHook;
		} // if
	} // if

	return bResult;
}


//---------------------------------------------------------------------------
// HackModuleOnLoad
//
// Used when a DLL is newly loaded after hooking a function
//---------------------------------------------------------------------------
void WINAPI CApiHookMgr::HackModuleOnLoad(HMODULE hmod, DWORD dwFlags)
{
	//
	// If a new module is loaded, just hook it
	//
	if ((hmod != NULL) && ((dwFlags & LOAD_LIBRARY_AS_DATAFILE) == 0)) 
	{
		CLockMgr<CCSWrapper>  lockMgr(sm_CritSec, TRUE);
		
		CHookedFunction* pHook;
		CHookedFunctions::const_iterator itr;
		for (itr = sm_pHookedFunctions->begin(); 
			itr != sm_pHookedFunctions->end(); 
			++itr)
		{
			pHook = itr->second;
			pHook->ReplaceInOneModule(
				pHook->Get_CalleeModName(), 
				pHook->Get_pfnOrig(), 
				pHook->Get_pfnHook(), 
				hmod
				);
		} // for
	} // if
}

//---------------------------------------------------------------------------
//
// System API hooks prototypes
//
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// CApiHookMgr::CApiHookMgr::MyLoadLibraryA
//
// 
//---------------------------------------------------------------------------
HMODULE WINAPI CApiHookMgr::MyLoadLibraryA(PCSTR pszModuleName)
{
	dlog("In MyLoadLibraryA")
	HMODULE hmod = ::LoadLibraryA(pszModuleName);
	HackModuleOnLoad(hmod, 0);

	return hmod;
}

//---------------------------------------------------------------------------
// CApiHookMgr::CApiHookMgr::MyLoadLibraryW
//
// 
//---------------------------------------------------------------------------
HMODULE WINAPI CApiHookMgr::MyLoadLibraryW(PCWSTR pszModuleName)
{
	HMODULE hmod = ::LoadLibraryW(pszModuleName);
	HackModuleOnLoad(hmod, 0);

	return hmod;
}

//---------------------------------------------------------------------------
// CApiHookMgr::CApiHookMgr::MyLoadLibraryExA
//
// 
//---------------------------------------------------------------------------
HMODULE WINAPI CApiHookMgr::MyLoadLibraryExA(
	PCSTR  pszModuleName, 
	HANDLE hFile, 
	DWORD dwFlags)
{
	HMODULE hmod = ::LoadLibraryExA(pszModuleName, hFile, dwFlags);
	HackModuleOnLoad(hmod, 0);

	return hmod;
}

//---------------------------------------------------------------------------
// CApiHookMgr::CApiHookMgr::MyLoadLibraryExW
//
// 
//---------------------------------------------------------------------------
HMODULE WINAPI CApiHookMgr::MyLoadLibraryExW(
	PCWSTR pszModuleName, 
	HANDLE hFile, 
	DWORD dwFlags)
{
	HMODULE hmod = ::LoadLibraryExW(pszModuleName, hFile, dwFlags);
	HackModuleOnLoad(hmod, 0);

	return hmod;
}

//---------------------------------------------------------------------------
// CApiHookMgr::CApiHookMgr::MyGetProcAddress
//
// 
//---------------------------------------------------------------------------
FARPROC WINAPI CApiHookMgr::MyGetProcAddress(HMODULE hmod, PCSTR pszProcName)
{
	// It is possible that multiple threads will call hooked GetProcAddress() 
	// API, therefore we should make it thread safe because it accesses sm_pHookedFunctions 
	// shared container.
	CLockMgr<CCSWrapper>  lockMgr(sm_CritSec, TRUE);
	//
	// Get the original address of the function
	//
	FARPROC pfn = GetProcAddressWindows(hmod, pszProcName);
	//
	// Attempt to locate if the function has been hijacked
	//
	CHookedFunction* pFuncHook = 
		sm_pHookedFunctions->GetHookedFunction(
			hmod, 
			pszProcName
			);

	if (NULL != pFuncHook)
		//
		// The address to return matches an address we want to hook
		// Return the hook function address instead
		//
		pfn = pFuncHook->Get_pfnHook();

	return pfn;
}

//---------------------------------------------------------------------------
// GetProcAddressWindows
//
// Returns original address of the API function
//---------------------------------------------------------------------------
FARPROC WINAPI CApiHookMgr::GetProcAddressWindows(HMODULE hmod, PCSTR pszProcName)
{
	return ::GetProcAddress(hmod, pszProcName);
}




//---------------------------------------------------------------------------
//
// class CHookedFunction
//  
//---------------------------------------------------------------------------

//
// The highest private memory address (used for Windows 9x only)
//
PVOID CHookedFunction::sm_pvMaxAppAddr = NULL;
//
// The PUSH opcode on x86 platforms
//
const BYTE cPushOpCode = 0x68;   

//---------------------------------------------------------------------------
// CHookedFunction
//  
//
//---------------------------------------------------------------------------
CHookedFunction::CHookedFunction(
	CHookedFunctions* pHookedFunctions,
	PCSTR             pszCalleeModName, 
	PCSTR             pszFuncName, 
	PROC              pfnOrig,
	PROC              pfnHook
	):
	m_pHookedFunctions(pHookedFunctions),
	m_bHooked(FALSE),
	m_pfnOrig(pfnOrig),
	m_pfnHook(pfnHook)
{
	strcpy(m_szCalleeModName, pszCalleeModName); 
	strcpy(m_szFuncName, pszFuncName);	

	if (sm_pvMaxAppAddr == NULL) 
	{
		//
		// Functions with address above lpMaximumApplicationAddress require
		// special processing (Windows 9x only)
		//
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		sm_pvMaxAppAddr = si.lpMaximumApplicationAddress;
	} // if
   
	if (m_pfnOrig > sm_pvMaxAppAddr) 
	{
		//
		// The address is in a shared DLL; the address needs fixing up 
		//
		PBYTE pb = (PBYTE) m_pfnOrig;
		if (pb[0] == cPushOpCode) 
		{
			//
			// Skip over the PUSH op code and grab the real address
			//
			PVOID pv = * (PVOID*) &pb[1];
			m_pfnOrig = (PROC) pv;
		} // if
	} // if
}


//---------------------------------------------------------------------------
// ~CHookedFunction
//  
//
//---------------------------------------------------------------------------
CHookedFunction::~CHookedFunction()
{
	UnHookImport();
}


PCSTR CHookedFunction::Get_CalleeModName() const
{
	return const_cast<PCSTR>(m_szCalleeModName);
}

PCSTR CHookedFunction::Get_FuncName() const
{
	return const_cast<PCSTR>(m_szFuncName);
}

PROC CHookedFunction::Get_pfnHook() const
{
	return m_pfnHook;
}

PROC CHookedFunction::Get_pfnOrig() const
{
	return m_pfnOrig;
}

//---------------------------------------------------------------------------
// HookImport
//  
// Set up a new hook function
//---------------------------------------------------------------------------
BOOL CHookedFunction::HookImport()
{
	m_bHooked = DoHook(TRUE, m_pfnOrig, m_pfnHook);
	return m_bHooked;
}

//---------------------------------------------------------------------------
// UnHookImport
//  
// Restore the original API handler
//---------------------------------------------------------------------------
BOOL CHookedFunction::UnHookImport()
{
	if (m_bHooked)
		m_bHooked = !DoHook(FALSE, m_pfnHook, m_pfnOrig);
	return !m_bHooked;
}

//---------------------------------------------------------------------------
// ReplaceInAllModules
//  
// Replace the address of a imported function entry  in all modules
//---------------------------------------------------------------------------
BOOL CHookedFunction::ReplaceInAllModules(
	BOOL  bHookOrRestore,
	PCSTR pszCalleeModName, 
	PROC  pfnCurrent, 
	PROC  pfnNew
	) 
{
	BOOL bResult = FALSE;

	if ((NULL != pfnCurrent) && (NULL != pfnNew))
	{
		BOOL                bReplace  = FALSE;
		CExeModuleInstance  *pProcess = NULL;
		CTaskManager        taskManager; 
		CModuleInstance     *pModule;
		//
		// Retrieves information about current process and modules. 
		// The taskManager dynamically decides whether to use ToolHelp 
		// library or PSAPI
		//
		taskManager.PopulateProcess(::GetCurrentProcessId(), TRUE);
		pProcess = taskManager.GetProcessById(::GetCurrentProcessId());
		if (NULL != pProcess)
		{
			// Enumerates all modules loaded by (pProcess) process
			for (DWORD i = 0; i < pProcess->GetModuleCount(); i++)
			{
				pModule = pProcess->GetModuleByIndex(i);
				bReplace = 
					(pModule->Get_Module() != ModuleFromAddress(CApiHookMgr::MyLoadLibraryA)); 

				// We don't hook functions in our own modules
				if (bReplace)
				{
					
					// Hook this function in this module
					bResult = ReplaceInOneModule(
						pszCalleeModName, 
						pfnCurrent, 
						pfnNew, 
						pModule->Get_Module()
						) || bResult;
				}
			} // for
			// Hook this function in the executable as well
			dlog("replacing in exe")
			bResult = ReplaceInOneModule(
				pszCalleeModName, 
				pfnCurrent, 
				pfnNew, 
				pProcess->Get_Module()
				) || bResult;
		} // if
	} // if
	return bResult;
}


//---------------------------------------------------------------------------
// ReplaceInOneModule
//  
// Replace the address of the function in the IAT of a specific module
//---------------------------------------------------------------------------
BOOL CHookedFunction::ReplaceInOneModule(
	PCSTR   pszCalleeModName, 
	PROC    pfnCurrent, 
	PROC    pfnNew, 
	HMODULE hmodCaller
	) 
{
	BOOL bResult = FALSE;
	__try
	{
		ULONG ulSize;
		// Get the address of the module's import section
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = 
			(PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
			hmodCaller, 
			TRUE, 
			IMAGE_DIRECTORY_ENTRY_IMPORT, 
			&ulSize
			);
		// Does this module has import section ?
		if (pImportDesc == NULL)
			__leave;  
		// Loop through all descriptors and
		// find the import descriptor containing references to callee's functions
		while (pImportDesc->Name)
		{
			PSTR pszModName = (PSTR)((PBYTE) hmodCaller + pImportDesc->Name);
			if (_stricmp(pszModName, pszCalleeModName) == 0) 
				break;   // Found
			pImportDesc++;
		} // while
		// Does this module import any functions from this callee ?
		if (pImportDesc->Name == 0)
			__leave;  
		// Get caller's IAT 
		PIMAGE_THUNK_DATA pThunk = 
			(PIMAGE_THUNK_DATA)( (PBYTE) hmodCaller + pImportDesc->FirstThunk );
		// Replace current function address with new one
		while (pThunk->u1.Function)
		{
			// Get the address of the function address
			PROC* ppfn = (PROC*) &pThunk->u1.Function;
			// Is this the function we're looking for?
			BOOL bFound = (*ppfn == pfnCurrent);
			// Is this Windows 9x
			if (!bFound && (*ppfn > sm_pvMaxAppAddr)) 
			{
				PBYTE pbInFunc = (PBYTE) *ppfn;
				// Is this a wrapper (debug thunk) represented by PUSH instruction?
				if (pbInFunc[0] == cPushOpCode) 
				{
					ppfn = (PROC*) &pbInFunc[1];
					// Is this the function we're looking for?
					bFound = (*ppfn == pfnCurrent);
				} // if
			} // if

			if (bFound) 
			{
				MEMORY_BASIC_INFORMATION mbi;
				::VirtualQuery(ppfn, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				// In order to provide writable access to this part of the 
				// memory we need to change the memory protection
				if (FALSE == ::VirtualProtect(
					mbi.BaseAddress,
					mbi.RegionSize,
					PAGE_READWRITE,
					&mbi.Protect)
					)
					__leave;
				// Hook the function.
                *ppfn = *pfnNew;
				bResult = TRUE;
				// Restore the protection back
                DWORD dwOldProtect;
				::VirtualProtect(
					mbi.BaseAddress,
					mbi.RegionSize,
					mbi.Protect,
					&dwOldProtect
					);
				break;
			} // if
			pThunk++;
		} // while
	}
	__finally
	{
		// do nothing
	}
	// This function is not in the caller's import section
	return bResult;
}

//---------------------------------------------------------------------------
// DoHook
//  
// Perform actual replacing of function pointers
//---------------------------------------------------------------------------
BOOL CHookedFunction::DoHook(
	BOOL bHookOrRestore,
	PROC pfnCurrent, 
	PROC pfnNew
	)
{
	// Hook this function in all currently loaded modules
	dlog("In Do Hook")
	dlog(m_szCalleeModName)
	return ReplaceInAllModules(
		bHookOrRestore, 
		m_szCalleeModName, 
		pfnCurrent, 
		pfnNew
		);
}

//
// Indicates whether the hooked function is mandatory one
//
BOOL CHookedFunction::IsMandatory()
{
	BOOL bResult = FALSE;
	API_FUNC_ID apiFuncId;
	for (int i = 0; i < NUMBER_OF_MANDATORY_API_FUNCS; i++)
	{
		apiFuncId = MANDATORY_API_FUNCS[i];
		if ( (0==_stricmp(apiFuncId.szCalleeModName, m_szCalleeModName)) &&
		     (0==_stricmp(apiFuncId.szFuncName, m_szFuncName)) )
		{
			bResult = TRUE;
			break;
		} // if
	} // for

	return bResult;
}

//---------------------------------------------------------------------------
// 
// class CHookedFunctions 
//
//---------------------------------------------------------------------------

CHookedFunctions::CHookedFunctions(CApiHookMgr* pApiHookMgr):
	m_pApiHookMgr(pApiHookMgr)
{

}

CHookedFunctions::~CHookedFunctions()
{

}


//---------------------------------------------------------------------------
// GetHookedFunction
//  
// Return the address of an CHookedFunction object
//---------------------------------------------------------------------------
CHookedFunction* CHookedFunctions::GetHookedFunction(
	HMODULE hmodOriginal, 
	PCSTR   pszFuncName
	)
{
	char szFileName[MAX_PATH];
	::GetModuleFileName(hmodOriginal, szFileName, MAX_PATH);
	// We must extract only the name and the extension
	ExtractModuleFileName(szFileName);

	return GetHookedFunction(szFileName, pszFuncName);
}

//---------------------------------------------------------------------------
// GetFunctionNameFromExportSection
//  
// Return the name of the function from EAT by its ordinal value
//---------------------------------------------------------------------------
BOOL CHookedFunctions::GetFunctionNameFromExportSection(
	HMODULE hmodOriginal,
	DWORD   dwFuncOrdinalNum,
	PSTR    pszFuncName
	) 
{
	BOOL bResult = FALSE;
	// Make sure we return a valid string (atleast an empty one)
	strcpy(pszFuncName, "\0");
	__try
	{
		ULONG ulSize;
		// Get the address of the module's export section
		PIMAGE_EXPORT_DIRECTORY pExportDir = 
			(PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
			hmodOriginal, 
			TRUE, 
			IMAGE_DIRECTORY_ENTRY_EXPORT, 
			&ulSize
			);
		// Does this module has export section ?
		if (pExportDir == NULL)
			__leave;  
		// Get the name of the DLL
		PSTR pszDllName = reinterpret_cast<PSTR>( pExportDir->Name + (DWORD)hmodOriginal);
		// Get the starting ordinal value. By default is 1, but
		// is not required to be so
		DWORD dwFuncNumber = pExportDir->Base;
		// The number of entries in the EAT
		DWORD dwNumberOfExported = pExportDir->NumberOfFunctions;
		// Get the address of the ENT
		PDWORD pdwFunctions = (PDWORD)( pExportDir->AddressOfFunctions + (DWORD)hmodOriginal);
		//  Get the export ordinal table
		PWORD pwOrdinals = (PWORD)(pExportDir->AddressOfNameOrdinals + (DWORD)hmodOriginal);
		// Get the address of the array with all names
		DWORD *pszFuncNames =	(DWORD *)(pExportDir->AddressOfNames + (DWORD)hmodOriginal);

		PSTR pszExpFunName;

		// Walk through all of the entries and try to locate the
		// one we are looking for
		for (DWORD i = 0; i < dwNumberOfExported; i++, pdwFunctions++)
		{
			DWORD entryPointRVA = *pdwFunctions;
			if ( entryPointRVA == 0 )   // Skip over gaps in exported function
				continue;               // ordinals (the entrypoint is 0 for
										// these functions).
			// See if this function has an associated name exported for it.
			for ( DWORD j=0; j < pExportDir->NumberOfNames; j++ )
			{
				// Note that pwOrdinals[x] return values starting form 0.. (not from 1)
				if ( pwOrdinals[j] == i  )
				{
					pszExpFunName = (PSTR)(pszFuncNames[j] + (DWORD)hmodOriginal);
					// Is this the same ordinal value ?
					// Notice that we need to add 1 to pwOrdinals[j] to get actual 
					// number
					if (dwFuncOrdinalNum == pwOrdinals[j] + 1)
					{
						if ((pszExpFunName != NULL) && (strlen(pszExpFunName) > 0))
							strcpy(pszFuncName, pszExpFunName);
						__leave;
					}
				}
			}
		} // for
	}
	__finally
	{
		// do nothing
	}
	// This function is not in the caller's import section
	return bResult;
}

//---------------------------------------------------------------------------
// GetFunctionNameByOrdinal
//  
// Return the name of the function by its ordinal value
//---------------------------------------------------------------------------
void CHookedFunctions::GetFunctionNameByOrdinal(
	PCSTR   pszCalleeModName, 
	DWORD   dwFuncOrdinalNum,
	PSTR    pszFuncName
	)
{
	HMODULE hmodOriginal = ::GetModuleHandle(pszCalleeModName);
	// Take the name from the export section of the DLL
	GetFunctionNameFromExportSection(hmodOriginal, dwFuncOrdinalNum, pszFuncName);
}



//---------------------------------------------------------------------------
// GetHookedFunction
//  
// Return the address of an CHookedFunction object
//---------------------------------------------------------------------------
CHookedFunction* CHookedFunctions::GetHookedFunction( 
	PCSTR   pszCalleeModName, 
	PCSTR   pszFuncName
	)
{
	CHookedFunction* pHook = NULL;
	char szFuncName[MAX_PATH];
	//
	// Prevent accessing invalid pointers and examine values 
	// for APIs exported by ordinal
	//
	if ( (pszFuncName) && 
	     ((DWORD)pszFuncName > 0xFFFF) && 
		 strlen(pszFuncName) ) 
	{
		strcpy(szFuncName, pszFuncName);
	} // if
	else
	{
		GetFunctionNameByOrdinal(pszCalleeModName, (DWORD)pszFuncName, szFuncName);
	}
	// Search in the map only if we have found the name of the requested function
	if (strlen(szFuncName) > 0)
	{
		char szKey[MAX_PATH];
		sprintf(
			szKey, 
			"<%s><%s>", 
			pszCalleeModName,
			szFuncName
			);
		// iterators can be used to check if an entry is in the map
		CHookedFunctions::const_iterator citr = find( szKey );
		if ( citr != end() )
			pHook = citr->second;
	} // if

	return pHook;
}



//---------------------------------------------------------------------------
// AddHook
//  
// Add a new object to the container
//---------------------------------------------------------------------------
BOOL CHookedFunctions::AddHook(CHookedFunction* pHook)
{
	BOOL bResult = FALSE;
	if (NULL != pHook)
	{
		char szKey[MAX_PATH];
		sprintf(
			szKey, 
			"<%s><%s>", 
			pHook->Get_CalleeModName(),
			pHook->Get_FuncName()
			);
		// Find where szKey is or should be
		CHookedFunctions::iterator lb = lower_bound(szKey);
		//
		// when an "add" is performed, insert() is more efficient
		// than operator[].
		// For more details see -item 24 page 109 "Effective STL" by Meyers
		//
		// Adds pair(pszKey, pObject) to the map
		insert( lb, value_type(szKey, pHook) );
		//
		// added to the map
		//
		bResult = TRUE;
	} // if
	return bResult;
}

//---------------------------------------------------------------------------
// RemoveHook
//  
// Remove exising object pointer from the container
//---------------------------------------------------------------------------
BOOL CHookedFunctions::RemoveHook(CHookedFunction* pHook)
{
	BOOL bResult = FALSE;
	try
	{
		if (NULL != pHook)
		{
			char szKey[MAX_PATH];
			sprintf(
				szKey, 
				"<%s><%s>", 
				pHook->Get_CalleeModName(),
				pHook->Get_FuncName()
				);
			//
			// Find where szKey is located 
			//
			CHookedFunctions::iterator itr = find(szKey);
			if (itr != end())
			{
				delete itr->second;
				erase(itr);
			}
			bResult = TRUE;
		} // if
	}
	catch (...)
	{
		bResult = FALSE;
	}
	return bResult;
}
//----------------------End of file -----------------------------------------
