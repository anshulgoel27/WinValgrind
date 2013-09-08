#ifndef _APIHOOK_H_
#define _APIHOOK_H_


#include <map>
#include <string>
using namespace std;
#include "..\LockMgr.h"
#include "..\ModuleInstance.h"


#define REGISTER_HOOK(Function, DLL) HookImport(#DLL ##".dll",#Function,(PROC)CApiHookMgr::My##Function)

//---------------------------------------------------------------------------
//
// Forward declarations
//
//---------------------------------------------------------------------------


class CHookedFunctions;

//---------------------------------------------------------------------------
//
// class CApiHookMgr
//  
//---------------------------------------------------------------------------
class CApiHookMgr  
{
public:
	CApiHookMgr();
	virtual ~CApiHookMgr();
public:
	//
	// Hook up an API 
	//
	BOOL HookImport(
		PCSTR pszCalleeModName, 
		PCSTR pszFuncName, 
		PROC  pfnHook
		);
	//
	// Restore hooked up API function
	//
	BOOL UnHookImport(
		PCSTR pszCalleeModName, 
		PCSTR pszFuncName
		);
	// 
	// Hook all needed system functions in order to trap loading libraries
	//
	BOOL HookSystemFuncs();

	// Hook handle alloc functions
	BOOL HookHandleAllocFuncs();

	// 
	// Unhook all functions and restore original ones
	//
	void UnHookAllFuncs();
	//
	// Indicates whether there is hooked function
	//
	BOOL AreThereHookedFunctions();
private:
	//
	// Let's allow CApiHookMgr to access private methods of CHookedFunction    
	//
	friend class CHookedFunction;
	//
	// Create a critical section on the stack
	//
	static CCSWrapper sm_CritSec;
	//
	// Handle to current module
	//
	HMODULE m_hmodThisInstance;
	//
	// Container keeps track of all hacked functions
	// 
	static CHookedFunctions* sm_pHookedFunctions;
	//
	// Determines whether all system functions has been successfuly hacked
	//
	BOOL m_bSystemFuncsHooked;

	//
	// Determines whether all handle alloc functions has been successfuly hacked
	//
	BOOL m_bHandleFuncsHooked;

	//
	// Used when a DLL is newly loaded after hooking a function
	//
	static void WINAPI HackModuleOnLoad(
		HMODULE hmod, 
		DWORD   dwFlags
		);
	//
	// Used to trap events when DLLs are loaded 
	//
	static HMODULE WINAPI CApiHookMgr::MyLoadLibraryA(
		PCSTR  pszModuleName
		);
	static HMODULE WINAPI CApiHookMgr::MyLoadLibraryW(
		PCWSTR pszModuleName
		);
	static HMODULE WINAPI CApiHookMgr::MyLoadLibraryExA(
		PCSTR  pszModuleName, 
		HANDLE hFile, 
		DWORD  dwFlags
		);
	static HMODULE WINAPI CApiHookMgr::MyLoadLibraryExW(
		PCWSTR pszModuleName, 
		HANDLE hFile, 
		DWORD  dwFlags
		);
	//
	// Returns address of replacement function if hooked function is requested
	//
	static FARPROC WINAPI CApiHookMgr::MyGetProcAddress(
		HMODULE hmod, 
		PCSTR   pszProcName
		);
	//
	// Returns original address of the API function
	//
	static FARPROC WINAPI GetProcAddressWindows(
		HMODULE hmod, 
		PCSTR   pszProcName
		);

	// Handle alloc methods
	static HANDLE WINAPI MyCreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,LPCSTR lpName);
	static HANDLE WINAPI MyCreateEventW( LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,LPCWSTR lpName);
	static HANDLE WINAPI MyCreateEventExA( LPSECURITY_ATTRIBUTES lpEventAttributes, LPCSTR lpName, DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyCreateEventExW( LPSECURITY_ATTRIBUTES lpEventAttributes, LPCWSTR lpName, DWORD dwFlags, DWORD dwDesiredAccess );
	static HANDLE WINAPI MyOpenEventA( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);
	static HANDLE WINAPI MyOpenEventW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName );
	static HANDLE WINAPI MyCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner, LPCSTR lpName );
	static HANDLE WINAPI MyCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCWSTR lpName);
	static HANDLE WINAPI MyCreateMutexExA(LPSECURITY_ATTRIBUTES lpEventAttributes,LPCSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyCreateMutexExW(LPSECURITY_ATTRIBUTES lpEventAttributes,LPCWSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyOpenMutexA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
	static HANDLE WINAPI MyOpenMutexW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpName);
	static HANDLE WINAPI MyCreateSemaphoreA( LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,LPCSTR lpName );
	static HANDLE WINAPI MyCreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName);
	static HANDLE WINAPI MyCreateSemaphoreExA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyCreateSemaphoreExW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,LONG lInitialCount,LONG lMaximumCount,LPCWSTR lpName,DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyOpenSemaphoreA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
	static HANDLE WINAPI MyOpenSemaphoreW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPWSTR lpName);
	static HANDLE WINAPI MyCreateWaitableTimerA( LPSECURITY_ATTRIBUTES lpTimerAttributes, BOOL bManualReset, LPCSTR lpTimerName);
	static HANDLE WINAPI MyCreateWaitableTimerW(LPSECURITY_ATTRIBUTES lpTimerAttributes,BOOL bManualReset,LPCWSTR lpTimerName);
	static HANDLE WINAPI MyCreateWaitableTimerExA(LPSECURITY_ATTRIBUTES lpTimerAttributes,LPCSTR lpTimerName,DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyCreateWaitableTimerExW(LPSECURITY_ATTRIBUTES lpTimerAttributes,LPCWSTR lpTimerName,DWORD dwFlags,DWORD dwDesiredAccess);
	static HANDLE WINAPI MyOpenWaitableTimerA(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpTimerName);
	static HANDLE WINAPI MyOpenWaitableTimerW(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCWSTR lpTimerName);

	// file function
	static HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile);
	static HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile);
	static HANDLE WINAPI MyCreateFileTransactedA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile,HANDLE hTransaction,PUSHORT pusMiniVersion,PVOID  lpExtendedParameter);
	static HANDLE WINAPI MyCreateFileTransactedW(LPCWSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile,HANDLE hTransaction,PUSHORT pusMiniVersion,PVOID  lpExtendedParameter );
	static HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData);
	static HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName,LPWIN32_FIND_DATAW lpFindFileData);
	static HANDLE WINAPI MyFindFirstFileExA(LPCSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags);
	static HANDLE WINAPI MyFindFirstFileExW(LPCWSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags);
	static HANDLE WINAPI MyFindFirstFileNameTransactedW (LPCWSTR lpFileName,DWORD dwFlags,LPDWORD StringLength,PWCHAR LinkName,HANDLE hTransaction);
	static HANDLE WINAPI MyFindFirstFileNameW (LPCWSTR lpFileName,DWORD dwFlags,LPDWORD StringLength,PWCHAR LinkName);
	static HANDLE WINAPI MyFindFirstFileTransactedA(LPCSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags,HANDLE hTransaction);
	static HANDLE WINAPI MyFindFirstFileTransactedW(LPCWSTR lpFileName,FINDEX_INFO_LEVELS fInfoLevelId,LPVOID lpFindFileData,FINDEX_SEARCH_OPS fSearchOp,LPVOID lpSearchFilter,DWORD dwAdditionalFlags,HANDLE hTransaction);
	static HANDLE WINAPI MyFindFirstStreamTransactedW(LPCWSTR lpFileName,STREAM_INFO_LEVELS InfoLevel,LPVOID lpFindStreamData,DWORD dwFlags,HANDLE hTransaction);
	static HANDLE WINAPI MyFindFirstStreamW( LPCWSTR lpFileName,STREAM_INFO_LEVELS InfoLevel,LPVOID lpFindStreamData,DWORD dwFlags);
	static BOOL WINAPI MyFindClose( HANDLE hFindFile);
	static HANDLE WINAPI MyOpenFileById(HANDLE hFile,LPFILE_ID_DESCRIPTOR lpFileID,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwFlags);
	static HANDLE WINAPI MyReOpenFile(HANDLE hOriginalFile,DWORD dwDesiredAccess,DWORD dwShareMode,DWORD dwFlags);
	static HANDLE WINAPI MyCreateIoCompletionPort(HANDLE FileHandle,HANDLE ExistingCompletionPort,ULONG_PTR CompletionKey,DWORD NumberOfConcurrentThreads);

	//Authorization function
	static BOOL   WINAPI MyCreateRestrictedToken(HANDLE ExistingTokenHandle,DWORD Flags,DWORD DisableSidCount,PSID_AND_ATTRIBUTES SidsToDisable,DWORD DeletePrivilegeCount,PLUID_AND_ATTRIBUTES PrivilegesToDelete,DWORD RestrictedSidCount,PSID_AND_ATTRIBUTES SidsToRestrict,PHANDLE NewTokenHandle);
	static BOOL   WINAPI MyDuplicateToken(HANDLE ExistingTokenHandle,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,PHANDLE DuplicateTokenHandle);
	static BOOL   WINAPI MyDuplicateTokenEx(HANDLE hExistingToken,DWORD dwDesiredAccess,LPSECURITY_ATTRIBUTES lpTokenAttributes,SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,TOKEN_TYPE TokenType,PHANDLE phNewToken);
	static BOOL   WINAPI MyOpenProcessToken(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle);
	static BOOL   WINAPI MyOpenThreadToken(HANDLE ThreadHandle,DWORD DesiredAccess,BOOL OpenAsSelf,PHANDLE TokenHandle);

	//Directory management
	static HANDLE WINAPI MyFindFirstChangeNotificationA(LPCSTR lpPathName,BOOL bWatchSubtree,DWORD dwNotifyFilter);
	static HANDLE WINAPI MyFindFirstChangeNotificationW(LPCWSTR lpPathName,BOOL bWatchSubtree,DWORD dwNotifyFilter);
	static BOOL   WINAPI MyFindCloseChangeNotification(HANDLE hChangeHandle);
	
	// File mapping
	static HANDLE WINAPI MyCreateMemoryResourceNotification( MEMORY_RESOURCE_NOTIFICATION_TYPE NotificationType );
	static HANDLE WINAPI MyCreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName );
	static HANDLE WINAPI MyCreateFileMappingW( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName );
	static HANDLE WINAPI MyCreateFileMappingNumaA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName, DWORD nndPreferred );
	static HANDLE WINAPI MyCreateFileMappingNumaW( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName, DWORD nndPreferred) ;
	static HANDLE WINAPI MyOpenFileMappingA( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName );
	static HANDLE WINAPI MyOpenFileMappingW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName );
	
	//Memory
	static HANDLE WINAPI MyHeapCreate( DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize );
	static BOOL   WINAPI MyHeapDestroy(HANDLE hHeap );
	
	//Process and thread
	static BOOL   WINAPI MyCreateProcessA( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
	static BOOL   WINAPI MyCreateProcessW( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
	static BOOL   WINAPI MyCreateProcessAsUserA(HANDLE hToken,LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
	static BOOL   WINAPI MyCreateProcessAsUserW(HANDLE hToken,LPWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
	static BOOL   WINAPI MyCreateProcessWithLogonW(LPCWSTR lpUsername,LPCWSTR lpDomain,LPCWSTR lpPassword,DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
	static BOOL   WINAPI MyCreateProcessWithTokenW(HANDLE hToken,DWORD dwLogonFlags,LPCWSTR lpApplicationName,LPWSTR lpCommandLine,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
	static HANDLE WINAPI MyOpenProcess( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId );
	static HANDLE WINAPI MyCreateThread( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
	static HANDLE WINAPI MyCreateRemoteThread( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId );
	static HANDLE WINAPI MyOpenThread( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId );
	static HANDLE WINAPI MyCreateJobObjectA( LPSECURITY_ATTRIBUTES lpJobAttributes, LPCSTR lpName );
	static HANDLE WINAPI MyCreateJobObjectW( LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName );
	
	//Mail slot
	static HANDLE WINAPI MyCreateMailslotA( LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes );
	static HANDLE WINAPI MyCreateMailslotW( LPCWSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes );
	
	// pipe
	static BOOL   WINAPI MyCreatePipe( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize );
	static HANDLE WINAPI MyCreateNamedPipeA( LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes );
	static HANDLE WINAPI MyCreateNamedPipeW( LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes );
	
	//Registry
	static LSTATUS WINAPI MyRegCreateKeyExA( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition );
	static LSTATUS WINAPI MyRegCreateKeyExW ( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition );
	static LSTATUS WINAPI MyRegCreateKeyTransactedA( HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition, HANDLE hTransaction, PVOID  pExtendedParemeter );
	static LSTATUS WINAPI MyRegCreateKeyTransactedW( HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, CONST LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition, HANDLE hTransaction, PVOID  pExtendedParemeter );
	static LSTATUS WINAPI MyRegOpenCurrentUser( REGSAM samDesired, PHKEY phkResult );
	static LSTATUS WINAPI MyRegOpenKeyA ( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult );
	static LSTATUS WINAPI MyRegOpenKeyW ( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult );
	static LSTATUS WINAPI MyRegOpenKeyExA ( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult );
	static LSTATUS WINAPI MyRegOpenKeyExW ( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult );
	static LSTATUS WINAPI MyRegOpenKeyTransactedA ( HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult, HANDLE hTransaction, PVOID  pExtendedParemeter );
	static LSTATUS WINAPI MyRegOpenKeyTransactedW ( HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult, HANDLE hTransaction, PVOID  pExtendedParemeter );
	static LSTATUS WINAPI MyRegOpenUserClassesRoot( HANDLE hToken, DWORD dwOptions, REGSAM samDesired, PHKEY  phkResult );
	static LSTATUS WINAPI MyRegCreateKeyA ( HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult );
	static LSTATUS WINAPI MyRegCreateKeyW ( HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult );
	static LSTATUS WINAPI MyRegCloseKey ( HKEY hKey );
	
	// Timers
	static HANDLE WINAPI MyCreateTimerQueue(void);
	static BOOL   WINAPI MyCreateTimerQueueTimer(PHANDLE phNewTimer,HANDLE TimerQueue,WAITORTIMERCALLBACK Callback,PVOID Parameter,DWORD DueTime,DWORD Period,ULONG Flags);
	static BOOL   WINAPI MyDeleteTimerQueueTimer(HANDLE TimerQueue,HANDLE Timer,HANDLE CompletionEvent);
	static BOOL   WINAPI MyDeleteTimerQueueEx(HANDLE TimerQueue,HANDLE CompletionEvent);
	static BOOL WINAPI MyDeleteTimerQueue(HANDLE TimerQueue);
	
	//Critical section
	static void WINAPI MyInitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
	static BOOL WINAPI MyInitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount,DWORD Flags);
	static BOOL WINAPI MyInitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection,DWORD dwSpinCount);
	static void WINAPI MyDeleteCriticalSection( LPCRITICAL_SECTION lpCriticalSection);
	
	
	static BOOL   WINAPI MyDuplicateHandle(HANDLE hSourceProcessHandle,HANDLE hSourceHandle,HANDLE hTargetProcessHandle,LPHANDLE lpTargetHandle,DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwOptions);
	static BOOL   WINAPI MyCloseHandle( HANDLE hObject );
	
	static HANDLE WINAPI MyGlobalAlloc( UINT uFlags, SIZE_T dwBytes );
	static HANDLE WINAPI MyGlobalReAlloc( HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags );
	static HANDLE WINAPI MyGlobalFree( HGLOBAL hMem );
	static HLOCAL WINAPI MyLocalAlloc( UINT uFlags, SIZE_T uBytes );
	static HLOCAL WINAPI MyLocalReAlloc( HLOCAL hMem, SIZE_T uBytes, UINT uFlags );
	static HLOCAL WINAPI MyLocalFree(HLOCAL hMem );



	//
	// Add a newly intercepted function to the container
	//
	BOOL AddHook(
		PCSTR  pszCalleeModName, 
		PCSTR  pszFuncName, 
		PROC   pfnOrig,
		PROC   pfnHook
		);
	//
	// Remove intercepted function from the container
	//
	BOOL RemoveHook(
		PCSTR pszCalleeModName, 
		PCSTR pszFuncName
		);
};


//---------------------------------------------------------------------------
//
// class CHookedFunction
//  
//---------------------------------------------------------------------------
class CHookedFunction  
{
public:
	CHookedFunction(
		CHookedFunctions* pHookedFunctions,
		PCSTR             pszCalleeModName, 
		PCSTR             pszFuncName, 
		PROC              pfnOrig,
		PROC              pfnHook
		);
	virtual ~CHookedFunction();

    PCSTR Get_CalleeModName() const;
	PCSTR Get_FuncName() const;
	PROC Get_pfnHook() const;
	PROC Get_pfnOrig() const;
	//
	// Set up a new hook function
	//
	BOOL HookImport();
	//
	// Restore the original API handler
	//
	BOOL UnHookImport();
	//
	// Replace the address of the function in the IAT of a specific module
	//
	BOOL ReplaceInOneModule(
		PCSTR   pszCalleeModName, 
		PROC    pfnCurrent, 
		PROC    pfnNew, 
		HMODULE hmodCaller
		);
	//
	// Indicates whether the hooked function is mandatory one
	//
	BOOL IsMandatory();

private:
	CHookedFunctions* m_pHookedFunctions;
	BOOL              m_bHooked;
	char              m_szCalleeModName[MAX_PATH];
	char              m_szFuncName[MAX_PATH];
	PROC              m_pfnOrig;
	PROC              m_pfnHook;
	//
	// Maximum private memory address
	//
	static  PVOID   sm_pvMaxAppAddr;    
	//
	// Perform actual replacing of function pointers
	// 
	BOOL DoHook(
		BOOL bHookOrRestore,
		PROC pfnCurrent, 
		PROC pfnNew
		);
	//
	// Replace the address of a imported function entry  in all modules
	//
	BOOL ReplaceInAllModules(
		BOOL   bHookOrRestore,
		PCSTR  pszCalleeModName, 
		PROC   pfnCurrent, 
		PROC   pfnNew
		);
};


//---------------------------------------------------------------------------
//
// class CNocaseCmp
//
// Implements case-insensitive string compare
//
//---------------------------------------------------------------------------
class CNocaseCmp
{
public:
	//
	// A built-in highly efficient method for case-insensitive string compare.
	// Returns true, when string x is less than string y
	//
	bool operator()(const string& x, const string& y) const
	{
		return ( _stricmp(x.c_str(), y.c_str()) < 0 );
	}
};


//---------------------------------------------------------------------------
//
// class CHookedFunctions
//
//---------------------------------------------------------------------------
class CHookedFunctions: public map<string, CHookedFunction*, CNocaseCmp>
{
public:
	CHookedFunctions(CApiHookMgr* pApiHookMgr);
	virtual ~CHookedFunctions();
public:
	// 
	// Return the address of an CHookedFunction object
	//
	CHookedFunction* GetHookedFunction( 
		PCSTR pszCalleeModName, 
		PCSTR pszFuncName
		);
	//
	// Return the address of an CHookedFunction object
	//
	CHookedFunction* GetHookedFunction( 
		HMODULE hmod, 
		PCSTR   pszFuncName
		);
	//
	// Add a new object to the container
	//
	BOOL AddHook(CHookedFunction* pHook);
	//
	// Remove exising object pointer from the container
	//
	BOOL RemoveHook(CHookedFunction* pHook);
private:
	//  
	// Return the name of the function from EAT by its ordinal value
	//
	BOOL GetFunctionNameFromExportSection(
		HMODULE hmodOriginal,
		DWORD   dwFuncOrdinalNum,
		PSTR    pszFuncName
		); 
	//  
	// Return the name of the function by its ordinal value
	//
	void GetFunctionNameByOrdinal(
		PCSTR   pszCalleeModName, 
		DWORD   dwFuncOrdinalNum,
		PSTR    pszFuncName
		);


	
	CApiHookMgr* m_pApiHookMgr;
};



#endif // !defined(_APIHOOK_H_)
