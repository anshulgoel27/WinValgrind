#ifndef _APIHOOK_H_
#define _APIHOOK_H_


#include <map>
#include <string>
using namespace std;
#include <LockMgr.h>
#include <ModuleInstance.h>


#define HOOK_IMPORT(Function, DLL) HookImport(#DLL ##".dll",#Function,(PROC)CApiHookMgr::My##Function)

//////////////////////////////////////////////////////////////////////////////
//
// Forward declarations
//
//////////////////////////////////////////////////////////////////////////////


class CHookedFunctions;

//////////////////////////////////////////////////////////////////////////////
//
// class CApiHookMgr
//  
//////////////////////////////////////////////////////////////////////////////
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
	 
	// Hook all needed system functions in order to trap loading libraries
	BOOL HookSystemFuncs();

	// Hook handle alloc functions
	BOOL HookHandleAllocFuncs();

	// Hook memory alloc functions
	BOOL HookMemAllocFuncs();
	
	// Hook GDI object alloc functions
	BOOL HookGDIAllocFuncs();

	// 
	// Unhook all functions and restore original ones
	//
	void UnHookAllFuncs();
	//
	// Indicates whether there is hooked function
	//
	BOOL AreThereHookedFunctions();
	//
	// Hooked API count
	//
	size_t HookedFunctionCount() const;

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
	// Determines whether all memory allocation functions has been successfuly hacked
	//
	BOOL m_bMemFuncsHooked;

	//
	// Determines whether all GDI object allocation functions has been successfuly hacked
	//
	BOOL m_bGDIFuncsHooked;

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
	
	//////////////////////////////////////////////////////////////
	// Memory alloc methods hooks
	//////////////////////////////////////////////////////////////
	static LPVOID WINAPI MyHeapAlloc( IN HANDLE hHeap, IN DWORD dwFlags, IN SIZE_T dwBytes );
	static LPVOID WINAPI MyHeapReAlloc( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes );
	static LPVOID WINAPI MyVirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
	static BOOL WINAPI MyVirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );
	static LPVOID WINAPI MyVirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
	static BOOL WINAPI MyVirtualFreeEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );
	static BOOL WINAPI MyHeapFree(  HANDLE hHeap,  DWORD dwFlags,  LPVOID lpMem );
	static LPVOID WINAPI MyCoTaskMemAlloc( SIZE_T cb);
	static LPVOID WINAPI MyCoTaskMemRealloc(LPVOID pv, SIZE_T cb);
	static void   WINAPI MyCoTaskMemFree( LPVOID pv );
	static LPVOID WINAPI MyMapViewOfFile( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap );
	static LPVOID WINAPI MyMapViewOfFileEx( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress );
	static BOOL WINAPI MyUnmapViewOfFile( LPCVOID lpBaseAddress );
	
	// static int myntmapviewofsection( handle sectionhandle, handle processhandle, pvoid *baseaddress,
									// ulong_ptr zerobits, size_t commitsize, plarge_integer sectionoffset, psize_t viewsize,
									// section_inherit inheritdisposition, ulong allocationtype, ulong win32protect );
	// static int myntunmapviewofsection( handle processhandle, pvoid baseaddress );
	
	////////////////////////////////////////////////////////////// 
	// Handle alloc methods hooks
	//////////////////////////////////////////////////////////////
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


	////////////////////////////////////////////////////////////// 
	// GDI object alloc methods hooks
	//////////////////////////////////////////////////////////////

	// Bitmap
	static HANDLE WINAPI MyLoadImageA(HINSTANCE hInst,LPCSTR name,UINT type,int cx,int cy,UINT fuLoad);
	static HANDLE WINAPI MyLoadImageW( HINSTANCE hInst,LPCWSTR name,UINT type,int cx,int cy,UINT fuLoad);
	static HBITMAP WINAPI MyLoadBitmapA( HINSTANCE hInstance, LPCSTR lpBitmapName);
	static HBITMAP WINAPI MyLoadBitmapW( HINSTANCE hInstance, LPCWSTR lpBitmapName );
	static HANDLE  WINAPI MyLoadImageADef( HINSTANCE hInst, LPCSTR name, UINT type,int cx,int cy, UINT fuLoad);
	static HANDLE  WINAPI MyLoadImageWDef( HINSTANCE hInst, LPCWSTR name, UINT type, int cx, int cy, UINT fuLoad);
	static HBITMAP WINAPI MyCreateBitmap(  int nWidth,  int nHeight, UINT nPlanes,  UINT nBitCount,  CONST VOID *lpBits);
	static HBITMAP WINAPI MyCreateBitmapIndirect(  CONST BITMAP *pbm );
	static HBITMAP WINAPI MyCreateCompatibleBitmap(  HDC hdc,  int cx,  int cy);
	static HBITMAP WINAPI MyCreateDIBitmap(  HDC hdc,  CONST BITMAPINFOHEADER *pbmih,  DWORD flInit,  CONST VOID *pjBits,  CONST BITMAPINFO *pbmi,  UINT iUsage);
	static HBITMAP WINAPI MyCreateDIBSection( HDC hdc,  CONST BITMAPINFO *lpbmi,  UINT usage, VOID **ppvBits,  HANDLE hSection,  DWORD offset);
	static HBITMAP WINAPI MyCreateDiscardableBitmap( HDC hdc, int cx, int cy);
	static HANDLE  WINAPI MyCopyImage( HANDLE h, UINT type, int cx, int cy, UINT flags);
	static BOOL WINAPI MyDeleteObject(  HGDIOBJ ho);

	// Icons
	static BOOL WINAPI MyGetIconInfo( HICON hIcon, PICONINFO piconinfo);
	static BOOL WINAPI MyGetIconInfoExA( HICON hicon, PICONINFOEXA piconinfo);
	static BOOL WINAPI MyGetIconInfoExW( HICON hicon,PICONINFOEXW piconinfo);
	static HICON WINAPI MyCreateIcon(HINSTANCE hInstance,int nWidth,int nHeight,BYTE cPlanes,BYTE cBitsPixel,CONST BYTE *lpbANDbits,CONST BYTE *lpbXORbits);
	static HICON WINAPI MyCreateIconFromResource( PBYTE presbits, DWORD dwResSize, BOOL fIcon, DWORD dwVer);
	static HICON WINAPI MyCreateIconFromResourceEx( PBYTE presbits, DWORD dwResSize,BOOL fIcon,DWORD dwVer,int cxDesired,int cyDesired,UINT Flags );
	static HICON WINAPI MyCreateIconIndirect( PICONINFO piconinfo );
	static BOOL  WINAPI MyDestroyIcon(HICON hIcon);
	static HICON WINAPI MyDuplicateIcon(HINSTANCE hInst, HICON hIcon);
	static HICON WINAPI MyExtractAssociatedIconA(HINSTANCE hInst,  LPSTR lpIconPath,  LPWORD lpiIcon);
	static HICON WINAPI MyExtractAssociatedIconW(HINSTANCE hInst,  LPWSTR lpIconPath,  LPWORD lpiIcon);
	static HICON WINAPI MyExtractAssociatedIconExA(HINSTANCE hInst,LPSTR lpIconPath,  LPWORD lpiIconIndex,  LPWORD lpiIconId);
	static HICON WINAPI MyExtractAssociatedIconExW(HINSTANCE hInst,LPWSTR lpIconPath,  LPWORD lpiIconIndex,  LPWORD lpiIconId);
	static HICON WINAPI MyExtractIconA(HINSTANCE hInst, LPCSTR lpszExeFileName, UINT nIconIndex);
	static HICON WINAPI MyExtractIconW(HINSTANCE hInst, LPCWSTR lpszExeFileName, UINT nIconIndex);
	static UINT  WINAPI MyExtractIconExA(LPCSTR lpszFile, int nIconIndex, HICON *phiconLarge, HICON *phiconSmall, UINT nIcons);
	static UINT  WINAPI MyExtractIconExW(LPCWSTR lpszFile, int nIconIndex,  HICON *phiconLarge, HICON *phiconSmall, UINT nIcons);
	static HICON WINAPI MyLoadIconA( HINSTANCE hInstance, LPCSTR lpIconName );
	static HICON WINAPI MyLoadIconW( HINSTANCE hInstance, LPCWSTR lpIconName );
	static UINT  WINAPI MyPrivateExtractIconsA( LPCSTR szFileName, int nIconIndex, int cxIcon, int cyIcon, HICON *phicon, UINT *piconid, UINT nIcons, UINT flags);
	static UINT  WINAPI MyPrivateExtractIconsW( LPCWSTR szFileName, int nIconIndex, int cxIcon, int cyIcon, HICON *phicon, UINT *piconid,UINT nIcons,UINT flags);
	static HICON WINAPI MyCopyIcon( HICON hIcon);

	// Cursors
	static HCURSOR WINAPI MyCreateCursor( HINSTANCE hInst, int xHotSpot, int yHotSpot,int nWidth, int nHeight, CONST VOID *pvANDPlane,CONST VOID *pvXORPlane);
	static HCURSOR WINAPI MyLoadCursorA( HINSTANCE hInstance, LPCSTR lpCursorName);
	static HCURSOR WINAPI MyLoadCursorW( HINSTANCE hInstance, LPCWSTR lpCursorName);
	static HCURSOR WINAPI MyLoadCursorFromFileA( LPCSTR lpFileName );
	static HCURSOR WINAPI MyLoadCursorFromFileW( LPCWSTR lpFileName );
	static BOOL WINAPI MyDestroyCursor( HCURSOR hCursor );

	// Brush
	static HBRUSH  WINAPI MyCreateBrushIndirect(  CONST LOGBRUSH *plbrush);
	static HBRUSH  WINAPI MyCreateSolidBrush(  COLORREF color);
	static HBRUSH  WINAPI MyCreatePatternBrush(  HBITMAP hbm);
	static HBRUSH  WINAPI MyCreateDIBPatternBrush(  HGLOBAL h,  UINT iUsage);
	static HBRUSH  WINAPI MyCreateDIBPatternBrushPt(  CONST VOID *lpPackedDIB,  UINT iUsage);
	static HBRUSH  WINAPI MyCreateHatchBrush(  int iHatch,  COLORREF color);
	
	// DC
	static HDC WINAPI MyCreateCompatibleDC( HDC hdc );
	static HDC WINAPI MyCreateDCA( LPCSTR pwszDriver,  LPCSTR pwszDevice,  LPCSTR pszPort,  CONST DEVMODEA * pdm );
	static HDC WINAPI MyCreateDCW( LPCWSTR pwszDriver,  LPCWSTR pwszDevice,  LPCWSTR pszPort,  CONST DEVMODEW * pdm );
	static HDC WINAPI MyCreateICA( LPCSTR pszDriver,  LPCSTR pszDevice,  LPCSTR pszPort,  CONST DEVMODEA * pdm );
	static HDC WINAPI MyCreateICW( LPCWSTR pszDriver,  LPCWSTR pszDevice,  LPCWSTR pszPort,  CONST DEVMODEW * pdm );
	static HDC WINAPI MyGetDC( HWND hWnd );
	static HDC WINAPI MyGetDCEx( HWND hWnd, HRGN hrgnClip, DWORD flags );
	static HDC WINAPI MyGetWindowDC( HWND hWnd );
	static int WINAPI MyReleaseDC( HWND hWnd, HDC hDC);
	static BOOL WINAPI MyDeleteDC( HDC hdc);
	
	// Font
	static HFONT WINAPI MyCreateFontA(  int cHeight,  int cWidth,  int cEscapement,  int cOrientation,  int cWeight,  DWORD bItalic,
     DWORD bUnderline,  DWORD bStrikeOut,  DWORD iCharSet,  DWORD iOutPrecision,  DWORD iClipPrecision,
     DWORD iQuality,  DWORD iPitchAndFamily, LPCSTR pszFaceName);

	static HFONT WINAPI MyCreateFontW(  int cHeight,  int cWidth,  int cEscapement,  int cOrientation,  int cWeight,  DWORD bItalic,
     DWORD bUnderline,  DWORD bStrikeOut,  DWORD iCharSet,  DWORD iOutPrecision,  DWORD iClipPrecision,
     DWORD iQuality,  DWORD iPitchAndFamily, LPCWSTR pszFaceName);

	static HFONT WINAPI MyCreateFontIndirectA(  CONST LOGFONTA *lplf);
	static HFONT WINAPI MyCreateFontIndirectW( CONST LOGFONTW *lplf);
	
	// Meta File
	static HDC WINAPI MyCreateMetaFileA(  LPCSTR pszFile );
	static HDC WINAPI MyCreateMetaFileW(  LPCWSTR pszFile );
	static HDC WINAPI MyCreateEnhMetaFileA(  HDC hdc,  LPCSTR lpFilename,  CONST RECT *lprc,  LPCSTR lpDesc);
	static HDC WINAPI MyCreateEnhMetaFileW(  HDC hdc,  LPCWSTR lpFilename,  CONST RECT *lprc,  LPCWSTR lpDesc);
	static HENHMETAFILE WINAPI MyGetEnhMetaFileA(  LPCSTR lpName );
	static HENHMETAFILE WINAPI MyGetEnhMetaFileW(  LPCWSTR lpName );
	static HMETAFILE WINAPI MyGetMetaFileA(  LPCSTR lpName);
	static HMETAFILE WINAPI MyGetMetaFileW( LPCWSTR lpName );
	static BOOL WINAPI MyDeleteMetaFile( HMETAFILE hmf );
	static BOOL WINAPI MyDeleteEnhMetaFile( HENHMETAFILE hmf );
	static HENHMETAFILE WINAPI MyCopyEnhMetaFileA( HENHMETAFILE hEnh, LPCSTR lpFileName);
	static HENHMETAFILE WINAPI MyCopyEnhMetaFileW( HENHMETAFILE hEnh, LPCWSTR lpFileName);
	static HENHMETAFILE WINAPI MyCloseEnhMetaFile( HDC hdc);
	static HMETAFILE WINAPI MyCloseMetaFile( HDC hdc);
	
	// Pen
	static HPEN WINAPI MyCreatePen(  int iStyle,  int cWidth,  COLORREF color);
	static HPEN WINAPI MyCreatePenIndirect(  CONST LOGPEN *plpen);
	static HPEN WINAPI MyExtCreatePen( DWORD iPenStyle, DWORD cWidth, CONST LOGBRUSH *plbrush, DWORD cStyle, CONST DWORD *pstyle);
	
	// Region 
	static HRGN WINAPI MyPathToRegion( HDC hdc);
	static HRGN WINAPI MyCreateEllipticRgn(  int x1,  int y1,  int x2, int y2);
	static HRGN WINAPI MyCreateEllipticRgnIndirect(  CONST RECT *lprect);
	static HRGN WINAPI MyCreatePolygonRgn( CONST POINT *pptl, int cPoint, int iMode);
	static HRGN WINAPI MyCreatePolyPolygonRgn( CONST POINT *pptl, CONST INT  *pc, int cPoly, int iMode);
	static HRGN WINAPI MyCreateRectRgn(  int x1,  int y1,  int x2,  int y2);
	static HRGN WINAPI MyCreateRectRgnIndirect(  CONST RECT *lprect);
	static HRGN WINAPI MyCreateRoundRectRgn(  int x1,  int y1,  int x2,  int y2,  int w,  int h);
	static HRGN WINAPI MyExtCreateRegion( CONST XFORM * lpx,  DWORD nCount, CONST RGNDATA * lpData);
	
	// Palette 
	static HPALETTE WINAPI MyCreateHalftonePalette(  HDC hdc);
	static HPALETTE WINAPI MyCreatePalette( CONST LOGPALETTE * plpal );



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


//////////////////////////////////////////////////////////////////////////////
//
// class CHookedFunction
//  
//////////////////////////////////////////////////////////////////////////////
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


//////////////////////////////////////////////////////////////////////////////
//
// class CNocaseCmp
//
// Implements case-insensitive string compare
//
//////////////////////////////////////////////////////////////////////////////
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


//////////////////////////////////////////////////////////////////////////////
//
// class CHookedFunctions
//
//////////////////////////////////////////////////////////////////////////////
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
