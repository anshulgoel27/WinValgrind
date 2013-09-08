#ifndef _COMMON_DEF_
#define _COMMON_DEF_

#include "stdafx.h"
#include <map>
#include <vector>
#include <afxmt.h>
#include <new.h>
#include <DbgHelp.h>

using namespace std;

enum HOOK_TYPE_e
{ 
	HT_UNKNOWN = 0,
	HT_MEMORY = 1,
	HT_GDI = 2,
	HT_HANDLE = 3,
	HT_NOTHING = 4
};

typedef vector<DWORD64> STACK_ARRAY;
struct MEM_INFO
{
    STACK_ARRAY parCallStack;
    SIZE_T nMemSize;
};

struct g_Config
{
	static HOOK_TYPE_e g_HookType;
	static int g_StackDepth;
	static bool g_bTrack;
	static bool g_bHooked;
	static CCriticalSection SyncObj;
	static map<LPVOID,MEM_INFO> g_Config::m_MemMap;
	static CString sDllPath;
};


enum HANDLE_TYPES_e
{
	TYPE_EVENT_HANDLE,
	TYPE_MUTEX_HANDLE,
	TYPE_SEMAPHOR_HANDLE,
    TYPE_CRITICAL_SECTION_HANDLE,
	TYPE_WAIT_TIMER_HANDLE,
	TYPE_FILE_HANDLE,
	TYPE_TOKEN_HANDLE,
	TYPE_CHANGE_NOFICATION_HANDLE,
	TYPE_MEMEORY_MAPPED_FILE_HANDLE,
	TYPE_MEMORY_HANDLE,
	TYPE_PROCESS_HANDLE,
	TYPE_THREAD_HANDLE,
	TYPE_JOB_HANDLE,
	TYPE_MAIL_SLOT_HANDLE,
	TYPE_PIPE_HANDLE,
	TYPE_REGISTRY_HANDLE,
    TYPE_TIMER_QUEUE,
	TYPE_UNKNOWN
};




//////////////////////////////////////////////////////////////
//////////global variables and declarations//////////////////


#define STACKWALK_MAX_NAMELEN 1024

void StackDump( LPVOID pMem, DWORD dwBytes);
void CreateCallStack( LPVOID lpMem, SIZE_T dwBytes );
void RemovCallStack( LPVOID lpMem );
void CopyStack(LPVOID lpExisting, LPVOID lpNew, int nType );

#endif