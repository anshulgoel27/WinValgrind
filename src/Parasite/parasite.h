// parasite.h : main header file for the parasite DLL
//

#ifndef _PARASITE_DEF_
#define _PARASITE_DEF_


#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

// CParasiteApp
// See parasite.cpp for the implementation of this class
//
#include <ApiHook.h>
#include <common.h>



class CParasiteApp : public CWinApp
{
private:
	static CApiHookMgr* sm_pHookMgr;
protected:
	static DWORD WINAPI DumpController( LPVOID pParam );
public:
	CParasiteApp();
	bool Cleanup();
// Overrides
public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	DECLARE_MESSAGE_MAP()
};



void DumpLeak();
void EmptyLeakMap();

#ifdef PARASITE_DLL_SRC
#define PARASITE_DLL_EXPORT extern "C" __declspec(dllexport)
#else
#define PARASITE_DLL_EXPORT extern "C" __declspec(dllimport)
#endif

PARASITE_DLL_EXPORT bool IsLeakDetected(void* pObject );
PARASITE_DLL_EXPORT void SetHookType(HOOK_TYPE_e eType );


#endif