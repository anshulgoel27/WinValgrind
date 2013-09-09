// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently


#if !defined(AFX_STDAFX_H__A3056BBB_B70B_466F_985C_20F15AA5B1EC__INCLUDED_)
#define AFX_STDAFX_H__A3056BBB_B70B_466F_985C_20F15AA5B1EC__INCLUDED_

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // some CString constructors will be explicit

#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxole.h>         // MFC OLE classes
#include <afxodlgs.h>       // MFC OLE dialog classes
#include <afxdisp.h>        // MFC Automation classes
#endif // _AFX_NO_OLE_SUPPORT

#ifndef _AFX_NO_DB_SUPPORT
#include <afxdb.h>                      // MFC ODBC database classes
#endif // _AFX_NO_DB_SUPPORT

#ifndef _AFX_NO_DAO_SUPPORT
#include <afxdao.h>                     // MFC DAO database classes
#endif // _AFX_NO_DAO_SUPPORT

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC support for Internet Explorer 4 Common Controls
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>                     // MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <string>
#include "pugixml.hpp"
#include <vector>

#define DUMP_EVENT _T("_leak_dump_evt_")
#define CLEAR_LEAKS _T("_clr_all_leaks_evt_")
#define EXIT_PARASITE_DLL _T("_exit_parasite_dll_evt_" )

extern int g_bLog;

#include <fstream>

#define dlog(text) \
{ \
	if(g_bLog!=0) \
	{ \
		std::ofstream log(g_Config::sDllPath+"Debuglog.txt",std::ios::app); \
		log << __FUNCTION__ << "::" << __LINE__ << "\t" << text << "\n"; \
		log.close(); \
	}\
}


#define dlog_v(name,variable) \
{ \
	if(g_bLog!=0) \
	{ \
		std::ofstream log(g_Config::sDllPath+"Debuglog.txt",std::ios::app); \
		log << __FUNCTION__ << "::" << __LINE__ << "\t" << name <<": " << variable << "\n"; \
		log.close(); \
	}\
}


#endif