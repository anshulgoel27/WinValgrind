#ifndef _CONFIG_LOADER_
#define _CONFIG_LOADER_

#include <vector>
#include <string>

typedef BOOL (WINAPI * SymRefreshModuleListDef)( HANDLE hProcess );

class CConfigLoader
{
private:
	std::vector<std::string> m_symbolVec;
	bool LoadDLL();
	CDialog m_ProgressDlg;
	CString m_csPath;
	CString m_csDllPath;
protected:
	static UINT __cdecl ThreadEntry( LPVOID pParam );
	static BOOL CALLBACK SymRegisterCallbackProc64( HANDLE hProcess,
													ULONG ActionCode,
													ULONG64 CallbackData,
													ULONG64 UserContext );
	void ShowWaitDialog();
public:
	CConfigLoader() :
		 m_ProgressDlg( IDD_SYM_PROG )
	{

	}
	bool LoadConfig();
};

#endif