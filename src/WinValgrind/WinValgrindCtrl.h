#pragma once

#include "stdafx.h"



const std::string sConfigTemplate = "<WinValgrind><!-- Type of HOOK --><MonitorType>MEMORY</MonitorType><!-- PDB Path --><PDBInfo><!-- Do not remove PDB path 1 & 2 --><PDBInfo1 path=\"test\" /><PDBInfo2 path=\"test\" /><!-- microsoft sysmbol server --><PDBInfo3 path=\"test\" /><!-- Add Monitored process symbol path --></PDBInfo></WinValgrind>";

class CWinValgrindCtrl
{
private:
	CStringA m_csSystemPath;
	CStringA m_csSymbolPath;
	CStringA m_csDllPath;
public:
	CWinValgrindCtrl ()
	{
		
        if (GetEnvironmentVariableA("SYSTEMROOT", m_csSystemPath.GetBuffer( MAX_PATH), MAX_PATH) > 0)
        {
            m_csSystemPath.ReleaseBuffer();
            m_csSystemPath += "\\system32";
        }
        else
        {
            m_csSystemPath.ReleaseBuffer();
        }        
        
              
        
        if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", m_csSymbolPath.GetBuffer( MAX_PATH), MAX_PATH) > 0)
        {
            m_csSymbolPath.ReleaseBuffer();
        }
        else
        {
            m_csSymbolPath.ReleaseBuffer();
			m_csSymbolPath = "SRV*c:\\Windows\\Symbols*http://msdl.microsoft.com/download/symbols";
        }
        //add the hook dll path so that it can load the pdb of hookdll
        
        HMODULE hHookDll = GetModuleHandleA( "parasite.dll");
        if( GetModuleFileNameA( hHookDll, m_csDllPath.GetBuffer( MAX_PATH), MAX_PATH ))
        {
            m_csDllPath.ReleaseBuffer();
            int nPos = m_csDllPath.ReverseFind('\\');
            if( 0 < nPos )
            {
                m_csDllPath = m_csDllPath.Left( nPos + 1 );
            }
          
        }
	}
	bool GenerateDefaultConfigTemplate ();
	bool InjectParasite (int nPid);

	
};

