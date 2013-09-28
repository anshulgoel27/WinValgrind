#include "common.h"

HOOK_TYPE_e g_Config::g_HookType = HT_HANDLE;
int g_Config::g_StackDepth = 20;
bool g_Config::g_bTrack = true;
bool g_Config::g_bHooked = false;
CCriticalSection g_Config::SyncObj;
map<LPVOID,MEM_INFO> g_Config::m_MemMap;
CString g_Config::sDllPath;

#ifdef _M_IX86
void StackDump( LPVOID pMem, DWORD dwBytes)
{
		STACKFRAME64 stStackFrame = {0};
        CONTEXT stContext = {0};
        stContext.ContextFlags = CONTEXT_ALL;    
        __asm    call x
        __asm x: pop eax
        __asm    mov stContext.Eip, eax
        __asm    mov stContext.Ebp, ebp
        __asm    mov stContext.Esp, esp

        stStackFrame.AddrPC.Offset = stContext.Eip;
        stStackFrame.AddrPC.Mode = AddrModeFlat;
        stStackFrame.AddrFrame.Offset = stContext.Ebp;
        stStackFrame.AddrFrame.Mode = AddrModeFlat;
        stStackFrame.AddrStack.Offset = stContext.Esp;
        stStackFrame.AddrStack.Mode = AddrModeFlat;
 
//         BYTE SymBol[ sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN ] = {0};
// 
//         SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)SymBol;
//         pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
//         pSymbol->MaxNameLen = STACKWALK_MAX_NAMELEN;
// 
//         IMAGEHLP_LINE64 Line = {0};
//         Line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );
        
        HANDLE hProcess = GetCurrentProcess();
        MEM_INFO stInfo;
        //stInfo.parCallStack = new STACK_ARRAY;
        
		//void * p = AllocMem(sizeof(STACK_ARRAY));
        //stInfo.parCallStack = new( (void*)p ) STACK_ARRAY;
        
        stInfo.nMemSize = dwBytes;
        for( int i =0; i < g_Config::g_StackDepth ; i++ )// only retrieve 40 functions
        {
            BOOL b = StackWalk64( IMAGE_FILE_MACHINE_I386, hProcess, GetCurrentThread(), 
                              &stStackFrame ,&stContext, 0, 
                              SymFunctionTableAccess64 , SymGetModuleBase64, NULL );
            if ( !b )
            {
               break;
            }
            DWORD64 dwDisplacement = 0;
            if (stStackFrame.AddrPC.Offset == stStackFrame.AddrReturn.Offset)
            {
              break;
            }

//////////////////////////////////////////////////////////////////////////
        //if( SymFromAddr( hProcess, stStackFrame.AddrPC.Offset, &dwDisplacement, pSymbol ))
        //{
        //		CString cs = "Ordinal823";
        //	if( cs == pSymbol->Name)
        //		{
        //			break;
        //		}
        //			
        //}
//////////////////////////////////////////////////////////////////////////

            if( i <= 1 )// ignore the functions on the top of stack which is our own.
            {
                continue;
            }
			stInfo.parCallStack.push_back( stStackFrame.AddrPC.Offset );
        }
        g_Config::m_MemMap[pMem] = stInfo;        
}

#else
void StackDump( LPVOID pMem, SIZE_T dwBytes)
{
        
    CONTEXT                       Context;
    //KNONVOLATILE_CONTEXT_POINTERS NvContext;
    //UNWIND_HISTORY_TABLE          UnwindHistoryTable;
    PRUNTIME_FUNCTION             RuntimeFunction;
    PVOID                         HandlerData;
    ULONG64                       EstablisherFrame;
    ULONG64                       ImageBase;

    //OutputDebugString(L"StackTrace64: Executing stack trace...\n");

    //
    // First, we'll get the caller's context.
    //

    RtlCaptureContext(&Context);

    //
    // Initialize the (optional) unwind history table.
    //

    /*RtlZeroMemory(
        &UnwindHistoryTable,
        sizeof(UNWIND_HISTORY_TABLE));*/

    
        //BYTE SymBol[ sizeof(SYMBOL_INFO) + STACKWALK_MAX_NAMELEN ] = {0};
        //SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)SymBol;
        //DWORD64 dwDisplacement;
     
        HANDLE hProcess = GetCurrentProcess();
        MEM_INFO stInfo;
        //stInfo.parCallStack = new STACK_ARRAY;
        
        //void * p = AllocMem(sizeof(STACK_ARRAY));
        //stInfo.parCallStack = new( (void*)p ) STACK_ARRAY;

        stInfo.nMemSize = dwBytes;
        for( int i =0; i < g_StackDepth ; i++ )// only retrieve 40 functions
        {
            //
        // Try to look up unwind metadata for the current function.
        //

        RuntimeFunction = RtlLookupFunctionEntry(
            Context.Rip,
            &ImageBase,
            NULL
            );

        /*RtlZeroMemory(
            &NvContext,
            sizeof(KNONVOLATILE_CONTEXT_POINTERS));*/

        if (!RuntimeFunction)
        {
            //
            // If we don't have a RUNTIME_FUNCTION, then we've encountered
            // a leaf function.  Adjust the stack approprately.
            //

            Context.Rip  = (ULONG64)(*(PULONG64)Context.Rsp);
            Context.Rsp += 8;
        }
        else
        {
            //
            // Otherwise, call upon RtlVirtualUnwind to execute the unwind for
            // us.
            //

            RtlVirtualUnwind(
                0, //UNW_FLAG_NHANDLER,
                ImageBase,
                Context.Rip,
                RuntimeFunction,
                &Context,
                &HandlerData,
                &EstablisherFrame,
                NULL );
        }

        //
        // If we reach an RIP of zero, this means that we've walked off the end
        // of the call stack and are done.
        //

        if (!Context.Rip)
            break;

//////////////////////////////////////////////////////////////////////////
         
                 //if( SymFromAddr( hProcess, Context.Rip, &dwDisplacement, pSymbol ))
                 //{
                 //    CString cs = "Ordinal823";
                 //     if( cs == pSymbol->Name)
                 //    {
                 //        break;
                 //    }
                 //   
                 //}
//////////////////////////////////////////////////////////////////////////

            if( i <= 1 )// ignore the functions on the top of stack which is our own.
            {
                continue;
            }
            stInfo.parCallStack.push_back( Context.Rip );
        }        
        g_Config::m_MemMap[pMem] = stInfo;        
}
#endif


void CreateCallStack( LPVOID lpMem, SIZE_T dwBytes )
{
    if( !lpMem )
    {
		return;
    }
    try
    {		
        CSingleLock lockObj( &g_Config::SyncObj, TRUE );
        if( g_Config::g_bHooked && g_Config::g_bTrack )
        {
            g_Config::g_bTrack = false;
			StackDump( lpMem, dwBytes );
#ifdef ENABLE_LOG
            CString cs;
            cs.Format( "Allocating    %x" ,(UINT)lpMem);
            OutputDebugString(cs);
#endif
            g_Config::g_bTrack = true;
        }
    }
    catch(...)
    {
    }
    
}

void RemovCallStack( LPVOID lpMem )
{
    try
    {
        if( !lpMem )
        {
            return;
        }

        CSingleLock lockObj( &g_Config::SyncObj, TRUE );
        if( g_Config::g_bHooked && g_Config::g_bTrack )
        {
            g_Config::g_bTrack = false;
            MEM_INFO stInfo;
			if( g_Config::m_MemMap.find(lpMem)!=g_Config::m_MemMap.end())
            {
                //delete stInfo.parCallStack;
				stInfo = g_Config::m_MemMap[lpMem];
				stInfo.parCallStack.clear();
				stInfo.parCallStack.~vector();
				g_Config::m_MemMap.erase(lpMem);
#ifdef ENABLE_LOG
                CString cs;
                cs.Format( "De-allocating %x" ,(UINT)lpMem);
                OutputDebugString(cs);
#endif
            }
            g_Config::g_bTrack = true;
        }
    }
    catch(...)
    {
    }	
}

