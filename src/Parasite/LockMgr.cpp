#include "LockMgr.h"

//---------------------------------------------------------------------------
//
// class CCSWrapper 
//
// CRTICIAL_SECTION user object wrapper
//
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
//
// Constructor
//
//---------------------------------------------------------------------------
CCSWrapper::CCSWrapper()
{
	m_nSpinCount = 0;
	::InitializeCriticalSection( &m_cs );
}

//---------------------------------------------------------------------------
//
// Destructor
//
//---------------------------------------------------------------------------
CCSWrapper::~CCSWrapper()
{
	::DeleteCriticalSection( &m_cs );
}


//---------------------------------------------------------------------------
// Enter 
//
// This function waits for ownership of the specified critical section object 
//---------------------------------------------------------------------------
void CCSWrapper::Enter()
{
	::EnterCriticalSection( &m_cs );
	m_nSpinCount++;
}

//---------------------------------------------------------------------------
// Leave
//
// Releases ownership of the specified critical section object. 
//---------------------------------------------------------------------------
void CCSWrapper::Leave()
{
	m_nSpinCount--;
	::LeaveCriticalSection( &m_cs );
}

//--------------------- End of the file -------------------------------------
