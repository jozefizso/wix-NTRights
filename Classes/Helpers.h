#pragma once
// MFC included first to avoid link errors
#include "..\stdafx.h"
#include "ntsecapi.h"
#include <lm.h>   // NetApi32.lib
#include "Aclapi.h" // Security

#include <stdio.h>
#include <sddl.h>

//# pragma comment(lib, "wbemuuid.lib")
//# pragma comment(lib, "Advapi32.lib")
//# pragma comment(lib, "psapi.lib")
//# pragma comment(lib, "IPHlpApi.Lib")
# pragma comment(lib, "netapi32.lib")

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13

CString    FormatError        ( DWORD dwError );
PSID       GetSid             ( LPCTSTR pszName, LPCTSTR pszServer );
CString    GetMachineName     ();
void       InitLsaString      (PLSA_UNICODE_STRING LsaString, LPWSTR String);
