#include "Helpers.h"

using namespace std;

CString FormatError(DWORD dwError)
{
    CString strError;
    char*   pszError;

    // Format string using default language.
    ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&pszError, 0, NULL);

    // Copy message and free buffer.
    strError = pszError;
    ::LocalFree(pszError);

    // Trim excess whitespace.
    strError.Trim();

    return strError;
}

void InitLsaString(PLSA_UNICODE_STRING LsaString,LPWSTR String)
{
    DWORD StringLength;

    if(String == NULL) {
        LsaString->Buffer = NULL;
        LsaString->Length = 0;
        LsaString->MaximumLength = 0;
        return;
    }

    StringLength = lstrlenW(String);
    LsaString->Buffer = String;
    LsaString->Length = (USHORT) StringLength * sizeof(WCHAR);
    LsaString->MaximumLength=(USHORT)(StringLength+1) * sizeof(WCHAR);
}

//	Global function to get a SID given a name and a server (From CodeProject)
PSID GetSid( LPCTSTR pszName, LPCTSTR pszServer )
{
    PSID		 pSid = PSID(NULL);
    TCHAR		 ptszDomainName[256];
    DWORD		 dwSIDSize = 0,
        dwDomainNameSize = sizeof(ptszDomainName);
    SID_NAME_USE snuType = SidTypeUnknown;

    LookupAccountName(pszServer, pszName, NULL, &dwSIDSize, NULL, &dwDomainNameSize, &snuType);

    if (dwSIDSize)
    {
        //	Success, now allocate our buffers
        pSid = (PSID) new BYTE[dwSIDSize];

        if (!LookupAccountName(NULL, pszName, pSid, &dwSIDSize, ptszDomainName, &dwDomainNameSize, &snuType))
        {
            delete pSid;
            pSid = PSID(NULL);
        }
    }

    return pSid;
}

CString GetMachineName ()
{
    USES_CONVERSION;
    DWORD dwLevel = 102;
    LPWKSTA_INFO_102 pBuf = NULL;
    NET_API_STATUS nStatus;

    // Machine name
    CString name = "";

    nStatus = NetWkstaGetInfo( NULL, dwLevel, (LPBYTE*) &pBuf );

    if ( nStatus == NERR_Success )
    {
        name = W2A ( pBuf->wki102_computername );
    }

    if ( pBuf != NULL )
    {
        NetApiBufferFree(pBuf);
    }

    return name;
}