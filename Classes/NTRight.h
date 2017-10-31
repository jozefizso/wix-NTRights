#pragma once
#include "..\stdafx.h"
#include <atlstr.h>
#include "ntsecapi.h"
#include "windows.h"

#include "Helpers.h"

// If you have the ddk, include ntstatus.h.
//#include "ntstatus.h"
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

typedef enum
{
    SeCreateTokenPrivilege = 0x00000001, 
    SeAssignPrimaryTokenPrivilege,
    SeLockMemoryPrivilege,
    SeIncreaseQuotaPrivilege,
    SeUnsolicitedInputPrivilege,
    SeMachineAccountPrivilege,
    SeTcbPrivilege,
    SeSecurityPrivilege,
    SeTakeOwnershipPrivilege,
    SeLoadDriverPrivilege,
    SeSystemProfilePrivilege,
    SeSystemtimePrivilege,
    SeProfileSingleProcessPrivilege,
    SeIncreaseBasePriorityPrivilege,
    SeCreatePagefilePrivilege,
    SeCreatePermanentPrivilege,
    SeBackupPrivilege,
    SeRestorePrivilege,
    SeShutdownPrivilege,
    SeAuditPrivilege,
    SeSystemEnvironmentPrivilege,
    SeChangeNotifyPrivilege,
    SeRemoteShutdownPrivilege,
    SeBatchLogonRight,
    SeCreateGlobalPrivilege,
    SeDebugPrivilege,
    SeDenyBatchLogonRight,
    SeDenyInteractiveLogonRight,
    SeDenyNetworkLogonRight,
    SeDenyServiceLogonRight,
    SeEnableDelegationPrivilege,
    SeImpersonatePrivilege,
    SeInteractiveLogonRight,
    SeNetworkLogonRight,
    SeServiceLogonRight,
    SeSyncAgentPrivilege,
    SeUndockPrivilege,
} NTRightType;


class NTRight
{

public:

    // Constructors / Destructor
    NTRight( CString sPrincipal, NTRightType sRight );
    ~NTRight( void );

    // Methods
    bool      Grant ( );
    bool      Revoke ( );

    // "Properties"
    CString   getError ();
    PSID      getSid ();

    void      setPrincipal ( CString sPrincipal );
    CString   getPrincipal ();
    void      setRight ( NTRightType sRight );
    CString   getRight ();

private:

    // Private Methods
    void       setError ( CString sError );
    CString    ResolveNTRightName();
    bool       ModifyPriviledge(bool bGrant);

    // Fields
    CString     principal;
    NTRightType right;
    CString     error;
    PSID        userSid;
};

/* 

potentially dangerous privileges

SeAssignPrimaryTokenPrivilege
SeBackupPrivilege
SeDebugPrivilege
SeIncreaseQuotaPrivilege
SeTchPrivilege

From: http://support.microsoft.com/kb/279664

NTRights.Exe - Beta Version by Georg Zanzen
Grants/Revokes NT-Rights to a user/group
usage: -u xxx  User/Group
-m \\xxx  machine to perform the operation on (default local machine)
-e xxxxx Add xxxxx to the event log
-r xxx  revokes the xxx right
+r xxx  grants the xxx right

Valid NTRights are:

SeCreateTokenPrivilege
SeAssignPrimaryTokenPrivilege
SeLockMemoryPrivilege
SeIncreaseQuotaPrivilege
SeUnsolicitedInputPrivilege
SeMachineAccountPrivilege
SeTcbPrivilege
SeSecurityPrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeProfileSingleProcessPrivilege
SeIncreaseBasePriorityPrivilege
SeCreatePagefilePrivilege
SeCreatePermanentPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeShutdownPrivilege
SeAuditPrivilege
SeSystemEnvironmentPrivilege
SeChangeNotifyPrivilege
SeRemoteShutdownPrivilege

Additional (appears undocumented):
SeBatchLogonRight
SeCreateGlobalPrivilege
SeDebugPrivilege
SeDenyBatchLogonRight
SeDenyInteractiveLogonRight
SeDenyNetworkLogonRight
SeDenyServiceLogonRight
SeEnableDelegationPrivilege
SeImpersonatePrivilege
SeInteractiveLogonRight
SeNetworkLogonRight
SeServiceLogonRight
SeSyncAgentPrivilege
SeUndockPrivilege
*/
