#include "NTRight.h"

NTRight::NTRight( CString sPrincipal, NTRightType sRight )
{
    this->setError("0");
    this->setPrincipal(sPrincipal);
    this->setRight(sRight);

    // Determine sid for account
    this->userSid = GetSid ( this->getPrincipal(), "" );
}

NTRight::~NTRight( )
{
    //// Free object's SID buffer
    //if (this->userSid != NULL) 
    //{
    //    HeapFree( GetProcessHeap(), 0, this->userSid );
    //}
}

bool NTRight::Revoke ( )
{
   // MessageBox ( NULL, "NTRights::Revoke", "NTRights::Revoke", MB_OK );

    int result = this->ModifyPriviledge(false);

    if (result != STATUS_SUCCESS)
    {return false;} else {return true;}
}

bool NTRight::Grant ( )
{
    // MessageBox ( NULL, "NTRights::Grant", "NTRights::Grant", MB_OK );

    int result = this->ModifyPriviledge(true);

    if (result != STATUS_SUCCESS)
    {return false;} else {return true;}
}

bool NTRight::ModifyPriviledge(bool bGrant)
{
    USES_CONVERSION;
    LSA_HANDLE PolicyHandle;
    //PSID pSid; -> prompoted to field
    NTSTATUS Status;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_UNICODE_STRING ServerString;
    PLSA_UNICODE_STRING Server;
    bool res = true;

    // Always initialize the object attributes to all zeroes.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    // Machine name
    LPWSTR ServerName = A2W( ::GetMachineName() );
    InitLsaString(&ServerString, ServerName); // Make a LSA_UNICODE_STRING out of the LPWSTR passed in
    Server = &ServerString;

    // Attempt to open the policy with change rights
    DWORD DesiredAccess = POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES;
    Status = LsaOpenPolicy(Server,&ObjectAttributes,DesiredAccess,&PolicyHandle);

    if(Status != STATUS_SUCCESS) 
    {
        this->setError( "Error while opening machine policy: " + ::FormatError(Status) );
        return false;
    }

    // Grant / Revoke privilege
    LSA_UNICODE_STRING PrivilegeString; InitLsaString(&PrivilegeString, A2W( this->getRight() ) ); // Create a LSA_UNICODE_STRING for the privilege name.
    
    if( bGrant )
    {
        // Grant
        Status = LsaAddAccountRights( PolicyHandle, this->getSid(), &PrivilegeString, TRUE );
        if(Status != STATUS_SUCCESS)
        {
            this->setError( "Error while modifying priviledge: " +::FormatError(Status) );
            res = false;
        }
    }
    else
    {
        // Revoke
        Status =  LsaRemoveAccountRights( PolicyHandle, this->getSid(), FALSE, &PrivilegeString, 1);
        if(Status != STATUS_SUCCESS)
        {
            this->setError( "Error while modifying priviledge: " +::FormatError(Status) );
            res = false;
        }
    }

    // Cleanup
    LsaClose( PolicyHandle );

    return res;
}

// Translate NTRight enum values to corresponding strings
CString NTRight::ResolveNTRightName()
{
    if ( right == NTRightType::SeCreateTokenPrivilege )
    {
        return "SeCreateTokenPrivilege";
    }
    else if ( right == NTRightType::SeAssignPrimaryTokenPrivilege )
    {
        return "SeAssignPrimaryTokenPrivilege";
    }
    else if ( right == NTRightType::SeLockMemoryPrivilege )
    {
        return "SeLockMemoryPrivilege";
    }
    else if ( right == NTRightType::SeIncreaseQuotaPrivilege )
    {
        return "SeIncreaseQuotaPrivilege";
    }
    else if ( right == NTRightType::SeUnsolicitedInputPrivilege )
    {
        return "SeUnsolicitedInputPrivilege";
    }
    else if ( right == NTRightType::SeMachineAccountPrivilege )
    {
        return "SeMachineAccountPrivilege";
    }
    else if ( right == NTRightType::SeTcbPrivilege )
    {
        return "SeTcbPrivilege";
    }
    else if ( right == NTRightType::SeSecurityPrivilege )
    {
        return "SeSecurityPrivilege";
    }
    else if ( right == NTRightType::SeTakeOwnershipPrivilege )
    {
        return "SeTakeOwnershipPrivilege";
    }
    else if ( right == NTRightType::SeLoadDriverPrivilege )
    {
        return "SeLoadDriverPrivilege";
    }
    else if ( right == NTRightType::SeSystemProfilePrivilege )
    {
        return "SeSystemProfilePrivilege";
    }
    else if ( right == NTRightType::SeSystemtimePrivilege )
    {
        return "SeSystemtimePrivilege";
    }
    else if ( right == NTRightType::SeProfileSingleProcessPrivilege )
    {
        return "SeProfileSingleProcessPrivilege";
    }
    else if ( right == NTRightType::SeIncreaseBasePriorityPrivilege )
    {
        return "SeIncreaseBasePriorityPrivilege";
    }
    else if ( right == NTRightType::SeCreatePagefilePrivilege )
    {
        return "SeCreatePagefilePrivilege";
    }
    else if ( right == NTRightType::SeCreatePermanentPrivilege )
    {
        return "SeCreatePermanentPrivilege";
    }
    else if ( right == NTRightType::SeBackupPrivilege )
    {
        return "SeBackupPrivilege";
    }
    else if ( right == NTRightType::SeRestorePrivilege )
    {
        return "SeRestorePrivilege";
    }
    else if ( right == NTRightType::SeShutdownPrivilege )
    {
        return "SeShutdownPrivilege";
    }
    else if ( right == NTRightType::SeAuditPrivilege )
    {
        return "SeAuditPrivilege";
    }
    else if ( right == NTRightType::SeSystemEnvironmentPrivilege )
    {
        return "SeSystemEnvironmentPrivilege";
    }
    else if ( right == NTRightType::SeChangeNotifyPrivilege )
    {
        return "SeChangeNotifyPrivilege";
    }
    else if ( right == NTRightType::SeRemoteShutdownPrivilege )
    {
        return "SeRemoteShutdownPrivilege";
    }
    else if ( right == NTRightType::SeBatchLogonRight )
    {
        return "SeBatchLogonRight";
    }
    else if ( right == NTRightType::SeCreateGlobalPrivilege )
    {
        return "SeCreateGlobalPrivilege";
    }
    else if ( right == NTRightType::SeDebugPrivilege )
    {
        return "SeDebugPrivilege";
    }
    else if ( right == NTRightType::SeDenyBatchLogonRight )
    {
        return "SeDenyBatchLogonRight";
    }
    else if ( right == NTRightType::SeDenyInteractiveLogonRight )
    {
        return "SeDenyInteractiveLogonRight";
    }
    else if ( right == NTRightType::SeDenyNetworkLogonRight )
    {
        return "SeDenyNetworkLogonRight";
    }
    else if ( right == NTRightType::SeDenyServiceLogonRight )
    {
        return "SeDenyServiceLogonRight";
    }
    else if ( right == NTRightType::SeEnableDelegationPrivilege )
    {
        return "SeEnableDelegationPrivilege";
    }
    else if ( right == NTRightType::SeImpersonatePrivilege )
    {
        return "SeImpersonatePrivilege";
    }    
    else if ( right == NTRightType::SeInteractiveLogonRight )
    {
        return "SeInteractiveLogonRight";
    }
    else if ( right == NTRightType::SeNetworkLogonRight )
    {
        return "SeNetworkLogonRight";
    }
    else if ( right == NTRightType::SeServiceLogonRight )
    {
        return "SeServiceLogonRight";
    }
    else if ( right == NTRightType::SeSyncAgentPrivilege )
    {
        return "SeSyncAgentPrivilege";
    }
    else if ( right == NTRightType::SeUndockPrivilege )
    {
        return "SeUndockPrivilege";
    }
    else
    {
        return "INVALID";
    }
}

// Class "Properties"
void NTRight::setPrincipal( CString sPrincipal )
{
    principal = sPrincipal;
}

CString NTRight::getPrincipal()
{
    return principal;
}

void NTRight::setError ( CString sError )
{
    this->error = sError;
}

CString NTRight::getError ()
{
    return error;
}

void NTRight::setRight ( NTRightType sRight )
{
    right = sRight;
}

CString NTRight::getRight ()
{    
    return ResolveNTRightName();
}

PSID NTRight::getSid ()
{    
    return this->userSid;
}
