#pragma once
#include "stdafx.h"
#include "Classes\NTRight.h"

#ifndef UNICODE
#define UNICODE
#endif

int _tmain(int argc, _TCHAR* argv[])
{
    NTRight* right1 = new NTRight("DOMAIN\\USER", NTRightType::SeBatchLogonRight );

    right1->Grant();
    //right1->Revoke();

    right1->~NTRight();

    return 0;
}

// http://www.nomoreasp.net/2007/12/14/lsaopenaccount-not-needed/
// http://www.codeguru.com/cpp/w-p/files/folderdirectorymaintenance/print.php/c4457
