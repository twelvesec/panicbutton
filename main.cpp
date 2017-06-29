#define _WIN32_WINNT 0x0501

#include "main.h"
#include "winpmem.h"
#include <PowrProf.h>
#include <iostream>
#include <getopt.h>

bool silent = false;

#define Log(x, ...) if(!silent) _tprintf(x, __VA_ARGS__)

using namespace std;

void banner(void) {
    Log(TEXT(
            "  ______              __          _____          \n"
            " /_  __/      _____  / /   _____ / ___/___  _____\n"
            "  / / | | /| / / _ \\/ / | / / _ \\\\__ \\/ _ \\/ ___/\n"
            " / /  | |/ |/ /  __/ /| |/ /  __/__/ /  __/ /__  \n"
            "/_/   |__/|__/\\___/_/ |___/\\___/____/\\___/\\___/  \n"
            "\n"
            "TwelveSec Panic Button.\n"
            "This program is designed to dump the target system raw memory in to a file and hibernate.\n\n"
            "Copyright (C) 2017 Twelvesec\n"
            "\n"
            "This program is free software: you can redistribute it and/or modify\n"
            "it under the terms of the GNU General Public License version 3 as published by\n"
            "the Free Software Foundation.\n"
            "\n"
            "This program is distributed in the hope that it will be useful,\n"
            "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
            "GNU General Public License for more details.\n"
            "\n"
            "You should have received a copy of the GNU General Public License\n"
            "along with this program.  If not, see <http://www.gnu.org/licenses/>.\n\n"
            "Attributions:\n"
            "    Winpmem - https://github.com/google/rekall/tree/master/tools/windows/winpmem\n"
            "\n"
            "Help:\n"
            "    -s  Silent mode.\n\n"
    ), 0);
}

int _tmain(int argc, _TCHAR *argv[]) {
    __int64 status;

    HANDLE procHandle = GetCurrentProcess();
    HANDLE accToken = NULL;
    uint32_t mode = PMEM_MODE_AUTO;
    WinPmem *pmem_handle = WinPmemFactory();
    TCHAR *driver_filename = NULL;
    TCHAR *output_file = (TCHAR *) TEXT("test.raw");
    int c;

    opterr = 0;

    while ((c = getopt(argc, argv, "s")) != -1)
        switch (c) {
            case 's':
                silent = true;
                break;
            case '?':
                Log(TEXT("Unknown option.\n"), optopt);
                return 1;
            default:
                abort();
        }

    if(silent) {
        pmem_handle->suppress_output = true;
    }
    banner();
    pmem_handle->set_driver_filename(driver_filename);
    status = pmem_handle->create_output_file(output_file);

    if (status > 0 && pmem_handle->install_driver() > 0 && pmem_handle->set_acquisition_mode(mode) > 0) {
        status = pmem_handle->write_raw_image();
    };

    pmem_handle->uninstall_driver();

    delete pmem_handle;

    if (OpenProcessToken(procHandle, TOKEN_WRITE | TOKEN_READ | TOKEN_QUERY, &accToken)) {
        SetPrivilege(accToken, "SeShutdownPrivilege", TRUE);
    }
    if(!SetSuspendState(TRUE, TRUE, TRUE))
        Log(TEXT("SetSuspendState error: %u\n"), (unsigned int) GetLastError());

    return (int) status;

}

BOOL SetPrivilege(
        HANDLE hToken,          // access token handle
        LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
        BOOL bEnablePrivilege   // to enable or disable privilege
) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid))        // receives LUID of privilege
    {
        Log(TEXT("LookupPrivilegeValue error: %u\n"), (unsigned int) GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES) NULL,
            (PDWORD) NULL)) {
        Log(TEXT("AdjustTokenPrivileges error: %u\n"), (unsigned int) GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        Log(TEXT("The token does not have the specified privilege. \n"), 0);
        return FALSE;
    }

    return TRUE;
}