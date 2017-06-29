#ifndef PANICBUTTON_MAIN_H
#define PANICBUTTON_MAIN_H

#include <windows.h>

void banner(void);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);

#endif //PANICBUTTON_MAIN_H
