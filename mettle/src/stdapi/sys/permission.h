#ifndef _PERMISSION_H
#define _PERMISSION_H

// Generic process open permissions
#define PROCESS_READ               (1 <<  0)
#define PROCESS_WRITE              (1 <<  1)
#define PROCESS_EXECUTE            (1 <<  2)
#define PROCESS_ALL               0xffffffff

#ifndef __MINGW32__

// Generic page protection flags
#define PROT_NONE                         0
#define PROT_READ                  (1 <<  0)
#define PROT_WRITE                 (1 <<  1)
#define PROT_EXEC                  (1 <<  2)
#define PROT_COW                   (1 << 20)

// Generic permissions
#define GEN_NONE                          0
#define GEN_READ                   (1 <<  0)
#define GEN_WRITE                  (1 <<  1)
#define GEN_EXEC                   (1 <<  2)

// Granular process open permissions
#define PROCESS_VM_OPERATION        (1 << 3)
#define PROCESS_VM_READ             (1 << 4)
#define PROCESS_QUERY_INFORMATION 0x00000400
#define PROCESS_SET_SESSIONID       (1 << 2)
#define PROCESS_VM_WRITE          0x00000020
#define PROCESS_DUP_HANDLE        0x00000040
#define PROCESS_SET_QUOTA         0x00000100
#define PROCESS_SET_INFORMATION   0x00000200
#define PROCESS_TERMINATE           (1 << 0)
#define PROCESS_CREATE_THREAD       (1 << 1)
#define PROCESS_CREATE_PROCESS    0x00000080
#define PROCESS_SUSPEND_RESUME    0x00000800

#endif

#endif
