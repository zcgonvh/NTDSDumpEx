/**
 *  The MIT License:
 *
 *  Copyright (c) 2010, 2013 Kevin Devine
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"),  to deal
 *  in the Software without restriction,  including without limitation the rights
 *  to use,  copy,  modify,  merge,  publish,  distribute,  sublicense,  and/or sell
 *  copies of the Software,  and to permit persons to whom the Software is
 *  furnished to do so,  subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND,  EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */
#ifndef NTDS_H
#define NTDS_H

#define UNICODE
#define _CRT_SECURE_NO_WARNINGS
#define JET_VERSION 0x0501

#include <windows.h> 
#include <esent.h>
#include <Sddl.h>

#include <string>
#include <vector>
#include <algorithm>

#include "attributes.h"

#define NTDS_PAGE_SIZE 8192

#define SAM_DOMAIN_OBJECT             0x00000000
#define SAM_GROUP_OBJECT				      0x10000000
#define SAM_NON_SECURITY_GROUP_OBJECT	0x10000001
#define SAM_ALIAS_OBJECT				      0x20000000
#define SAM_NON_SECURITY_ALIAS_OBJECT	0x20000001
#define SAM_USER_OBJECT					      0x30000000
#define SAM_MACHINE_ACCOUNT				    0x30000001
#define SAM_TRUST_ACCOUNT				      0x30000002
#define SAM_APP_BASIC_GROUP           0x40000000
#define SAM_APP_QUERY_GROUP           0x40000001
#define SAM_ACCOUNT_TYPE_MAX          0x7fffffff

typedef enum  {
	ADS_UF_SCRIPT = 1,        // 0x1
	ADS_UF_ACCOUNTDISABLE = 2,        // 0x2
	ADS_UF_HOMEDIR_REQUIRED = 8,        // 0x8
	ADS_UF_LOCKOUT = 16,       // 0x10
	ADS_UF_PASSWD_NOTREQD = 32,       // 0x20
	ADS_UF_PASSWD_CANT_CHANGE = 64,       // 0x40
	ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,      // 0x80
	ADS_UF_TEMP_DUPLICATE_ACCOUNT = 256,      // 0x100
	ADS_UF_NORMAL_ACCOUNT = 512,      // 0x200
	ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048,     // 0x800
	ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096,     // 0x1000
	ADS_UF_SERVER_TRUST_ACCOUNT = 8192,     // 0x2000
	ADS_UF_DONT_EXPIRE_PASSWD = 65536,    // 0x10000  
	ADS_UF_MNS_LOGON_ACCOUNT = 131072,   // 0x20000
	ADS_UF_SMARTCARD_REQUIRED = 262144,   // 0x40000
	ADS_UF_TRUSTED_FOR_DELEGATION = 524288,   // 0x80000
	ADS_UF_NOT_DELEGATED = 1048576,  // 0x100000
	ADS_UF_USE_DES_KEY_ONLY = 2097152,  // 0x200000
	ADS_UF_DONT_REQUIRE_PREAUTH = 4194304,  // 0x400000
	ADS_UF_PASSWORD_EXPIRED = 8388608,  // 0x800000
	ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216 // 0x1000000
} ADS_USER_FLAG_ENUM;

#define SYSTEM_KEY_LEN 16

#define LM_HASH_LEN 16
#define NT_HASH_LEN 16

// ===============================================
// PEK defines / structures
#define PEK_REVISION_1 1 // windows 2000 ?
#define PEK_REVISION_2 2 // windows 2003

#define PEK_SALT_LEN  16
#define PEK_AUTH_LEN  16
#define PEK_VALUE_LEN 16

#define PEK_SALT_ROUNDS 1000

typedef struct _PEK_HDR {
	DWORD dwMajor;             // either 1 or 2
	DWORD dwMinor;             // possibly inaccurate description
	BYTE bSalt[PEK_SALT_LEN];  // added with version 2
} PEK_HDR, *PPEK_HDR;

// unknown1 and unknown2 are used but I haven't investigated
// since the key probably doesn't get changed much
typedef struct _PEK_DATA {
	BYTE bAuth[PEK_AUTH_LEN];  // verifies if decryption successful
	FILETIME ftModified;       // when list was last changed
	DWORD dwUnknown1;          // 
	DWORD dwTotalKeys;         // total keys in list
	DWORD dwUnknown2;          // 
	BYTE bKey[PEK_VALUE_LEN];  // list can support multiple keys but it's not supported here at the moment.
} PEK_DATA, *PPEK_DATA;

typedef struct _PEK_LIST {
	PEK_HDR Hdr;
	PEK_DATA Data;
} PEK_LIST, *PPEK_LIST;

// There appears to be variations or revisions with this
// specific structure more than others.
// I've only studied Windows 2003/2008 server
// 
// Seems to work fine with those . . .
//
typedef struct _SECRET_DATA {
	WORD wVersion;             //
	WORD wUnknown;             // seems reserved
	DWORD dwPEKIndex;          // key index for PEK_LIST
	BYTE bSalt[PEK_SALT_LEN];  // RtlGenRandom();
	BYTE pbData;
} SECRET_DATA, *PSECRET_DATA;

// ===============================================

#ifdef DEBUG
#define dprintf printf
#else
#define dprintf
#endif

typedef struct _COLUMN_INFO {
	char name[JET_cbNameMost + 1];   // column name
	ULONG uColumnId;
	ULONG uAttrId;
} COLUMN_INFO, *PCOLUMN_INFO;

class NTDS {
private:
	JET_INSTANCE instance;
	JET_SESID sesId;
	JET_DBID dbId;
	JET_TABLEID tableId;
	JET_ERR err;

	DWORD dwError;
	std::wstring dbName;
	BOOL bPrintSize;

	PEK_LIST pekList;            // size might exceed structure 
	// i estimate very rarely 
	BOOL EnumColumns(VOID);
	ULONG GetColumnId(DWORD);
	BOOL IsAccountInactive(DWORD);
	BOOL IsAccountMachine(DWORD);
	DWORD GetColumnData(ULONG, PVOID, DWORD);
	VOID DumpHash(DWORD, PBYTE, FILE*,char);
	VOID DisplayDecrypted(DWORD, PBYTE, FILE*, char);
	VOID PEKDecryptSecretDataBlock(PBYTE, DWORD);
	BOOL EncryptDecryptWithKey(PBYTE, DWORD, PBYTE, DWORD, DWORD, PBYTE, DWORD);
	std::vector<COLUMN_INFO> columns;  // only attributes
public:
	NTDS();
	~NTDS();

	BOOL Load(char*);
	BOOL UnLoad(VOID);

	BOOL GetPEKey(PBYTE, PBYTE);
	BOOL GetHashes(char, BOOL, BOOL, BOOL, BOOL, FILE*, DWORD*, DWORD*, DWORD*, DWORD*);
	std::string GetError(VOID);
};

#endif

