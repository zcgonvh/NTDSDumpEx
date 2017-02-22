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

#include "ntds.h"

#pragma comment(lib, "esent.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

/**********************************************************
 *
 *  + Set page size
 *  + Set recovery off
 *  + Create instance
 *  + Create session
 *
 **********************************************************/
NTDS::NTDS() {

	instance = NULL;
	sesId = NULL;
	dbId = NULL;

	// set the page size for NTDS.dit
	err = JetSetSystemParameter(&instance, JET_sesidNil,
		JET_paramDatabasePageSize, NTDS_PAGE_SIZE, NULL);
	if (err == JET_errSuccess) {
		// Turn off recovery mode
		err = JetSetSystemParameter(&instance, JET_sesidNil,
			JET_paramRecovery, NULL, (JET_PCSTR)"Off");
		if (err == JET_errSuccess) {
			// create an instance
			err = JetCreateInstance(&instance, (JET_PCSTR)"ntdsdump_0_2");
			if (err == JET_errSuccess) {
				// initialize
				err = JetInit(&instance);
				if (err == JET_errSuccess) {
					// create session
					err = JetBeginSession(instance, &sesId, NULL, NULL);
				}
				else {
				}
			}
			else {
			}
		}
		else {
		}
	}
	else {
	}
}

/**********************************************************
 *
 *  + Close database
 *  + Detach database
 *  + End session
 *  + Terminate instance
 *
 **********************************************************/
NTDS::~NTDS() {

	if (dbId != NULL || sesId != NULL || instance != NULL || !dbName.empty()) {

		UnLoad();

		if (dbName.empty() && sesId != NULL) {
			// end session
			err = JetEndSession(sesId, 0);
			if (err == JET_errSuccess) {
				sesId = NULL;
			}
			else {
			}
		}
		if (sesId == NULL && instance != NULL) {
			// terminate instance
			err = JetTerm(instance);
			if (err == JET_errSuccess) {
				instance = NULL;
			}
			else {
			}
		}
	}
}

/**********************************************************
 *
 *  + Attach database
 *  + Open database
 *  + Enumerate columns
 *
 **********************************************************/
BOOL NTDS::Load(char* fname) {

	UnLoad();

	wchar_t wsConnect[128] = { 0 };
	// attach database
	// unicode doesn't appear to be supported...
	// yes..this will cause problems if the database name uses special characters
	//std::string database(fname.begin(), fname.end());
	err = JetAttachDatabaseA(sesId, fname, JET_bitDbReadOnly);
	if (err == JET_errSuccess) {
		std::string database(fname);
		dbName = std::wstring(database.begin(), database.end());
		// open database
		err = JetOpenDatabaseA(sesId, fname,
			(JET_PCSTR)wsConnect, &dbId, JET_bitDbReadOnly);
		if (err == JET_errSuccess) {
			// enumerate columns
			EnumColumns();
		}
		else {
			printf("[x]error at JetOpenDatabase()\n");
		}
	}
	else {
		printf("[x]error at JetAttachDatabase()\n");
	}
	return err == JET_errSuccess;
}

/**********************************************************
 *
 *  + Close database
 *  + Detach database
 *
 **********************************************************/
BOOL NTDS::UnLoad(VOID) {

	// close database
	if (dbId != NULL) {
		err = JetCloseDatabase(sesId, dbId, 0);
		if (err == JET_errSuccess) {
			dbId = NULL;
		}
	}
	// detach from session
	if (dbId == NULL && !dbName.empty()) {
		std::string database(dbName.begin(), dbName.end());
		err = JetDetachDatabase(sesId, (JET_PCSTR)database.c_str());
		if (err == JET_errSuccess) {
			dbName.clear();
		}
	}
	// clear column list
	if (dbName.empty() && columns.size() != 0) {
		columns.clear();
	}
	return err == JET_errSuccess;
}

/**********************************************************
 *
 *  + Open MSysObjects
 *  + Enumerate columns
 *
 **********************************************************/
std::string NTDS::GetError(VOID) {
	char errBuffer[1024];
	JetGetSystemParameter(instance, sesId, JET_paramErrorToString,
		reinterpret_cast<JET_API_PTR *>(&err), errBuffer,
		sizeof(errBuffer) / sizeof(char));
	return errBuffer;
}

/**********************************************************
 *
 *  + Open MSysObjects
 *  + Enumerate columns
 *
 *  We're only interested in attributes for ntds.dit
 *
 **********************************************************/
BOOL NTDS::EnumColumns(VOID) {

	JET_TABLEID tableId;
	JET_COLUMNLIST colList;

	// open MSysObjects table
	err = JetOpenTable(sesId, dbId, (JET_PCSTR)"MSysObjects", NULL, 0,
		JET_bitTableReadOnly | JET_bitTableSequential, &tableId);

	if (err != JET_errSuccess) {
		return FALSE;
	}

	// obtain list of columns
	colList.cbStruct = sizeof(colList);
	err = JetGetTableColumnInfo(sesId, tableId, NULL, &colList,
		sizeof(colList), JET_ColInfoListSortColumnid);

	if (err == JET_errSuccess) {
		err = JetMove(sesId, tableId, JET_MoveFirst, JET_bitNil);
		do {
			COLUMN_INFO info;
			memset(info.name, 0, sizeof(info.name));
			// get the column name
			err = JetRetrieveColumn(sesId, tableId, colList.columnidcolumnname,
				info.name, sizeof(info.name), NULL, JET_bitNil, NULL);

			if (err == JET_errSuccess) {
				// if this is an attribute
				if (info.name[0] == 'A'
					&& info.name[1] == 'T'
					&& info.name[2] == 'T') {
					err = JetRetrieveColumn(sesId, tableId, colList.columnidcoltyp,
						&info.uColumnId, sizeof(info.uColumnId), NULL, JET_bitNil, NULL);
					if (err == JET_errSuccess) {
						info.uAttrId = atol(&info.name[4]);
						columns.push_back(info);
					}
				}
			}
			
		} while ((err = JetMove(sesId, tableId, JET_MoveNext,JET_bitNil)) == JET_errSuccess);
	}
	
	err = JetCloseTable(sesId, tableId);
	return err == JET_errSuccess;
}

/**
 *
 *  Column names can change depending on state
 *  so it's unwise to hardcode the names
 *
 */
ULONG NTDS::GetColumnId(ULONG uAttrId) {
	ULONG Id = 0;
	for (size_t i = 0; i < columns.size(); i++) {
		if (uAttrId == columns[i].uAttrId) {
			Id = columns[i].uColumnId;
			break;
		}
	}
	return Id;
}

BOOL NTDS::EncryptDecryptWithKey(PBYTE pbKey, DWORD dwKeyLen,
	PBYTE pbSalt, DWORD dwSaltLen, DWORD dwSaltRounds,
	PBYTE pbData, DWORD dwDataLen) {

	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	BOOL bResult = FALSE;

	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT)) {
		if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
			// first, the key
			CryptHashData(hHash, pbKey, dwKeyLen, 0);

			// now the salt
			for (DWORD i = 0; i < dwSaltRounds; i++) {
				CryptHashData(hHash, pbSalt, dwSaltLen, 0);
			}
			// get an RC4 key
			if (CryptDeriveKey(hProv, CALG_RC4, hHash, 0x00800000, &hKey)) {
				// decrypt or encrypt..RC4 is a stream cipher so it doesn't matter
				bResult = CryptEncrypt(hKey, NULL, TRUE, 0, pbData, &dwDataLen, dwDataLen);
				CryptDestroyKey(hKey);
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return bResult;
}

static BYTE PekListAuthenticator[PEK_AUTH_LEN] =
{ 0x56, 0xD9, 0x81, 0x48, 0xEC, 0x91, 0xD1, 0x11,
0x90, 0x5A, 0x00, 0xC0, 0x4F, 0xC2, 0xD4, 0xCF };

/**********************************************************
 *
 *  + Obtain Pek-List
 *  + Open datatable
 *  + Retrieve list and decrypt first key
 *
 **********************************************************/
BOOL NTDS::GetPEKey(PBYTE pbSysKey, PBYTE pbPEKey) {
	int pekId = GetColumnId(ATT_PEK_LIST);
	BOOL bResult = FALSE;

	// need column id at least
	if (pekId == 0) {
		return FALSE;
	}

	// open the datatable
	JET_TABLEID tableId;
	err = JetOpenTable(sesId, dbId, (JET_PCSTR)"datatable", NULL, 0,
		JET_bitTableReadOnly | JET_bitTableSequential, &tableId);

	if (err != JET_errSuccess) {
		return FALSE;
	}

	// go to first
	err = JetMove(sesId, tableId, JET_MoveFirst, JET_bitNil);
	// while good read
	while (err == JET_errSuccess) {
		DWORD dwPekListSize = 0;
		err = JetRetrieveColumn(sesId, tableId, pekId,
			(void*)&pekList, sizeof(pekList), &dwPekListSize, JET_bitNil, NULL);

		// ensure it's good read and size exceeds size of PEK_LIST structure
		if (err == JET_errSuccess && dwPekListSize >= sizeof(PEK_LIST)) {
			// decrypt the data returned
			// depending on major/minor values in data read
			// a salt may or may not be required
			EncryptDecryptWithKey(pbSysKey, SYSTEM_KEY_LEN,
				pekList.Hdr.bSalt, PEK_SALT_LEN, PEK_SALT_ROUNDS,
				(PBYTE)&pekList.Data, dwPekListSize - sizeof(PEK_HDR));

			// verify our decryption was successful.
			bResult = (memcmp(pekList.Data.bAuth, PekListAuthenticator, PEK_AUTH_LEN) == 0);
			if (bResult) {
				// if good, copy back to buffer
				memcpy(pbPEKey, pekList.Data.bKey, PEK_VALUE_LEN);
				break;
			}
		}
		err = JetMove(sesId, tableId, JET_MoveNext, JET_bitNil);
	}
	// close table
	err = JetCloseTable(sesId, tableId);
	return bResult;
}

#define ROL32(a, n)(((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))
#define ROR32(a, n)((((a) & 0xffffffff) >> (n)) | ((a) << (32 - (n))))

#ifdef BIGENDIAN
# define SWAP32(n) (n)
#else
# define SWAP32(n) \
	ROR32((((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)), 16)
#endif

/**
 *
 *  Convert a string to DES key
 *
 */
void str2key(LPBYTE str, LPBYTE key) {
	DWORD x1, x2, r1, r2;
	PDWORD p1, p2, out = (PDWORD)key;
	int i;

	p1 = (PDWORD)&str[0];
	p2 = (PDWORD)&str[3];

	x1 = SWAP32(p1[0]);
	x2 = ROL32(SWAP32(p2[0]), 4);

	for (i = 0, r1 = 0, r2 = 0; i < 4; i++) {
		r1 = ROL32((r1 | (x1 & 0xFE000000)), 8);
		r2 = ROL32((r2 | (x2 & 0xFE000000)), 8);
		x1 <<= 7;
		x2 <<= 7;
	}
	*out++ = SWAP32(r1);
	*out++ = SWAP32(r2);
}

/**
 *
 *  Convert RID to 2 DES keys
 *
 */
void rid2keys(DWORD rid, LPBYTE key1, LPBYTE key2) {
	DWORD k[4];
	LPBYTE p = (LPBYTE)k;

	// so long as we're on LE architecture
	k[0] = k[1] = k[2] = rid;
	k[3] = k[0] & 0xFFFF;
	k[3] |= k[3] << 16;

	str2key(p, key1);
	str2key(&p[7], key2);
}

typedef struct _DES_KEY_BLOB {
	BLOBHEADER Hdr;
	DWORD dwKeySize;
	BYTE rgbKeyData[8];
} DES_KEY_BLOB;

BYTE header[] = { 0x08, 0x02, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00 };

/**
 *
 *  Very similar to SAM encryption
 *
 */
void decryptHash(DWORD rid, LPBYTE pbIn, LPBYTE pbOut) {
	DWORD dwDataLen;

	HCRYPTPROV hProv;
	HCRYPTKEY hKey1, hKey2;

	DES_KEY_BLOB Blob1, Blob2;

	if (CryptAcquireContext(&hProv, NULL, NULL,
		PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {

		// initialize keys
		rid2keys(rid, Blob1.rgbKeyData, Blob2.rgbKeyData);

		Blob1.dwKeySize = 8;
		Blob2.dwKeySize = 8;

		memcpy((void*)&Blob1.Hdr, (void*)header, 8);
		memcpy((void*)&Blob2.Hdr, (void*)header, 8);

		// import keys
		CryptImportKey(hProv, (BYTE*)&Blob1, sizeof(Blob1),
			0, CRYPT_EXPORTABLE, &hKey1);

		CryptImportKey(hProv, (BYTE*)&Blob2, sizeof(Blob2),
			0, CRYPT_EXPORTABLE, &hKey2);

		dwDataLen = 8;
		CryptDecrypt(hKey1, NULL, TRUE, 0, pbIn, &dwDataLen);
		memcpy(pbOut, pbIn, 8);

		dwDataLen = 8;
		CryptDecrypt(hKey2, NULL, TRUE, 0, pbIn + 8, &dwDataLen);
		memcpy(pbOut + 8, pbIn + 8, 8);

		CryptDestroyKey(hKey2);
		CryptDestroyKey(hKey1);

		CryptReleaseContext(hProv, 0);
	}
}

// isspace() removes spaces too which I want to keep
int myIsSpace(int c) {
	return c == '\n'
		|| c == '\r'
		|| c == '\t'
		|| c == '\v'
		|| c == '\f'
		|| c==':';//for john format
}

BOOL NTDS::IsAccountInactive(DWORD dwUserCtrl) {
	static ULONG lockOutId = 0;

	/** if account is disabled, skip it */
	if ((dwUserCtrl & ADS_UF_ACCOUNTDISABLE) != 0) {
		return TRUE;
	}
	/************************************
	 * This bit never seems set even when
	 * account is locked . . .
	 *************************************/
	if ((dwUserCtrl & ADS_UF_LOCKOUT) != 0) {
		return TRUE;
	}
	/************************************
	 * To compensate for above, check the
	 * lock out time instead
	 *************************************/
	if (lockOutId == 0) {
		lockOutId = GetColumnId(ATT_LOCKOUT_TIME);
	}
	FILETIME ftLockOut = { 0, 0 };
	DWORD dwSize = 0;

	err = JetRetrieveColumn(sesId, tableId, lockOutId,
		(PVOID)&ftLockOut, sizeof(ftLockOut), &dwSize, JET_bitNil, NULL);

	if (err == JET_errSuccess && dwSize != 0) {
		if (ftLockOut.dwLowDateTime != 0
			|| ftLockOut.dwHighDateTime != 0) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL NTDS::IsAccountMachine(DWORD dwUserCtrl) {
	if ((dwUserCtrl & ADS_UF_NORMAL_ACCOUNT) == 0) {
		return TRUE;
	}
	return FALSE;
}

DWORD NTDS::GetColumnData(ULONG columnId, PVOID pbBuffer, DWORD cbBufSize) {
	ZeroMemory(pbBuffer, cbBufSize);
	DWORD dwSize = 0;

	err = JetRetrieveColumn(sesId, tableId, columnId,
		(PVOID)pbBuffer, cbBufSize, &dwSize, JET_bitNil, NULL);
	return dwSize;
}
VOID NTDS::PEKDecryptSecretDataBlock(LPBYTE pbData, DWORD dwSize)
{
	PSECRET_DATA pSecret = (PSECRET_DATA)pbData;
	EncryptDecryptWithKey(pekList.Data.bKey, PEK_VALUE_LEN, pSecret->bSalt, PEK_SALT_LEN, 1, &pSecret->pbData, dwSize-24);
}
VOID NTDS::DisplayDecrypted(DWORD rid, PBYTE pbHash, FILE* fp,char fmt) {
	BYTE hash[16];
	char c[] = "%02x";
	c[3] = fmt;
	decryptHash(rid, pbHash, hash);
	for (int i = 0; i < 16; i++) {
		fprintf(fp,c,hash[i]);
	}
}
VOID NTDS::DumpHash(DWORD rid, PBYTE pbHash, FILE* fp,char fmt) {

	PEKDecryptSecretDataBlock(pbHash, 40);
	DisplayDecrypted(rid, pbHash + 24, fp, fmt);
}

/**********************************************************
 *
 *  + Obtain user attributes
 *  + Decrypt hashes
 *
 **********************************************************/
BOOL NTDS::GetHashes(char fmt, BOOL bHistory, BOOL bInactive, BOOL bMachines, BOOL bProfile, FILE* out, DWORD* pAccounts, DWORD* pMachines, DWORD* pEntries, DWORD* pHistory) {
	wchar_t samName[256], description[256], path[256];
	BYTE lmHash[256], ntHash[256], lmHistory[256], ntHistory[256], sid[256];
	DWORD rid, dwUserCtrl;
	DWORD dwAcc, dwMac, dwEnt, dwHis;
	LPBYTE plmHist = (LPBYTE)malloc(256);
	LPBYTE pntHist = (LPBYTE)malloc(256);
	// get column ids corresponding to user attributes
	ULONG uacId = GetColumnId(ATT_USER_ACCOUNT_CONTROL);
	ULONG sidId = GetColumnId(ATT_OBJECT_SID);
	ULONG lmId = GetColumnId(ATT_DBCS_PWD);
	ULONG ntId = GetColumnId(ATT_UNICODE_PWD);
	ULONG samId = GetColumnId(ATT_SAM_ACCOUNT_NAME);
	ULONG descId = GetColumnId(ATT_DESCRIPTION);
	ULONG homeId = GetColumnId(ATT_HOME_DIRECTORY);

	// history
	ULONG lmHistId = GetColumnId(ATT_LM_PWD_HISTORY);
	ULONG ntHistId = GetColumnId(ATT_NT_PWD_HISTORY);

	// ensure we all column ids before continuing
	if (sidId == 0 || lmId == 0 || ntId == 0
		|| uacId == 0 || samId == 0 || descId == 0 || homeId == 0) {
		return FALSE;
	}

	bPrintSize = FALSE;

	/************************************
	 * open the datatable
	 ************************************/
	err = JetOpenTable(sesId, dbId, (JET_PCSTR)"datatable", NULL, 0,
		JET_bitTableReadOnly | JET_bitTableSequential, &tableId);

	if (err != JET_errSuccess) {
		return FALSE;
	}

	// go to first row
	err = JetMove(sesId, tableId, JET_MoveFirst, JET_bitNil);

	// we good to go?
	if (err == JET_errSuccess) {

		dwAcc = dwEnt = dwMac = dwHis = 0;

		do {
			/************************************
			 * get the user account control value
			 ************************************/
			GetColumnData(uacId, (PVOID)&dwUserCtrl, sizeof(dwUserCtrl));

			if (err == JET_errSuccess) {
				/************************************
				 * skip locked/disabled accounts?
				 ************************************/
				if (!bInactive && IsAccountInactive(dwUserCtrl)) {
					continue;
				}
				/************************************
				 * skip machine accounts?
				 ************************************/
				if (!bMachines && IsAccountMachine(dwUserCtrl)) {
					continue;
				}
				/************************************
				 * get sAMAccountName
				 ************************************/
				GetColumnData(samId, (PVOID)samName, sizeof(samName));

				if (err == JET_errSuccess) {
					/************************************
					 * get objectSid
					 ************************************/
					GetColumnData(sidId, (PVOID)sid, sizeof(sid));

					if (err == JET_errSuccess) {
						DWORD dwCount = *GetSidSubAuthorityCount((PSID)&sid);
						rid = *GetSidSubAuthority((PSID)&sid, dwCount - 1);
						rid = _byteswap_ulong(rid);
						fwprintf(out, L"%s:%i:", samName, rid);

						//lm
						DWORD ret = GetColumnData(lmId, (PVOID)lmHash, sizeof(lmHash));

						if (err == JET_errSuccess && ret) {
							DumpHash(rid, lmHash, out, fmt);
						}
						else {
							fprintf(out, "aad3b435b51404eeaad3b435b51404ee");
						}
						fwprintf(out, L":");
						//nt
						ret = GetColumnData(ntId, (PVOID)ntHash, sizeof(ntHash));

						if (err == JET_errSuccess && ret) {
							DumpHash(rid, ntHash, out, fmt);
						}
						else {
							fprintf(out, "31d6cfe0d16ae931b73c59d7e0c089c0");
						}
						std::wstring desc;
						std::wstring home;
						//profile
						if (bProfile)
						{
							GetColumnData(descId, (PVOID)description, sizeof(description));
							GetColumnData(homeId, (PVOID)path, sizeof(path));
							desc = description;
							home = path;
							desc.erase(remove_if(desc.begin(), desc.end(), myIsSpace), desc.end());
							home.erase(remove_if(home.begin(), home.end(), myIsSpace), home.end());
							fwprintf(out, L":%s:%s:\n", desc.c_str(), home.c_str());
						}
						else
						{
							fwprintf(out, L":::\n");
						}
						//dump histories
						if (bHistory)
						{
							ZeroMemory(plmHist, 256);
							ZeroMemory(pntHist, 256);
							DWORD dwlmhSize = GetColumnData(lmHistId, plmHist, 256);
							DWORD dwnthSize = GetColumnData(ntHistId, pntHist, 256);
							DWORD max = dwlmhSize > dwnthSize ? dwlmhSize : dwnthSize;
							if ((max > 0) && (max - 24 >= 16))
							{
								DWORD dwlmhCount = (dwlmhSize - 24) >> 4;
								DWORD dwnthCount = (dwnthSize - 24) >> 4;
								DWORD dwmaxCount = dwlmhCount > dwnthCount ? dwlmhCount : dwnthCount;
								PEKDecryptSecretDataBlock(plmHist, dwlmhSize);
								PEKDecryptSecretDataBlock(pntHist, dwnthSize);
								for (int i = 0; i < (max - 24 >> 4); i++)
								{
									fwprintf(out, L"%s_hist_%d:%i:", samName, i, rid);
									if (i < dwlmhCount)
									{
										DisplayDecrypted(rid, (LPBYTE)(((DWORD)plmHist) + 24 + 16 * i), out, fmt);
									}
									else
									{
										fprintf(out, "aad3b435b51404eeaad3b435b51404ee");
									}
									fprintf(out, ":");
									if (i < dwlmhCount)
									{
										DisplayDecrypted(rid, (LPBYTE)(((DWORD)pntHist) + 24 + 16 * i), out, fmt);
									}
									else
									{
										fwprintf(out, L"31d6cfe0d16ae931b73c59d7e0c089c0");
									}
									if (bProfile)
									{
										fwprintf(out, L":%s:%s:\n", desc.c_str(), home.c_str());
									}
									else
									{
										fwprintf(out, L":::\n");
									}
									dwEnt++;
									dwHis++;
								}
							}
						}
						if (IsAccountMachine(dwUserCtrl))
						{
							dwMac++;
						}
						else
						{
							dwAcc++;
						}
						dwEnt++;
					}
				}
			}
		} while (JetMove(sesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);
		if (pAccounts){ *pAccounts = dwAcc; }
		if (pMachines){ *pMachines = dwMac; }
		if (pEntries){ *pEntries = dwEnt; }
		if (pHistory){ *pHistory = dwHis; }
		if (out != stdout) {
			fclose(out);
		}

	}
	// close table
	err = JetCloseTable(sesId, tableId);
	free(plmHist);
	free(pntHist);
	return err == JET_errSuccess;
}
