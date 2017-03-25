# NTDSDumpEx

NTDS.dit offline dumper with non-elevated

### Usage
	ntdsdumpex.exe <-d ntds.dit> <-k HEX-SYS-KEY | -s system.hiv |-r> [-o out.txt] [-h] [-m] [-p] [-u]
	-d    path of ntds.dit database
	-k    use specified SYSKEY
	-s    parse SYSKEY from specified system.hiv
	-r    read SYSKEY from registry
	-o    write output into
	-h    dump hash histories(if available)
	-p    dump description and path of home directory
	-m    dump machine accounts
	-u    USE UPPER-CASE-HEX

### Example:
	ntdsdumpex.exe -r
	ntdsdumpex.exe -d ntds.dit -o hash.txt -s system.hiv

### Reference Source
`ntds.h`,`ntds.cpp`,`attributes.h` from [ntds_decode](https://github.com/mubix/ntds_decode) (some changed).

`ntreg.c`,`ntreg.h` from search,fix some compatibility on windows,and remove the debug outputs.

### License
GPL
