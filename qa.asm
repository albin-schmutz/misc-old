# ----------------------------------------------------------------
# qa 0.00.00
# Q-Assembler
# Albin Schmutz @ www.vulture.ch
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# MS-DOS Header (00000000 - 00000040)
# ----------------------------------------------------------------

db "MZ"                         # e_magic
setp 00000010H
db "Albin Schmutz @ www.vulture.ch"
setp 0000003CH
dd 00000040H                    # e_lfanew

# ----------------------------------------------------------------
# PE Header 24 Bytes (00000040 - 00000058)
# ----------------------------------------------------------------

setp 00000040H
db "PE",0,0
db 4CH,01H                      # Machine (Intel 386)
db 3,0                          # NumberOfSections
dd 0                            # TimeDateStamp UNUSED
dd 0                            # PointerToSymbolTable UNUSED
dd 0                            # NumberOfSymbols UNUSED
db 0E0H,00H                     # SizeOfOptionalHeader
db 0FH,01H                      # Characteristics

# ----------------------------------------------------------------
# PE optionaler Header (00000058 - 000000B8)
# ----------------------------------------------------------------

setp 00000058H
db 0BH,01H                      # Magic (PE32)
db 0                            # MajorLinkerVersion UNUSED
db 0                            # MinorLinkerVersion UNUSED
dd 00000200H                    # SizeOfCode UNUSED
dd 00000300H                    # SizeOfInitializedData UNUSED
dd 0                            # SizeOfUninitializedData UNUSED
dd 00001000H                    # AddressOfEntryPoint
dd 00001000H                    # BaseOfCode UNUSED
dd 00002000H                    # BaseOfData UNUSED
dd 00400000H                    # ImageBase
dd 00001000H                    # SectionAlignment
dd 00000200H                    # FileAlignment
db 4,0                          # MajorOperatingSystemVer UNUSED
db 0,0                          # MinorOperatingSystemVer UNUSED
db 0,0                          # MajorImageVersion UNUSED
db 0,0                          # MinorImageVersion UNUSED
db 4,0                          # MajorSubsystemVersion
db 0,0                          # MinorSubsystemVersion UNUSED
dd 0                            # Win32VersionValue UNUSED
dd 00005000H                    # SizeOfImage
dd 00000200H                    # SizeOfHeaders
dd 0                            # CheckSum UNUSED
db 03H,00H                      # Subsystem (Win32 GUI)
db 00H,00H                      # DllCharacteristics UNUSED
dd 00100000H                    # SizeOfStackReserve UNUSED
dd 00010000H                    # SizeOfStackCommit
dd 00100000H                    # SizeOfHeapReserve
dd 00001000H                    # SizeOfHeapCommit UNUSED
dd 0                            # LoaderFlags UNUSED
dd 16                           # NumberOfRvaAndSizes UNUSED

# ----------------------------------------------------------------
# Data directories, 16 Eintraege (000000B8 - 00000138)
# ----------------------------------------------------------------

setp 000000B8H
dd 0                            #  0: Export Table UNUSED
dd 0

setp 000000C0H
dd 00000402CH                   #  1: RVA Import Table
dd 000000028H                   #     size

setp 00000118H
dd 0004054H                     # 12: RVA IAT
dd 000001CH                     #     size


# ----------------------------------------------------------------
# PE code section (00000138 - 00000160)
# ----------------------------------------------------------------

setp 00000138H
db "code",0,0,0,0               # Name
dd 00001000H                    # VirtualSize
dd 00001000H                    # VirtualAddress
dd 00001600H                    # SizeOfRawData
dd 00000200H                    # PointerToRawData
dd 0                            # PointerToRelocations UNUSED
dd 0                            # PointerToLinenumbers UNUSED
db 0,0                          # NumberOfRelocations UNUSED
db 0,0                          # NumberOfLinenumbers UNUSED
dd 60000020H                    # Characteristics

# ----------------------------------------------------------------
# PE data section (00000160 - 00000188)
# ----------------------------------------------------------------

setp 00000160H
db "data",0,0,0,0               # Name
dd 00002000H                    # VirtualSize
dd 00002000H                    # VirtualAddress
dd 00000600H                    # SizeOfRawData
dd 00001800H                    # PointerToRawData
dd 0                            # PointerToRelocations UNUSED
dd 0                            # PointerToLinenumbers UNUSED
db 0,0                          # NumberOfRelocations UNUSED
db 0,0                          # NumberOfLinenumbers UNUSED
dd 0C0000040H                   # Characteristics

# ----------------------------------------------------------------
# PE data section (00000188 - 000001B0)
# ----------------------------------------------------------------

setp 00000188H
db "imp",0,0,0,0,0              # Name
dd 00000102H                    # VirtualSize
dd 00004000H                    # VirtualAddress
dd 00000200H                    # SizeOfRawData
dd 00001E00H                    # PointerToRawData
dd 0                            # PointerToRelocations UNUSED
dd 0                            # PointerToLinenumbers UNUSED
db 0,0                          # NumberOfRelocations UNUSED
db 0,0                          # NumberOfLinenumbers UNUSED
dd 60000020H                    # Characteristics



# ----------------------------------------------------------------
# Code (00000200 - 00001800)
# ----------------------------------------------------------------

setp 00000200H

# Windows APIs sichern EBP, EBX, EDI, ESI und erwarten
# geloeschtes direction flag.

jmp 00001000H


# ----------------------------------------------------------------
# STR_LEN
#
# Laenge 0-terminierter String in EDI nach ECX.
# ----------------------------------------------------------------

slotp 10
push edi                        # EDI sichern
xorr ecx,ecx                    # ECX := -1
not ecx
xorr eax,eax                    # AL := 0
cld
repnz
scasb
not ecx                         # ECX erhaelt Laenge
dec ecx
pop edi                         # EDI wieder herstellen
ret



# ----------------------------------------------------------------
# MEM_EAX_AS_UINT
#
# EAX als UINT nach EDI schreiben, ECX mit Laenge der Ziffer laden
# und EDI um soviel erhoehen.
# Zerstoert EAX, EBX, EDX.
# ----------------------------------------------------------------

slotp 11
mov ebx,10                      # durch 10 dividieren
xorr ecx,ecx                    # ECX := 0

slotp 0
xorr edx,edx                    # EDX := 0
div ebx
addb edx,30H                    # '0'
push edx                        # Ziffer auf Stack
inc ecx
orr eax,eax                     # wenn Rest=0 fertig
jnz $0

movr eax,ecx                    # ECX sichern

slotp 1
pop edx
movyl edi,edx                   # mov [edi],dl
inc edi
loop $1

movr ecx,eax                    # ECX wieder herstellen
ret

# ----------------------------------------------------------------
# MEM_EAX_AS_HINT
#
# EAX als 8-stellige HEX Ziffer nach EDI schreiben,  ECX mit 8
# laden und EDI um soviel erhoehen.
# Zerstoert EAX, EBX, EDX.
# ----------------------------------------------------------------

slotp 12
mov ecx,8                       # Laenge der Ziffer
push ecx                        # sichern
addr edi,ecx                    # EDI erhaelt Ende der Position
push edi                        # sichern fuer Rueckgabe

slotp 0
movr ebx,eax
shr eax,4
andb ebx,0FH
movlyd edx,ebx,00402070H        # mov dl,[00402070H+ebx]
dec edi
movyl edi,edx                   # mov [edi],dl
loop $0
pop edi
pop ecx
ret



#----------------------------------------------------------------
# FILE_OPEN_READ
#
# File in EDI zum Lesen offnen und bei Erfolg File-Handle in EAX
# liefern. Setzt Zero-Flag bei Fehler.
# Zerstoert ECX, EDX.
# ----------------------------------------------------------------

slotp 13
pushb 0                         # Kein Template
pushb 0                         # Keine spez. Attribute
pushb 3                         # Oeffnen
pushb 0                         # Keine Security
pushb 0                         # Normal
pushd 80000000H                 # Lesend
push edi                        # Filename
call 00003218H                  # 00404018 (CreateFileA)
cmpb eax,0FFH                   # Fehler?
ret

# ----------------------------------------------------------------
# FILE_OPEN_WRITE
#
# File in EDI zum Schreiben oeffnen und bei Erfolg File-Handle in
# EAX liefern. Setzt Zero-Flag bei Fehler.
# Zerstoert ECX, EDX.
# ----------------------------------------------------------------

slotp 14
pushb 0                         # Kein Template
pushb 0                         # Keine spez. Attribute
pushb 2                         # Erstellen
pushb 0                         # Keine Security
pushb 0                         # Normal
pushd 40000000H                 # Schreibend
push edi                        # Filename
call 00003218H                  # 00404018 (CreateFileA)
cmpb eax,0FFH                   # Fehler?
ret

# ----------------------------------------------------------------
# FILE_CLOSE
#
# File in EDX schliessen.
# Zerstoert EAX, ECX, EDX.
# ----------------------------------------------------------------

slotp 15
push edx
call 00003212H                  # 00404012 (CloseHandle)
ret

# ----------------------------------------------------------------
# FILE_READ
#
# ECX Bytes aus File EDX lesen, nach EDI schreiben und IO_RES
# (00403B0C) mit Anzahl gelesener Bytes setzen. Setzt Zero-Flag
# bei Fehler.
# Zerstoert EAX, ECX, EDX.
# ----------------------------------------------------------------

slotp 16
pushb 0
pushd 00403B0CH                 # Resultat nach IO_RES
push ecx                        # Stringlaenge
push edi                        # Zieladresse
push edx                        # File Handle
call 0000321EH                  # 0040401E (ReadFile)
orr eax,eax                     # Fehler?
ret

# ----------------------------------------------------------------
# FILE_WRITE
#
# ECX Bytes ab EDI ins File EDX schreiben und IO_RES (00403B0C)
# mit Anzahl geschriebener Bytes setzen. Setzt Zero-Flag bei
# Fehler.
# Zerstoert EAX, ECX, EDX.
# ----------------------------------------------------------------

slotp 17
pushb 0
pushd 00403B0CH                 # Resultat nach IO_RES
push ecx                        # Stringlaenge
push edi                        # Quelladresse
push edx                        # File Handle
call 00003224H                  # 00404024 (WriteFile)
orr eax,eax                     # Fehler?
ret

# ----------------------------------------------------------------
# FILE_WRITE_LN
#
# Zeilenumbruch (0D0C) ins File EDX schreiben. Setzt Zero-Flag
# bei Fehler.
# Zerstoert EAX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 18
mov edi,0040201BH
mov ecx,2
jmps $17                        # FILE_WRITE



# ----------------------------------------------------------------
# OUT_STRZ
#
# Nullterminierten Text in EDI ausgeben.
# Zerstoert EAX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 19
call $10                        # STR_LEN
# dirket weiter mit OUT_STRN

# ----------------------------------------------------------------
# OUT_STRN
#
# Text in EDI mit Laenge ECX ausgeben.
# Zerstoert EAX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 20
movrm edx,00403B04H
jmps $17                        # FILE_WRITE

# ----------------------------------------------------------------
# OUT_UINT
#
# EAX als UINT ausgeben.
# Zerstoert EAX, EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 9
mov edi,00403BF0H
call $11                        # MEM_EAX_AS_UINT
subr edi,ecx
jmps $20                        # OUT_STRN

# ----------------------------------------------------------------
# OUT_HINT
#
# EAX als HEX ausgeben.
# Zerstoert EAX, EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

mov edi,00403BF0H
call $12                        # MEM_EAX_AS_HINT
subr edi,ecx
jmps $20                        # OUT_STRN

# ----------------------------------------------------------------
# OUT_LN
#
# Zeilenumbruch ausgeben.
# Zerstoert EAX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 21
movrm edx,00403B04H
jmps $18                        # FILE_WRITE_LN



# ----------------------------------------------------------------
# SRC_BLOCK
#
# Naechster 512 Byte grosser Block aus Quelldatei lesen, SRC_EOB
# auf letztes Zeichen + 1 und SRC_POS auf Position 0 setzen.
# Gibt bei Fehler Meldung aus und setzt Carry Flag.
# Zerstoert EAX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
movam 00403B0CH                 # Anzahl gelesene Zeichen
adda 00403E00H                  # SRC_BLOCK Buffer
movma 00403B14H                 # SRC_EOB setzen
clc
ret

slotp 22
movrm edx,00403B10H
mov edi,00403E00H
movmr edi,00403B18H
mov ecx,512
call $16                        # FILE_READ
jnz $0                          # Kein Fehler?

mov edi,00402043H               # Doch
mov ecx,23
call $20                        # OUT_STRN
stc
ret

# ----------------------------------------------------------------
# SRC_CHAR
#
# Naechstes Zeichen aus File nach EAX lesen, bei EOF -1, und
# SRC_LINE um 1 erhoehen wenn Zeichen = 10.
# Zerstoert EAX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
mov eax,0FFFFFFFFH
clc
ret

slotp 1
incm 00403B1CH                  # SRC_LINE erhoehen

slotp 2
incm 00403B18H                  # SRC_POS erhoehen
ret

slotp 3
movrm esp,00403B28H
ret

slotp 4
cmp ecx,00404000H               # ja, EOF erreicht?
jnz $0                          # ja

call $22                        # SRC_BLOCK
jc $3                           # Fehler?

slotp 23
movrm ecx,00403B18H             # ECX erhaelt SRC_POS
cmprm ecx,00403B14H             # EOB erreicht?
jz $4                           # ja

xorr eax,eax                    # EAX:=0
movly eax,ecx                   # AL:=[ECX]
cmpb eax,10                     # Zeilenende?
jz $1                           # ja
jmps $2                         # nein

# ----------------------------------------------------------------
# SRC_ERR
#
# Fehlermeldung in ESI mit Zeilenangabe schreiben und nach ERR_SP
# zuerueckkehren.
# ----------------------------------------------------------------

slotp 24
mov edi,00402080H
mov ecx,5
call $20                        # OUT_STRN
movam 00403B1CH
inc eax
call $9                         # OUT_UINT
mov edi,00402085H
mov ecx,2
call $20                        # OUT_STRN
movr edi,esi
call $10                        # STR_LEN
call $20                        # OUT_STRN
movrm esp,00403B28H
ret



# ----------------------------------------------------------------
# SCN_IS_LLET
#
# Carry-Flag setzen, wenn EAX kleiner Buchstabe (a-z) enthaelt.
# ----------------------------------------------------------------

slotp 0
clc
ret

slotp 25
cmpb eax,61H                    # 'a'
jc $0
cmpb eax,7BH                    # 'z'+1
ret

# ----------------------------------------------------------------
# SCN_IS_HDIG
#
# Wert (0-15 oder -1) in ECX zu Ziffer in EAX liefern.
# ----------------------------------------------------------------

slotp 26
mov edi,0040207FH               # 00402070H+15
mov ecx,17

slotp 0
std
repnz scasb
cld                             # WIN32 braucht das
dec ecx
ret

# ----------------------------------------------------------------
# SCN_IS_DIG
#
# Wert (0-9 oder -1) in ECX zu Ziffer in EAX liefern.
# ----------------------------------------------------------------

slotp 27
mov edi,00402079H               # 00402070H+9
mov ecx,11
jmps $0 

# ----------------------------------------------------------------
# SCN_SYM
#
# In EBX Wert des Symbols und in EAX naechstes Zeichen liefern,
# sonst Fehlerbehandlung.
# Erwartet in EAX erstes Zeichen.
# Zerstoert EBX, ECX, EDX, ESI, EDI, EBP.
# ----------------------------------------------------------------

slotp 0
pop eax
mov esi,00402110H               # Fehlermeldung
jmp $24

slotp 1                         # Identisch
movr ebx,edx                    # EBX:=32+EDX
addb ebx,32
pop eax
retn 8

slotp 2                         # Groesser
movr eax,edx
inc eax

slotp 3
cmpr eax,ebx
jg $0

movr edx,eax                    # EDX erhaelt mittleres Element
addr edx,ebx
shrs edx

addr ecx,edi                    # EDI und ECX wieder herstellen
subr ecx,ebp
movr edi,ebp

db 8DH,34H,0D5H                 # lea esi,[00402190H+EDX*8]
dd 00402190H
repz
cmpsb                           # String vergleichen
jz $1                           # Identisch
jc $2                           # Groesser

movr ebx,edx                    # Kleiner
dec ebx
jmps $3

slotp 28

mov ebx,8                       # Maximale Laenge: 7
pop edx                         # Ruecksprungadresse nach EDX
subr esp,ebx                    # 16-Byte Stackframe erstellen
movr ebp,esp
push edx

xorr ebx,ebx                    # EBX:=0

slotp 4
db 88H,44H,1DH,0                # mov [ebp+ebx],al
inc ebx
call $23                        # SRC_CHAR, naechstes Zeichen
call $25                        # SCN_IS_LLET
jc $4

push eax
db 0C6H,44H,1DH,0,0             # mov [ebp+ebx],0: String abschl.
movr edi,ebp                    # und nach EDI
addr edi,ebx                    # inklusive Laenge
inc edi
xorr ecx,ecx
mov eax,0                       # Untere Grenze
mov ebx,73                      # Obere Grenze

jmps $3

# ----------------------------------------------------------------
# SCN_INT
#
# Liefert in EBX Token 3 (TK_INT), in EAX naechstes Zeichen und
# in ECX Integerwert.
# Erwartet in ECX ersten Ziffernwert.
# Zerstoert ECX, EDX, EDI, ESI, EBP.
# ----------------------------------------------------------------

slotp 0
mov esi,0040209CH               # Fehlermeldung
jmp $24

slotp 1
mov esi,004020C7H               # Fehlermeldung
jmp $24

slotp 29

mov ebx,12                      # Maximale Laenge der Ziffer: 11
pop edx                         # Ruecksprungadresse nach EDX
movr ebp,esp                    # 12-Byte Stackframe erstellen
subr esp,ebx
push edx

slotp 2
dec ebp
dec ebx
orr ebx,ebx                     # EBX=0, Ziffer zu lang?
jz $0                           # ja

db 88H,4DH,00H                  # mov [ebp],cl Ziffernwert ablegen
call $23                        # SRC_CHAR
call $26                        # SCN_IS_HDIG
cmpb ecx,0FFH                   # -1, Fehler?
jnz $2                          # ja, loop

mov esi,10                      # Basis 10
cmpb eax,48H                    # Hex-Ziffer H am Ende?
db 75H,0AH                      # jnz, nein

call $23                        # SRC_CHAR, ja, naechstes Zeichen
mov esi,16                      # Basis 16

mov ecx,12                      # ECX erhaelt Ziffern-Offset
subr ecx,ebx
push eax                        # EAX sichern
xorr eax,eax                    # EAX:=0
dec ebp                         # EBP justieren mit ECX

slotp 3
xorr ebx,ebx                    # EBX:=0
db 8AH,5CH,0DH,00H              # mov bl,[ebp+ecx], EBX:=Ziffernw.
cmpr ebx,esi                    # Zifferwert<Basis?
jnc $1

mul esi                         # EAX mit Basis multiplzieren
addr eax,ebx                    # und EBX dazu addieren
loop $3

movr ecx,eax
pop eax
mov ebx,5                       # TK_INT

retn 12

# ----------------------------------------------------------------
# SCN_STR
#
# Liefert in EBX Token 4 (TK_STR), in EAX naechstes Zeichen und
# schreibt String nach SCN_BUF (00403D00) maximal Zeichen in
# d[00403D00]. Schreibt Fehlermeldung, wenn String zu lang.
# Zerstoert ECX, EDX, EDI, ESI.
# ----------------------------------------------------------------

slotp 0
mov esi,004020E7H               # Fehlermeldung
jmp $24

slotp 1
mov esi,00402100H               # Fehlermeldung
jmp $24

slotp 2
mov ebx,4
jmp $23                         # SRC_CHAR

slotp 30

mov esi,00403D00H               # Zieladresse String
movry ebx,esi                   # Max. erl. Laenge

slotp 3
call $23                        # SRC_CHAR
cmpb eax,0FFH
jz $0

cmpb eax,22H                    # "
jz $2

orr ebx,ebx
jz $1

movyl esi,eax
inc esi
dec ebx
jmps $3

slotp 4
ret

# ----------------------------------------------------------------
# SCN_COMMENT
#
# Ueberliesst Kommentar inklusive abschliessendes \n.
# Liefert in EAX naechstes Zeichen.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 31
call $23                        # SRC_CHAR
cmpb eax,0FFH                   # -1
jz $4
cmpb eax,10
jnz $31
jmp $23                         # SRC_CHAR

# ----------------------------------------------------------------
# SCN_TOKEN
#
# Liefert naechstes Token in EBX und naechstes Zeichen in EAX.
# Erwartet in EAX erstes Zeichen.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
push ebp
call $29                        # SCN_INT, EBX:=5 (TK_INT)
pop ebp
ret

slotp 1
jmp $30                         # SCN_STR, EBX:=4 (TK_STR)

slotp 2
inc ebx                         # EBX:=3 (TK_SLOT)

slotp 3
inc ebx                         # EBX:=2 (TK_COMMA)

slotp 4
inc ebx                         # EBX:=1 (TK_EOL)
jmp $23                         # SRC_CHAR

slotp 5
push ebp
call $28                        # SCN_SYM
pop ebp
slotp 6
ret

slotp 7
call $31                        # SCN_COMMENT
jmps 0000052EH                  # SCN_TOKEN

slotp 8
call $23                        # SRC_CHAR

setp 0000052EH
slotp 32
xorr ebx,ebx                    # EBX:=0 (TK_EOF)
cmpb eax,0FFH                   # -1
jz $6

cmpb eax,10                     # EOL?
jz $4

cmpb eax,33                     # Whitespace oder Space?
jc $8

cmpb eax,23H                    # '#', Kommentar
jz $7

cmpb eax,22H                    # '"', String
jz $1

cmpb eax,2CH                    # ',', Komma
jz $3

cmpb eax,24H                    # '$', Slot
jz $2

call $27                        # SCN_IS_DIG, Integer
cmpb ecx,0FFH                   # -1
jnz $0

call $25                        # SCN_IS_LLET, Symbol
jc $5

mov esi,00402087H               # Fehlermeldung
jmp $24                         # SRC_ERR



# ----------------------------------------------------------------
# GEN_WRITE
#
# Schliesst GEN_S, GEN_B, GEN_W und GEN_D ab.
# Stellt EAX vom Stack wieder her.
# ----------------------------------------------------------------

slotp 0
mov esi,00402054H               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 33
addmr ecx,00403B24H             # GEN_P erhoehen
movrm edx,00403B20H
call $17                        # FILE_WRITE
jz $0

pop eax
slotp 9
ret

# ----------------------------------------------------------------
# GEN_S
#
# Schreibt SCN_BUF (00403D00) bis ESI ins Zielfile.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 34
push eax
mov edi,00403D00H
movr ecx,esi
subr ecx,edi
jmps $33                        # GEN_WRITE

# ----------------------------------------------------------------
# GEN_B
#
# Schreibt Byte in ECX ins Zielfile.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 35
push eax
mov edi,00403D00H
movyl edi,ecx
mov ecx,1
jmps $33                        # GEN_WRITE

# ----------------------------------------------------------------
# GEN_W
#
# Schreibt Word in ECX ins Zielfile.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 36
push eax
mov edi,00403D00H
db 66H,89H,0FH                  # mov [edi],cx
mov ecx,2
jmps $33                        # GEN_WRITE

# ----------------------------------------------------------------
# GEN_D
#
# Schreibt Doubleword ECX ins Zielfile.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 37
push eax
mov edi,00403D00H
movyr edi,ecx
mov ecx,4
jmps $33                        # GEN_WRITE

# ----------------------------------------------------------------
# GEN_OC1
#
# Generiert 1-Byte-Opcode zu Symbol EBX.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 38
db 8AH,8CH,1BH                  # mov cl,[00402530H+EBX*2]
dd 00402530H
jmps $35

# ----------------------------------------------------------------
# GEN_OC2
#
# Generiert 2-Byte-Opcode zu Symbol EBX.
# Zerstoert ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 39
db 66H, 8BH,8CH,1BH             # mov cx,[00402530H+EBX*2]
dd 00402530H
jmps $36

# ----------------------------------------------------------------
# PRS_ACC_INT
#
# Fuehrt SCN_TOKEN aus, erwartet TK_INT oder TK_SLOT und liefert
# naechstes Zeichen in EAX und Integer in ECX.
# Erwartet in EAX erstes Zeichen.
# Zerstoert EBX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
cmpb ebx,5                      # EBX=TK_INT?
jz $9                           # ret

slotp 1
mov esi,0040211FH               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 40

call $32                        # SCN_TOKEN
cmpb ebx,3                      # EBX=TK_SLOT?
jnz $0

call $32                        # SCN_TOKEN
cmpb ebx,5                      # EBX=TK_INT?
jnz $1

db 81H,0E1H                     # and ecx,255
dd 255
movrm edi,00403B2CH
db 8BH,0CH,8FH                  # mov ecx,[edi+ecx*4]
ret

# ----------------------------------------------------------------
# PRS_ACC_REG
#
# Liefert Register Wert in ECX und liefert naechstes Zeichen in
# EAX oder gibt Fehlermeldung aus.
# Erwartet in EAX erstes Zeichen.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
mov esi,00402169H               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 41
call $32                        # SCN_TOKEN
subb ebx,32                     # Symbol?
jc $0

xorr ecx,ecx
db 8AH,8CH,1BH                  # mov cl,[00402530H+EBX*2]
dd 00402530H
ret

# ----------------------------------------------------------------
# PRS_ACC_COMMA
#
# Liefert naechstes Zeichen ein oder gibt Fehlermeldung aus,
# wenn Token nicht Komma ist.
# Erwartet in EAX Komma.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
mov esi,0040217BH               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 42
call $32                        # SCN_TOKEN
cmpb ebx,2                      # TK_COMMA
jnz $0
ret

# ----------------------------------------------------------------
# PRS_MR_SYM
#
# EBP erhaelt ModR/M aus Symboltabelle (EBX).
# Zerstoert EBX, ECX.
# ----------------------------------------------------------------

slotp 43
xorr ecx,ecx
db 8AH,8CH,1BH                  # mov cl,[00402530H+1+EBX*2]
dd 00402531H
movr ebp,ecx
ret

# ----------------------------------------------------------------
# PRS_OC1_MR_11_SYM_RRR_SUB
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: 11, reg: Symboltabelle, r/m: Register
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 44
call $38                        # GEN_OC1
call $43                        # PRS_MR_SYM, EBP erh. ModR/M reg
shl ebp,3
call $41                        # PRS_ACC_REG
addr ecx,ebp                    # ModR/M r/m
addb ecx,192                    # ModR/M mod: 11000000
call $35                        # GEN_B
ret

# ----------------------------------------------------------------
# PRS_OC1_MR_SY_RRS_RRT_SUB
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: Symboltabelle, reg: Zielregister, r/m: Quellregister.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 45
call $38                        # GEN_OC1
call $43                        # PRS_MR_SYM, EBP erh. ModR/M reg
call $41                        # PRS_ACC_REG
shl ecx,3                       # EBP erhaelt ModR/M reg
addr ebp,ecx
call $42                        # PRS_ACC_COMMA
call $41                        # PRS_ACC_REG
addr ecx,ebp                    # ModR/M r/m
call $35                        # GEN_B
ret



# ----------------------------------------------------------------
# PRS_ERR_REG
#
# Register als 1. Symbol. Gibt Fehlermeldung aus und bricht ab.
# ----------------------------------------------------------------

slotp 100

mov esi,00402155H               # Fehlermeldung
jmp $24                         # SRC_ERR

# ----------------------------------------------------------------
# PRS_OC1
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 101

call $38                        # GEN_OC1
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_B
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von B-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 102

call $38                        # GEN_OC1
call $40                        # PRS_ACC_INT
call $35                        # GEN_B
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_W
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von W-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 103

call $38                        # GEN_OC1
call $40                        # PRS_ACC_INT
call $36                        # GEN_W
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von D-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 104

call $38                        # GEN_OC1
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_R
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX und addiert Register dazu.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 105

movr ebp,ebx
call $41                        # PRS_ACC_REG
db 02H,8CH,2DH                  # add cl,[00402530H+EBP*2]
dd 00402530H
call $35                        # GEN_B
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_R_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX, addiert Register dazu und
# generiert D-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 106

movr ebp,ebx
call $41                        # PRS_ACC_REG
db 02H,8CH,2DH                  # add cl,[00402530H+EBP*2]
dd 00402530H
call $35                        # GEN_B
call $42                        # PRS_ACC_COMMA
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC_JMP_B
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX und berechnet relativen
# Jump B-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 107

call $38                        # GEN_OC1
call $40                        # PRS_ACC_INT
subrm ecx,00403B24H
dec ecx
call $35                        # GEN_B
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC_JMP_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX und berechnet relativen
# Jump D-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 108

call $38                        # GEN_OC1
call $40                        # PRS_ACC_INT
subrm ecx,00403B24H
subb ecx,4
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_00_RRR_101_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M.
# mod: 00, reg: Register, r/m: 101
# Dann wird Doubleword gelesen.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 109

call $38                        # GEN_OC1
call $41                        # PRS_ACC_REG
shl ecx,3                       # ModR/M reg
orb ecx,5                       # 00 %%% 101
call $35                        # GEN_B
call $42                        # PRS_ACC_COMMA
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_00_SYM_101_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M.
# mod: 00, reg: Symboltabelle, r/m: 101
# Dann wird Doubleword gelesen.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 110     

call $38                        # GEN_OC1
call $43                        # PRS_MR_SYM, EBP erh. ModR/M reg
shl ebp,3
mov ecx,5                       # 00000101
addr ecx,ebp
call $35                        # GEN_B
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_11_SYM_RRR
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: 11, reg: Symboltabelle, r/m: Register
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 111

call $44                        # PRS_OC1_MR_11_SYM_RRR_SUB
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_11_SYM_RRR_B
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: 11, reg: Symboltabelle, r/m: Register
# Dann wird Byte gelesen.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 112

call $44                        # PRS_OC1_MR_11_SYM_RRR_SUB
call $42                        # PRS_ACC_COMMA
call $40                        # PRS_ACC_INT
call $35                        # GEN_B
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_11_SYM_RRR_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: 11, reg: Symboltabelle, r/m: Register
# Dann wird Doubleword gelesen.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 113

call $44                        # PRS_OC1_MR_11_SYM_RRR_SUB
call $42                        # PRS_ACC_COMMA
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_SY_RRT_RRS
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: Symboltabelle, reg: Quellregister, r/m: Zielregister.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 114

call $38                        # GEN_OC1
call $43                        # PRS_MR_SYM, EBP erh. ModR/M reg
call $41                        # PRS_ACC_REG
addr ebp,ecx                    # EBP erhaelt ModR/M r/m
call $42                        # PRS_ACC_COMMA
call $41                        # PRS_ACC_REG
shl ecx,3                       # ModR/M reg
addr ecx,ebp
call $35                        # GEN_B
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_SY_RRS_RRT
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: Symboltabelle, reg: Zielregister, r/m: Quellregister.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 115

call $45                        # PRS_OC1_MR_SY_RRS_RRT_SUB
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC1_MR_SY_RRS_RRT_D
#
# Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
# mod: Symboltabelle, reg: Zielregister, r/m: Quellregister.
# Dann wird Double-Word gelesen.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 116

call $45                        # PRS_OC1_MR_SY_RRS_RRT_SUB
call $42                        # PRS_ACC_COMMA
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_OC2_D
#
# Erzeugt 2-Byte-Opcode zu Symbol EBX gefolgt von D-Wert.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 117

call $39                        # GEN_OC2
call $40                        # PRS_ACC_INT
call $37                        # GEN_D
jmp $32                         # SCN_TOKEN

# ----------------------------------------------------------------
# PRS_DB
#
#  Liest Byte-Datentokens ein (Integer oder String) und schreibt
#  sie in Zielfile.
#  Liest naechstes Token ein.
#  Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
mov esi,00402144H               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 1
ret

slotp 2
cmpb ebx,4                      # EBX=TK_STR?
jnz $0

call $34                        # GEN_S

slotp 3
call $32                        # SCN_TOKEN
cmpb ebx,2                      # EBX=TK_COMMA?
jnz $1

slotp 118

db 0C7H,05H                     # Maximale Laenge String
dd 00403D00H                    # mov [00403D00H],dword 256
dd 256

call $32                        # SCN_TOKEN
orr ebx,ebx                     # EBX=TK_EOF?
jz $1

cmpb ebx,1                      # EBX=TK_EOL?
jz $1

cmpb ebx,5                      # EBX=TK_INT?
jnz $2

call $35                        # GEN_B
jmps $3

# ----------------------------------------------------------------
# PRS_DD
#
# Liest Doubleword-Integers ein und schreibt sie in Zielfile.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 119

slotp 0
call $40                        # PRS_ACC_INT
orr ebx,ebx                     # EBX=TK_EOF?
jz $1

cmpb ebx,1                      # EBX=TK_EOL?
jz $1

call $37                        # GEN_D
call $32                        # SCN_TOKEN
cmpb ebx,2                      # EBX=TK_COMMA?
jz $0

ret

# ----------------------------------------------------------------
# PRS_SETP
#
# Schreibt soviele 0 Bytes in Zielfile bis Position nach
# setp erreicht ist.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
jmp $32                         # SCN_TOKEN

slotp 1
mov esi,00402130H               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 120

call $40                        # PRS_ACC_INT
movr ebx,ecx
subrm ebx,00403B24H             # Vergleicht neuer P mit akt.
jz $0
jc $1

slotp 2
xorr ecx,ecx
call $35                        # GEN_B
dec ebx
orr ebx,ebx
jz $0
jmps $2

# ----------------------------------------------------------------
# PRS_SLOTP
#
# Slot (0-255) mit Position laden.
# Liest naechstes Token ein.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 121

call $40                        # PRS_ACC_INT
movrm ebx,00403B24H
db 81H,0E1H                     # and ecx,255
dd 255
movrm edi,00403B2CH
db 89H,1CH,8FH                  # mov [edi+ecx*4],ebx
jmp $32                         # SCN_TOKEN



# ----------------------------------------------------------------
# PRS_LINE
#
# Parst Zeile fuer Zeile.
# Springt bei Fehler direkt von hier zurueck.
# Zerstoert EBX, ECX, EDX, EDI.
# ----------------------------------------------------------------

slotp 0
ret

slotp 1
mov esi,00402144H               # Fehlermeldung
jmp $24                         # SRC_ERR

slotp 56

movmr esp,00403B28H             # Stackpointer Fehlerbehandlung
call $23                        # SRC_CHAR

slotp 2
call $32                         # SCN_TOKEN

slotp 3
orr ebx,ebx                     # EBX=TK_EOF?
jz $0

cmpb ebx,1                      # EBX=TK_EOL?
jz $2

cmpb ebx,32                     # Symbol?
jc $1

subb ebx,32
db 8BH,14H,9DH                  # mov edx,[00402400H+EBX*4]
dd 00402400H
db 81H,0C2H                     # add edx,00400E00H
dd 00400E00H
db 0FFH,0D2H                    # call edx
jmps $3

ret



# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------

setp 00001000H


# Standard-Device File-Handles initialisieren

pushb 0F6H                      # STD_INPUT_HANDLE (-10)
call 0000320CH                  # 0040400C (GetStdHandle)
movma 00403B00H

pushb 0F5H                      # STD_OUTPUT_HANDLE (-11)
call 0000320CH                  # 0040400C (GetStdHandle)
movma 00403B04H

pushb 0F4H                      # STD_OUTPUT_HANDLE (-12)
call 0000320CH                  # 0040400C (GetStdHandle)
movma 00403B08H


# Titel ausgeben

mov edi,00402000H
call $19                        # OUT_STRZ


# Filename aus Kommandozeile parsen

call 00003200H                  # 00404000 (GetCommandLineA)

slotp 0                         # Erstes Space oder \0 suchen
inc eax
db 80H,38H,0                    # cmp [eax],byte 0
jz 00001045H
db 80H,38H,32                   # cmp [eax],byte 32
jnz $0
dec eax

slotp 1                         # Erstes Nicht-Space suchen
inc eax
db 80H,38H,32                   # cmp [eax],byte 32
jz $1

setp 00001045H

movr edi,eax
call $10                        # STR_LEN
andb ecx,0FH                    # Stringlaenge begrenzen
movr esi,edi
mov edi,00403E00H               # SRC_BLOCK als Buffer
repz
movsb
movr ebx,edi


# Input-Filename zusammenstellen und ausgeben

db 0C7H,03H,".asm"              # mov [ebx],dword '.asm'
db 0C6H,43H,04H,0               # mov [ebx+4], byte 0
mov edi,00402020H
db 0C7H,07H," Inp"              # mov [edi],dword ' Inp'
inc edi
call $19                        # OUT_STRZ
mov edi,00403E00H               # SRC_BLOCK als Buffer
call $19                        # OUT_STRZ
call $21                        # OUT_LN


# File zum Lesen oeffnen

mov edi,00403E00H               # SRC_BLOCK als Buffer
call $13                        # FILE_OPEN_READ
jnz 000010A0H                   # Fehler?
mov edi,00402032H               # ja
call $19                        # OUT_STRZ
mov eax,1
ret

setp 000010A0H
movma 00403B10H


# Output-Filename zusammenstellen und ausgeben

db 0C7H,03H,".exe"              # mov [ebx],dword '.exe'
db 0C6H,43H,4,0                 # mov [ebx+4],byte 0
mov edi,00402020H
db 0C7H,07H,"Outp"              # #mov [edi],dword 'Outp'
call $19                        # OUT_STRZ
mov edi,00403E00H               # SRC_BLOCK als Buffer
call $19                        # OUT_STRZ
call $21                        # OUT_LN


# File zum Schreiben oeffnen

mov edi,00403E00H               # SRC_BLOCK als Buffer
call $14                        # FILE_OPEN_WRITE
jnz 000010EAH                   # Fehler?
mov edi,00402032H               # ja
call $19                        # OUT_STRZ
mov eax,1
ret

setp 000010EAH
movma 00403B20H


# Speicher fuer SLOTs reservieren

pushd 4H                        # PAGE_READWRITE
pushd 3000H                     # MEM_COMMIT | MEM_RESERVE
pushd 1024                      # Anzahl Bytes
pushd 0                         # keine lpAddress vorgeben
call 00003206H                  # 00404006 (VirtualAlloc)
orr eax,eax                     # cmp eax,0
jnz 00001112H
mov eax,1
ret

setp 00001112H
movma 00403B2CH                 # Startadresse sichern


# SRC und GEN initialisieren

db 0C7H,05H                     # mov [00403B1CH],dword 0
dd 00403B1CH                    # SRC_LINE:=0
dd 0

call $22                        # SRC_BLOCK
jc 0000112DH


call $56                        # PRS_LINE

setp 0000112DH

movrm edx,00403B10H
call $15                        # FILE_CLOSE
movrm edx,00403B20H
call $15                        # FILE_CLOSE


xorr eax,eax                    # EAX:=0

ret



# ----------------------------------------------------------------
# Initialisierte Daten (00001800 - 000001E00)
# ----------------------------------------------------------------

setp 00001800H                                      # VA: 00402000

db "qa 0.00.00 by Albin Schmutz",13,10,0,0,0

db "XXXXut-Filename: ",0                            # VA: 00402020
db "Open file failed",0                             # VA: 00402032
db "Read file failed",0                             # VA: 00402043
db "Write file failed",0                            # VA: 00402054

db 0,0,0,0,0,0,0,0,0,0

db "0123456789ABCDEF"                               # VA: 00402070

# Fehlermeldungen

setp 00001880H                                      # VA: 00402080

db "Line "                                          # VA: 00402080
db ": "                                             # VA: 00402085
db "unexpected character",0                         # VA: 00402087
db "integer token with more than 11 characters",0   # VA: 0040209C
db "integer token without H postfix",0              # VA: 004020C7
db "unexpected eof in string",0                     # VA: 004020E7
db "string too long",0                              # VA: 00402100
db "unknown symbol",0                               # VA: 00402110
db "integer expected",0                             # VA: 0040211F
db "p to set < active p",0                          # VA: 00402130
db "unexpected token",0                             # VA: 00402144
db "unexpected register",0                          # VA: 00402155
db "register expected",0                            # VA: 00402169
db "comma expected",0                               # VA: 0040217B

# Symboltabellen. Anzahl Symbole in SCN_SYM anpassen.

# Symbole Texte

setp 00001990H                                      # VA: 00402190

db "adda",0,0,0,0
db "addb",0,0,0,0
db "addmr",0,0,0
db "addr",0,0,0,0
db "andb",0,0,0,0
db "call",0,0,0,0
db "clc",0,0,0,0,0
db "cld",0,0,0,0,0
db "cmp",0,0,0,0,0
db "cmpb",0,0,0,0
db "cmpr",0,0,0,0
db "cmprm",0,0,0
db "cmpsb",0,0,0
db "db",0,0,0,0,0,0
db "dd",0,0,0,0,0,0
db "dec",0,0,0,0,0
db "div",0,0,0,0,0
db "eax",0,0,0,0,0
db "ebp",0,0,0,0,0
db "ebx",0,0,0,0,0
db "ecx",0,0,0,0,0
db "edi",0,0,0,0,0
db "edx",0,0,0,0,0
db "esi",0,0,0,0,0
db "esp",0,0,0,0,0
db "inc",0,0,0,0,0
db "incm",0,0,0,0
db "jc",0,0,0,0,0,0
db "jg",0,0,0,0,0,0
db "jmp",0,0,0,0,0
db "jmpm",0,0,0,0
db "jmps",0,0,0,0
db "jnc",0,0,0,0,0
db "jnz",0,0,0,0,0
db "jz",0,0,0,0,0,0
db "loop",0,0,0,0
db "mov",0,0,0,0,0
db "movam",0,0,0
db "movly",0,0,0
db "movlyd",0,0
db "movma",0,0,0
db "movmr",0,0,0
db "movr",0,0,0,0
db "movrm",0,0,0
db "movry",0,0,0
db "movsb",0,0,0
db "movyl",0,0,0
db "movyr",0,0,0
db "mul",0,0,0,0,0
db "not",0,0,0,0,0
db "orb",0,0,0,0,0
db "orr",0,0,0,0,0
db "pop",0,0,0,0,0
db "push",0,0,0,0
db "pushb",0,0,0
db "pushd",0,0,0
db "repnz",0,0,0
db "repz",0,0,0,0
db "ret",0,0,0,0,0
db "retn",0,0,0,0
db "scasb",0,0,0
db "setp",0,0,0,0
db "shl",0,0,0,0,0
db "shls",0,0,0,0
db "shr",0,0,0,0,0
db "shrs",0,0,0,0
db "slotp",0,0,0
db "stc",0,0,0,0,0
db "std",0,0,0,0,0
db "subb",0,0,0,0
db "subr",0,0,0,0
db "subrm",0,0,0
db "xorr",0,0,0,0

# Symbole Sprungtabelle

setp 00001C00H                  # VA: 00402400

dd $104                         # adda (add eax,i32)
dd $112                         # addb (add r32,i8)
dd $109                         # addmr (add [i32],r32)
dd $114                         # addr (add r32,r32)
dd $112                         # andb (and r32,i8)
dd $108                         # call i32
dd $101                         # clc
dd $101                         # cld
dd $113                         # cmp (cmp r32,i32)
dd $112                         # cmpb (cmp r32,i8)
dd $114                         # cmpr (cmp r32,r32)
dd $109                         # cmprm (cmp r32,[i32])
dd $101                         # cmpsb
dd $118                         # PRS_DB
dd $119                         # PRS_DD
dd $105                         # dec (dec r32)
dd $111                         # div (div r32)
dd $100
dd $100
dd $100
dd $100
dd $100
dd $100
dd $100
dd $100
dd $105                         # inc (inc r32)
dd $110                         # incm (inc [i32])
dd $107                         # jc
dd $107                         # jg
dd $108                         # jmp (jmp i32)
dd $117                         # jmpm (jmp [i32])
dd $107                         # jmps (jmp i8)
dd $107                         # jnc
dd $107                         # jnz
dd $107                         # jz
dd $107                         # loop
dd $106                         # mov (mov r32,i32)
dd $104                         # movam (mov eax,[i32])
dd $115                         # movly (mov r8,[r32])
dd $116                         # movlyd (mov r8,[i32+r32])
dd $104                         # movma (mov [i32],eax)
dd $109                         # movmr (mov [i32],r32)
dd $114                         # movr (mov r32,r32)
dd $109                         # movrm (mov r32,[i32])
dd $115                         # movry (mov r32,[r32])
dd $101                         # movsb
dd $114                         # movyl (mov [r32],r8)
dd $114                         # movyr (mov [r32],r32)
dd $111                         # mul (mul r32)
dd $111                         # not (not r32)
dd $112                         # orb (or r32,i8)
dd $114                         # orr (or r32,r32)
dd $105                         # pop (pop r32)
dd $105                         # push (push r32)
dd $102                         # pushb (push i8)
dd $104                         # pushd (push i32)
dd $101                         # repnz
dd $101                         # repz
dd $101                         # ret
dd $103                         # retn (ret i16)
dd $101                         # scasb
dd $120
dd $112                         # shl (shl r32,i8)
dd $111                         # shls (shl r32,1)
dd $112                         # shr (shr r32,i8)
dd $111                         # shrs (shr r32,1)
dd $121
dd $101                         # stc
dd $101                         # std
dd $112                         # subb (sub r32,i8)
dd $114                         # subr (sub r32,r32)
dd $109                         # subrm (sub r32,[i32])
dd $114                         # xorr (xor r32,r32)

#  Symbole Opcodewerte, VA: 00402530

setp 00001D30H

db 05H,0                        # adda
db 83H,0                        # addb
db 01H,192                      # addmr
db 01H,192                      # addr
db 83H,4                        # andb
db 0E8H,0                       # call
db 0F8H,0                       # clc
db 0FCH,0                       # cld
db 81H,7                        # cmp
db 83H,7                        # cmpb
db 39H,192                      # cmpr
db 3BH,7                        # cmprm
db 0A6H,0                       # cmpsb
db 0,0
db 0,0
db 48H,0                        # dec
db 0F7H,6                       # div
db 0,0                          # Register EAX
db 5,0                          # Register EBP
db 3,0                          # Register EBX
db 1,0                          # Register ECX
db 7,0                          # Register EDI
db 2,0                          # Register EDX
db 6,0                          # Register ESI
db 4,0                          # Register ESP
db 40H,0                        # inc
db 0FFH,0                       # incm
db 72H,0                        # jc
db 7FH,0                        # jg
db 0E9H,0                       # jmp
db 0FFH,25H                     # jmpy
db 0EBH,0                       # jmps
db 73H,0                        # jnz
db 75H,0                        # jnz
db 74H,0                        # jz
db 0E2H,0                       # loop
db 0B8H,0                       # mov
db 0A1H,0                       # movam
db 8AH,0                        # movly
db 8AH,128                      # movlyd
db 0A3H,0                       # movma
db 89H,0                        # movmr
db 89H,192                      # movr
db 8BH,0                        # movrm
db 8BH,0                        # movry
db 0A4H,0                       # movsb
db 88H,0                        # movyl
db 89H,0                        # movyr
db 0F7H,4                       # mul
db 0F7H,2                       # not
db 83H,1                        # orb
db 09H,192                      # orr
db 58H,0                        # pop
db 50H,0                        # push
db 6AH,0                        # pushb
db 68H,0                        # pushd
db 0F2H,0                       # repnz
db 0F3H,0                       # repz
db 0C3H,0                       # ret
db 0C2H,0                       # retn
db 0AEH,0                       # scasb
db 0,0
db 0C1H,4                       # shl
db 0D1H,4                       # shls
db 0C1H,5                       # shr
db 0D1H,5                       # shrs
db 0,0
db 0F9H,0                       # stc
db 0FDH,0                       # std
db 83H,5                        # subb
db 29H,192                      # subr
db 2BH,7                        # subrm
db 31H,192                      # xorr

# ----------------------------------------------------------------
# Uninitialisierte Daten
# ----------------------------------------------------------------

# 00403B00 IO_STDIN
# 00403B04 IO_STDOUT
# 00403B08 IO_STDERR
# 00403B0C IO_RES
# 00403B10 SRC_FILE File-Handle der Quelldatei
# 00403B14 SRC_EOB  SRC_BLOCK + Anzahl gelesene Zeichen
# 00403B18 SRC_POS  Aktives Zeichen in SRC_BLOCK
# 00403B1C SRC_LINE Aktive Zeilennummer
# 00403B20 GEN_FILE File-Handle der Zieldatei
# 00403B24 GEN_P Programmposition
# 00403B28 ERR_SP Stackpointer fuer Fehlerbehandlung
# 00403B2C SLOT_ADDR Startadresse Slots

# 00403BF0 IO_BUF

# 00403D00 SCN_BUF bis 00403E00
# 00403E00 SRC_BLOCK bis 00404000

# ----------------------------------------------------------------
# Import-Tabellen (00001E00 - 000001E40)
# ----------------------------------------------------------------

setp 00001E00H                  # VA: 00404000

jmpm 00404054H                  # 00404000 (GetCommandLineA)
jmpm 00404058H                  # 00404006 (VirtualAlloc)
jmpm 0040405CH                  # 0040400C (GetStdHandle)
jmpm 00404060H                  # 00404012 (CloseHandle)
jmpm 00404064H                  # 00404018 (CreateFileA)
jmpm 00404068H                  # 0040401E (ReadFile)
jmpm 0040406CH                  # 00404024 (WriteFile)


setp 00001E2CH                  # VA: 0040402C

# Import table

dd 00004074H                    # OriginalFirstThunk
dd 0                            # TimeDateStamp
dd 0                            # ForwarderChain
dd 00004094H                    # Name
dd 00004054H                    # FirstThunk

dd 0
dd 0
dd 0
dd 0
dd 0

# VA: 00404054

# IAT (array of IMAGE_THUNK_DATA structures)

dd 000040A1H
dd 000040B3H
dd 000040C2H
dd 000040D1H
dd 000040DFH
dd 000040EDH
dd 000040F8H
dd 0

# VA: 00404074

# Import lookup table (array of IMAGE_THUNK_DATA structures)

dd 000040A1H
dd 000040B3H
dd 000040C2H
dd 000040D1H
dd 000040DFH
dd 000040EDH
dd 000040F8H
dd 0


# 00001E94 - 000002000

setp 00001E94H                  # VA: 00404094

db "KERNEL32.dll",0

# VA: 004040A1

db 0,0
db "GetCommandLineA",0

# VA: 004040B3

db 0,0
db "VirtualAlloc",0

# VA: 004040C2

db 0,0
db "GetStdHandle",0

# VA: 004040D1

db 0,0
db "CloseHandle",0

# VA: 004040DF

db 0,0
db "CreateFileA",0

# VA: 004040ED

db 0,0
db "ReadFile",0

# VA: 004040F8

db 0,0
db "WriteFile",0


setp 000002000H
