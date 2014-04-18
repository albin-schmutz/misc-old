;----------------------------------------------------------------
; qa 0.00.00
; Q-Assembler Basis NASM (fuer Bootstrapping)
; Albin Schmutz @ www.vulture.ch
;----------------------------------------------------------------

BITS 32

;----------------------------------------------------------------
; MS-DOS Header (00000000 - 00000040)
;----------------------------------------------------------------

dw "MZ"                         ;e_magic
times 14 db 0
db "Albin Schmutz @ www.vulture.ch"
times 14 db 0
dd 00000040H                    ;e_lfanew

;----------------------------------------------------------------
; PE Header 24 Bytes (00000040 - 00000058)
;----------------------------------------------------------------

dd "PE"
dw 014CH                        ;Machine (Intel 386)
dw 3                            ;NumberOfSections
dd 0                            ;TimeDateStamp UNUSED
dd 0                            ;PointerToSymbolTable UNUSED
dd 0                            ;NumberOfSymbols UNUSED
dw 00E0H                        ;SizeOfOptionalHeader
dw 010FH                        ;Characteristics

;----------------------------------------------------------------
; PE optionaler Header (00000058 - 000000B8)
;----------------------------------------------------------------

dw 010BH                        ;Magic (PE32)
db 0                            ;MajorLinkerVersion UNUSED
db 0                            ;MinorLinkerVersion UNUSED
dd 00000200H                    ;SizeOfCode UNUSED
dd 00000300H                    ;SizeOfInitializedData UNUSED
dd 0                            ;SizeOfUninitializedData UNUSED
dd 00001000H                    ;AddressOfEntryPoint
dd 00001000H                    ;BaseOfCode UNUSED
dd 00002000H                    ;BaseOfData UNUSED
dd 00400000H                    ;ImageBase
dd 00001000H                    ;SectionAlignment
dd 00000200H                    ;FileAlignment
dw 4                            ;MajorOperatingSystemVer UNUSED
dw 0                            ;MinorOperatingSystemVer UNUSED
dw 0                            ;MajorImageVersion UNUSED
dw 0                            ;MinorImageVersion UNUSED
dw 4                            ;MajorSubsystemVersion
dw 0                            ;MinorSubsystemVersion UNUSED
dd 0                            ;Win32VersionValue UNUSED
dd 00005000H                    ;SizeOfImage
dd 00000200H                    ;SizeOfHeaders
dd 0                            ;CheckSum UNUSED
dw 0003H                        ;Subsystem (Win32 GUI)
dw 0000H                        ;DllCharacteristics UNUSED
dd 00100000H                    ;SizeOfStackReserve UNUSED
dd 00010000H                    ;SizeOfStackCommit
dd 00100000H                    ;SizeOfHeapReserve
dd 00001000H                    ;SizeOfHeapCommit UNUSED
dd 0                            ;LoaderFlags UNUSED
dd 16                           ;NumberOfRvaAndSizes UNUSED

;----------------------------------------------------------------
; Data directories, 16 Eintraege (000000B8 - 00000138)
;----------------------------------------------------------------

dd 0                            ;..00B8  0: Export Table UNUSED
dd 0
dd 0000402CH                    ;..00C0  1: RVA Import Table
dd 00000028H                    ;           size

times 20 dd 0                   ;     2-11: not used

dd 0004054H                     ;..0118 12: RVA IAT
dd 000001CH                     ;           size

times 6 dd 0                    ;    13-15: not used

;----------------------------------------------------------------
; PE code section (00000138 - 00000160)
;----------------------------------------------------------------

db "code",0,0,0,0               ;Name
dd 00001000H                    ;VirtualSize
dd 00001000H                    ;VirtualAddress
dd 00001600H                    ;SizeOfRawData
dd 00000200H                    ;PointerToRawData
dd 0                            ;PointerToRelocations UNUSED
dd 0                            ;PointerToLinenumbers UNUSED
dw 0                            ;NumberOfRelocations UNUSED
dw 0                            ;NumberOfLinenumbers UNUSED
dd 60000020H                    ;Characteristics

;----------------------------------------------------------------
; PE data section (00000160 - 00000188)
;----------------------------------------------------------------

db "data",0,0,0,0               ;Name
dd 00002000H                    ;VirtualSize
dd 00002000H                    ;VirtualAddress
dd 00000600H                    ;SizeOfRawData
dd 00001800H                    ;PointerToRawData
dd 0                            ;PointerToRelocations UNUSED
dd 0                            ;PointerToLinenumbers UNUSED
dw 0                            ;NumberOfRelocations UNUSED
dw 0                            ;NumberOfLinenumbers UNUSED
dd 0C0000040H                   ;Characteristics

;----------------------------------------------------------------
; PE data section (00000188 - 000001B0)
;----------------------------------------------------------------

db "imp",0,0,0,0,0              ;Name
dd 00000102H                    ;VirtualSize
dd 00004000H                    ;VirtualAddress
dd 00000200H                    ;SizeOfRawData
dd 00001E00H                    ;PointerToRawData
dd 0                            ;PointerToRelocations UNUSED
dd 0                            ;PointerToLinenumbers UNUSED
dw 0                            ;NumberOfRelocations UNUSED
dw 0                            ;NumberOfLinenumbers UNUSED
dd 60000020H                    ;Characteristics

;----------------------------------------------------------------
; Filler (000001B0 - 00000200)
;----------------------------------------------------------------

times 80 db 0

;----------------------------------------------------------------
; Code (00000200 - 00001800)
;----------------------------------------------------------------

; Windows APIs sichern EBP, EBX, EDI, ESI und erwarten
; geloeschtes direction flag.

jmp MAIN



;----------------------------------------------------------------
; STR_LEN
;
; Laenge 0-terminierter String in EDI nach ECX.
;----------------------------------------------------------------

STR_LEN:

push edi                        ;EDI sichern
xor ecx,ecx                     ;ECX:=-1
not ecx
xor eax,eax                     ;AL:=0
cld
repnz scasb
not ecx                         ;ECX erhaelt Laenge
dec ecx
pop edi                         ;EDI wieder herstellen
ret



;----------------------------------------------------------------
; MEM_EAX_AS_UINT
;
; EAX als UINT nach EDI schreiben, ECX mit Laenge der Ziffer
; laden und EDI um soviel erhoehen.
; Zerstoert EAX, EBX, EDX.
;----------------------------------------------------------------

MEM_EAX_AS_UINT:

mov ebx,10                      ;durch 10 dividieren
xor ecx,ecx                     ;ECX:=0

L0_MEM_EAX_AS_UINT:
xor edx,edx                     ;EDX:=0
div ebx
add edx,byte '0'
push edx                        ;Ziffer auf Stack
inc ecx
or eax,eax                      ;wenn Rest=0 fertig
jne L0_MEM_EAX_AS_UINT

mov eax,ecx                     ;ECX sichern

L1_MEM_EAX_AS_UINT:
pop edx
mov [edi],dl
inc edi
loop L1_MEM_EAX_AS_UINT

mov ecx,eax                     ;ECX wieder herstellen
ret

;----------------------------------------------------------------
; MEM_EAX_AS_HINT
;
; EAX als 8-stellige HEX Ziffer nach EDI schreiben,  ECX mit 8
; laden und EDI um soviel erhoehen.
; Zerstoert EAX, EBX, EDX.
;----------------------------------------------------------------

MEM_EAX_AS_HINT:

mov ecx,8
push ecx
add edi,ecx
push edi
L0_MEM_EAX_AS_HINT:
mov ebx,eax
shr eax,4H
and ebx,byte 0FH
mov dl,[00402070H+ebx]
dec edi
mov [edi],dl
loop L0_MEM_EAX_AS_HINT
pop edi
pop ecx
ret



;----------------------------------------------------------------
; FILE_OPEN_READ
;
; File in EDI zum Lesen offnen und bei Erfolg File-Handle in EAX
; liefern. Setzt Zero-Flag bei Fehler.
; Zerstoert ECX, EDX.
;----------------------------------------------------------------

FILE_OPEN_READ:

push byte 0                     ;Kein Template
push byte 0                     ;Keine spez. Attribute
push byte 3                     ;Oeffnen
push byte 0                     ;Keine Security
push byte 0                     ;Normal
push 80000000H                  ;Lesend
push edi                        ;Filename
call 00003218H                  ;00404018 (CreateFileA)
cmp eax,byte -1                 ;Fehler?
ret

;----------------------------------------------------------------
; FILE_OPEN_WRITE
;
; File in EDI zum Schreiben oeffnen und bei Erfolg File-Handle in
; EAX liefern. Setzt Zero-Flag bei Fehler.
; Zerstoert ECX, EDX.
;----------------------------------------------------------------

FILE_OPEN_WRITE:

push byte 0                     ;Kein Template
push byte 0                     ;Keine spez. Attribute
push byte 2                     ;Erstellen
push byte 0                     ;Keine Security
push byte 0                     ;Normal
push 40000000H                  ;Schreibend
push edi                        ;Filename
call 00003218H                  ;00404018 (CreateFileA)
cmp eax,byte -1                 ;Fehler?
ret

;----------------------------------------------------------------
; FILE_CLOSE
;
; File in EDX schliessen.
; Zerstoert EAX, ECX, EDX.
;----------------------------------------------------------------

FILE_CLOSE:

push edx
call 00003212H                  ;00404012 (CloseHandle)
ret

;----------------------------------------------------------------
; FILE_READ
;
; ECX Bytes aus File EDX lesen, nach EDI schreiben und IO_RES
; (00403B0C) mit Anzahl gelesener Bytes setzen. Setzt Zero-Flag
; bei Fehler.
; Zerstoert EAX, ECX, EDX.
;----------------------------------------------------------------

FILE_READ:

push byte 0
push 00403B0CH                  ;Resultat nach IO_RES
push ecx                        ;Stringlaenge
push edi                        ;Zieladresse
push edx                        ;File Handle
call 0000321EH                  ;0040401E (ReadFile)
or eax,eax                      ;Fehler?
ret

;----------------------------------------------------------------
; FILE_WRITE
;
; ECX Bytes ab EDI ins File EDX schreiben und IO_RES (00403B0C)
; mit Anzahl geschriebener Bytes setzen. Setzt Zero-Flag bei
; Fehler.
; Zerstoert EAX, ECX, EDX.
;----------------------------------------------------------------

FILE_WRITE:

push byte 0
push 00403B0CH                  ;Resultat nach IO_RES
push ecx                        ;Stringlaenge
push edi                        ;Quelladresse
push edx                        ;File Handle
call 00003224H                  ;00404024 (WriteFile)
or eax,eax                      ;Fehler?
ret

;----------------------------------------------------------------
; FILE_WRITE_LN
;
; Zeilenumbruch (0D0C) ins File EDX schreiben. Setzt Zero-Flag
; bei Fehler.
; Zerstoert EAX, ECX, EDX, EDI.
;----------------------------------------------------------------

FILE_WRITE_LN:

mov edi,0040201BH
mov ecx,2
jmp short FILE_WRITE



;----------------------------------------------------------------
; OUT_STRZ
;
; Nullterminierten Text in EDI ausgeben.
; Zerstoert EAX, ECX, EDX, EDI.
;----------------------------------------------------------------

OUT_STRZ:

call STR_LEN
; dirket weiter mit OUT_STRN

;----------------------------------------------------------------
; OUT_STRN
;
; Text in EDI mit Laenge ECX ausgeben.
; Zerstoert EAX, ECX, EDX, EDI.
;----------------------------------------------------------------

OUT_STRN:

mov edx,[00403B04H]
jmp short FILE_WRITE

;----------------------------------------------------------------
; OUT_UINT
;
; EAX als UINT ausgeben.
; Zerstoert EAX, EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

OUT_UINT:

mov edi,00403BF0H
call MEM_EAX_AS_UINT
sub edi,ecx
jmp short OUT_STRN

;----------------------------------------------------------------
; OUT_HINT
;
; EAX als HEX ausgeben.
; Zerstoert EAX, EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

OUT_HINT:

mov edi,00403BF0H
call MEM_EAX_AS_HINT
sub edi,ecx
jmp short OUT_STRN

;----------------------------------------------------------------
; OUT_LN
;
; Zeilenumbruch ausgeben.
; Zerstoert EAX, ECX, EDX, EDI.
;----------------------------------------------------------------

OUT_LN:

mov edx,[00403B04H]
jmp short FILE_WRITE_LN



;----------------------------------------------------------------
; SRC_BLOCK
;
; Naechster 512 Byte grosser Block aus Quelldatei lesen, SRC_EOB
; auf letztes Zeichen + 1 und SRC_POS auf Position 0 setzen.
; Gibt bei Fehler Meldung aus und setzt Carry Flag.
; Zerstoert EAX, ECX, EDX, EDI.
;----------------------------------------------------------------

L0_SRC_BLOCK:
mov eax,[00403B0CH]             ;Anzahl gelesene Zeichen
add eax,00403E00H               ;SRC_BLOCK
mov [00403B14H],eax             ;SRC_EOB setzen
clc
ret

SRC_BLOCK:

mov edx,[00403B10H]
mov edi,00403E00H               ;SRC_BLOCK
mov [00403B18H],edi
mov ecx,512
call FILE_READ
jnz L0_SRC_BLOCK                ;Kein Fehler?

mov edi,00402043H               ;Doch
mov ecx,23
call OUT_STRN
stc
ret

;----------------------------------------------------------------
; SRC_CHAR
;
; Naechstes Zeichen aus File nach EAX lesen, bei EOF -1, und
; SRC_LINE um 1 erhoehen wenn Zeichen = 10.
; Zerstoert EAX, ECX, EDX, EDI.
;----------------------------------------------------------------

L0_SRC_CHAR:
mov eax,-1
clc
ret

L3_SRC_CHAR:
inc dword[00403B1CH]            ;SRC_LINE erhoehen

L2_SRC_CHAR:
inc dword[00403B18H]            ;SRC_POS erhoehen
ret

L4_SRC_CHAR:
mov esp,[00403B28H]
ret

L1_SRC_CHAR:                    ;EOB
cmp ecx,00404000H               ;ja, EOF erreicht?
jnz L0_SRC_CHAR                 ;ja

call SRC_BLOCK
jc L4_SRC_CHAR                  ;Fehler?

SRC_CHAR:

mov ecx,[00403B18H]             ;ECX erhaelt SRC_POS
cmp ecx,[00403B14H]             ;EOB erreicht?
jz L1_SRC_CHAR                  ;ja

xor eax,eax                     ;EAX:=0
mov al,[ecx]
cmp eax,byte 10                 ;Zeilenende?
jz L3_SRC_CHAR                  ;ja
jmp short L2_SRC_CHAR           ;nein

;----------------------------------------------------------------
; SRC_ERR
;
; Fehlermeldung in ESI mit Zeilenangabe schreiben und nach ERR_SP
; zuerueckkehren.
;----------------------------------------------------------------

SRC_ERR:

mov edi,00402080H
mov ecx,5
call OUT_STRN
mov eax,[00403B1CH]
inc eax
call OUT_UINT
mov edi,00402085H
mov ecx,2
call OUT_STRN
mov edi,esi
call STR_LEN
call OUT_STRN
mov esp,[00403B28H]
ret



;----------------------------------------------------------------
; SCN_IS_LLET
;
; Carry-Flag setzen, wenn EAX kleiner Buchstabe (a-z) enthaelt.
;----------------------------------------------------------------

L0_SCN_IS_LLET:
clc
ret

SCN_IS_LLET:

cmp eax,byte 'a'
jc L0_SCN_IS_LLET
cmp eax,byte 'z'+1
ret

;----------------------------------------------------------------
; SCN_IS_HDIG
;
; Wert (0-15 oder -1) in ECX zu Ziffer in EAX liefern.
;----------------------------------------------------------------

SCN_IS_HDIG:

mov edi,00402070H+15
mov ecx,17

L0_SCN_IS_HDIG:
std
repnz scasb
cld                              ;WIN32 braucht das
dec ecx
ret

;----------------------------------------------------------------
; SCN_IS_DIG
;
; Wert (0-9 oder -1) in ECX zu Ziffer in EAX liefern.
;----------------------------------------------------------------

SCN_IS_DIG:

mov edi,00402070H+9
mov ecx,11
jmp short L0_SCN_IS_HDIG

;----------------------------------------------------------------
; SCN_SYM
;
; In EBX Wert des Symbols und in EAX naechstes Zeichen liefern,
; sonst Fehlerbehandlung.
; Erwartet in EAX erstes Zeichen.
; Zerstoert EBX, ECX, EDX, ESI, EDI, EBP.
;----------------------------------------------------------------

L4_SCN_SYM:
pop eax
mov esi,00402110H               ;Fehlermeldung
jmp SRC_ERR

L3_SCN_SYM:                     ;Identisch
mov ebx,edx                     ;EBX:=32+EDX
add ebx,byte 32
pop eax
ret 8

L2_SCN_SYM:                     ;Groesser
mov eax,edx
inc eax

L1_SCN_SYM:
cmp eax,ebx
jg L4_SCN_SYM

mov edx,eax                     ;EDX erhaelt mittleres Element
add edx,ebx
shr edx,1

add ecx,edi                     ;EDI und ECX wieder herstellen
sub ecx,ebp
mov edi,ebp

lea esi,[00402190H+EDX*8]       ;String vergleichen
rep cmpsb
jz L3_SCN_SYM                   ;Identisch
jc L2_SCN_SYM                   ;Groesser

mov ebx,edx                     ;Kleiner
dec ebx
jmp short L1_SCN_SYM

SCN_SYM:

mov ebx,8                       ;Maximale Laenge: 7
pop edx                         ;Ruecksprungadresse nach EDX
sub esp,ebx                     ;16-Byte Stackframe erstellen
mov ebp,esp
push edx

xor ebx,ebx                     ;EBX:=0

L0_SCN_SYM:
mov [ebp+ebx],al
inc ebx
call SRC_CHAR                   ;naechstes Zeichen
call SCN_IS_LLET
jc L0_SCN_SYM

push eax                        ;Zeichen sichern
mov [ebp+ebx],byte 0            ;String abschliessen
mov edi,ebp                     ;und nach EDI
add edi,ebx                     ;inklusive Laenge
inc edi
xor ecx,ecx
mov eax,0                       ;Untere Grenze
mov ebx,73                      ;Obere Grenze

jmp short L1_SCN_SYM

;----------------------------------------------------------------
; SCN_INT
;
; Liefert in EBX Token 5 (TK_INT), in EAX naechstes Zeichen und
; in ECX Integerwert.
; Erwartet in ECX ersten Ziffernwert.
; Zerstoert ECX, EDX, EDI, ESI, EBP.
;----------------------------------------------------------------

L1_SCN_INT:
mov esi,0040209CH               ;Fehlermeldung
jmp SRC_ERR

L4_SCN_INT:
mov esi,004020C7H               ;Fehlermeldung
jmp SRC_ERR

SCN_INT:

mov ebx,12                      ;Maximale Laenge der Ziffer: 11
pop edx                         ;Ruecksprungadresse nach EDX
mov ebp,esp                     ;12-Byte Stackframe erstellen
sub esp,ebx
push edx

L0_SCN_INT:
dec ebp
dec ebx
or ebx,ebx                      ;EBX=0, Ziffer zu lang?
jz L1_SCN_INT                   ;ja

mov [ebp],cl                    ;Ziffernwert ablegen
call SRC_CHAR
call SCN_IS_HDIG
cmp ecx,byte -1                 ;Ziffer?
jnz L0_SCN_INT                  ;ja, loop

mov esi,10                      ;Basis 10
cmp eax,byte 'H'                ;Hex-Ziffer H am Ende?
jnz L2_SCN_INT                  ;nein

call SRC_CHAR                   ;ja, naechstes Zeichen
mov esi,16                      ;Basis 16

L2_SCN_INT:
mov ecx,12                      ;ECX erhaelt Ziffern-Offset
sub ecx,ebx
push eax                        ;EAX sichern
xor eax,eax                     ;EAX:=0
dec ebp                         ;EBP justieren mit ECX

L3_SCN_INT:
xor ebx,ebx                     ;EBX:=0
mov bl,[ebp+ecx]                ;EBX erhaelt Ziffernwert
cmp ebx,esi                     ;Zifferwert<Basis?
jnc L4_SCN_INT

mul esi                         ;EAX mit Basis multiplzieren
add eax,ebx                     ;und EBX dazu addieren
loop L3_SCN_INT

mov ecx,eax
pop eax
mov ebx,5                       ;TK_INT

ret 12

;----------------------------------------------------------------
; SCN_STR
;
; Liefert in EBX Token 4 (TK_STR), in EAX naechstes Zeichen und
; schreibt String nach SCN_BUF (00403D00) maximal Zeichen in
; d[00403D00]. Schreibt Fehlermeldung, wenn String zu lang.
; Zerstoert ECX, EDX, EDI, ESI.
;----------------------------------------------------------------

L1_SCN_STR:
mov esi,004020E7H               ;Fehlermeldung
jmp SRC_ERR

L3_SCN_STR:
mov esi,00402100H               ;Fehlermeldung
jmp SRC_ERR

L2_SCN_STR:
mov ebx,4
jmp SRC_CHAR

SCN_STR:

mov esi,00403D00H               ;Zieladresse String
mov ebx,[esi]                   ;Maximale erlaubte Laenge

L0_SCN_STR:
call SRC_CHAR
cmp eax,byte -1
jz L1_SCN_STR

cmp eax,byte '"'
jz L2_SCN_STR

or ebx,ebx
jz L3_SCN_STR

mov [esi],al
inc esi
dec ebx
jmp short L0_SCN_STR

L9_SCN_COMMENT:
ret

;----------------------------------------------------------------
; SCN_COMMENT
;
; Ueberliesst Kommentar inklusive abschliessendes \n.
; Liefert in EAX naechstes Zeichen.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

SCN_COMMENT:

call SRC_CHAR
cmp eax,byte -1
jz L9_SCN_COMMENT
cmp eax,byte 10
jnz SCN_COMMENT
jmp SRC_CHAR

;----------------------------------------------------------------
; SCN_TOKEN
;
; Liefert naechstes Token in EBX und naechstes Zeichen in EAX.
; Erwartet in EAX erstes Zeichen.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

L7_SCN_TOKEN:
push ebp
call SCN_INT                    ;EBX:=5 (TK_INT)
pop ebp
ret

L4_SCN_TOKEN:
jmp SCN_STR                     ;EBX:=4 (TK_STR)

L6_SCN_TOKEN:
inc ebx                         ;EBX:=3 (TK_SLOT)

L5_SCN_TOKEN:
inc ebx                         ;EBX:=2 (TK_COMMA)

L1_SCN_TOKEN:
inc ebx                         ;EBX:=1 (TK_EOL)
jmp SRC_CHAR

L8_SCN_TOKEN:
push ebp
call SCN_SYM
pop ebp
L9_SCN_TOKEN:
ret

L3_SCN_TOKEN:
call SCN_COMMENT
jmp short SCN_TOKEN

L2_SCN_TOKEN:
call SRC_CHAR

SCN_TOKEN:

xor ebx,ebx                     ;EBX:=0 (TK_EOF)
cmp eax,byte -1
jz L9_SCN_TOKEN

cmp eax,byte 10                 ;EOL?
jz L1_SCN_TOKEN

cmp eax,byte 33                 ;Whitespace oder Space?
jc L2_SCN_TOKEN

cmp eax,byte '#'                ;Kommentar
jz L3_SCN_TOKEN

cmp eax,byte '"'                ;String
jz L4_SCN_TOKEN

cmp eax,byte ','                ;Komma
jz L5_SCN_TOKEN

cmp eax,byte '$'                ;Slot
jz L6_SCN_TOKEN

call SCN_IS_DIG                 ;Integer
cmp ecx,byte -1
jnz L7_SCN_TOKEN

call SCN_IS_LLET                ;Symbol
jc L8_SCN_TOKEN

mov esi,00402087H               ;Fehlermeldung
jmp SRC_ERR



;----------------------------------------------------------------
; GEN_WRITE
;
; Schliesst GEN_S, GEN_B, GEN_W und GEN_D ab.
; Stellt EAX vom Stack wieder her.
;----------------------------------------------------------------

L0_GEN_WRITE:
mov esi,00402054H               ;Fehlermeldung
jmp SRC_ERR

GEN_WRITE:

add [00403B24H],ecx             ;GEN_P erhoehen
mov edx,[00403B20H]
call FILE_WRITE
jz L0_GEN_WRITE

pop eax
L1_GEN_WRITE:
ret

;----------------------------------------------------------------
; GEN_S
;
; Schreibt SCN_BUF (00403D00) bis ESI ins Zielfile.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

GEN_S:

push eax
mov edi,00403D00H
mov ecx,esi
sub ecx,edi
jmp short GEN_WRITE

;----------------------------------------------------------------
; GEN_B
;
; Schreibt Byte in ECX ins Zielfile.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

GEN_B:

push eax
mov edi,00403D00H
mov [edi],cl
mov ecx,1
jmp short GEN_WRITE

;----------------------------------------------------------------
; GEN_W
;
; Schreibt Word in ECX ins Zielfile.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

GEN_W:

push eax
mov edi,00403D00H
mov [edi],cx
mov ecx,2
jmp short GEN_WRITE

;----------------------------------------------------------------
; GEN_D
;
; Schreibt Doubleword ECX ins Zielfile.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

GEN_D:

push eax
mov edi,00403D00H
mov [edi],ecx
mov ecx,4
jmp short GEN_WRITE

;----------------------------------------------------------------
; GEN_OC1
;
; Generiert 1-Byte-Opcode zu Symbol EBX.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

GEN_OC1:

mov cl,[00402530H+EBX*2]
jmp short GEN_B

;----------------------------------------------------------------
; GEN_OC2
;
; Generiert 2-Byte-Opcode zu Symbol EBX.
; Zerstoert ECX, EDX, EDI.
;----------------------------------------------------------------

GEN_OC2:

mov cx,[00402530H+EBX*2]
jmp short GEN_W



;----------------------------------------------------------------
; PRS_ACC_INT
;
; Fuehrt SCN_TOKEN aus, erwartet TK_INT oder TK_SLOT und liefert
; naechstes Zeichen in EAX und Integer in ECX.
; Erwartet in EAX erstes Zeichen.
; Zerstoert EBX, EDX, EDI.
;----------------------------------------------------------------

L1_PRS_ACC_INT:
cmp ebx,byte 5                  ;EBX=TK_INT?
jz L1_GEN_WRITE                 ;ret

L2_PRS_ACC_INT:
mov esi,0040211FH               ;Fehlermeldung
jmp SRC_ERR

PRS_ACC_INT:

call SCN_TOKEN
cmp ebx,byte 3                  ;EBX=TK_SLOT?
jnz L1_PRS_ACC_INT

call SCN_TOKEN
cmp ebx,byte 5                  ;EBX=TK_INT?
jnz L2_PRS_ACC_INT

and ecx,255
mov edi,[00403B2CH]
mov ecx,[edi+ecx*4]
ret

;----------------------------------------------------------------
; PRS_ACC_REG
;
; Liefert Register Wert in ECX und liefert naechstes Zeichen in
; EAX oder gibt Fehlermeldung aus.
; Erwartet in EAX erstes Zeichen.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

L9_PRS_ACC_REG:
mov esi,00402169H
jmp SRC_ERR

PRS_ACC_REG:

call SCN_TOKEN
sub ebx,byte 32                 ;Symbol?
jc L9_PRS_ACC_REG

xor ecx,ecx
mov cl,[00402530H+ebx*2]
ret

;----------------------------------------------------------------
; PRS_ACC_COMMA
;
; Liefert naechstes Zeichen in oder gibt Fehlermeldung aus,
; wenn Token nicht Komma ist.
; Erwartet in EAX Komma.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

L9_PRS_ACC_COMMA:
mov esi,0040217BH
jmp SRC_ERR

PRS_ACC_COMMA:

call SCN_TOKEN
cmp ebx,byte 2                  ;TK_COMMA
jnz L9_PRS_ACC_COMMA
ret

;----------------------------------------------------------------
; PRS_MR_SYM
;
; EBP erhaelt ModR/M aus Symboltabelle (EBX).
; Zerstoert EBX, ECX.
;----------------------------------------------------------------

PRS_MR_SYM:

xor ecx,ecx
mov cl,[00402530H+1+EBX*2]
mov ebp,ecx
ret

;----------------------------------------------------------------
; PRS_OC1_MR_11_SYM_RRR_SUB
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: 11, reg: Symboltabelle, r/m: Register
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_11_SYM_RRR_SUB:

call GEN_OC1
call PRS_MR_SYM                 ;EBP erhaelt ModR/M reg
shl ebp,3
call PRS_ACC_REG
add ecx,ebp                     ;ModR/M r/m
add ecx,byte 192                ;ModR/M mod: 11000000
call GEN_B
ret

;----------------------------------------------------------------
; PRS_OC1_MR_SY_RRS_RRT_SUB
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: Symboltabelle, reg: Zielregister, r/m: Quellregister.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_SY_RRS_RRT_SUB:

call GEN_OC1
call PRS_MR_SYM                 ;EBP erhaelt ModR/M mod
call PRS_ACC_REG
shl ecx,3                       ;EBP erhaelt ModR/M reg
add ebp,ecx
call PRS_ACC_COMMA
call PRS_ACC_REG
add ecx,ebp                     ;ModR/M r/m
call GEN_B
ret



;----------------------------------------------------------------
; PRS_ERR_REG
;
; Register als 1. Symbol. Gibt Fehlermeldung aus und bricht ab.
;----------------------------------------------------------------

PRS_ERR_REG:

mov esi,00402155H               ;Fehlermeldung
jmp SRC_ERR

;----------------------------------------------------------------
; PRS_OC1
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1:

call GEN_OC1
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_B
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von B-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_B:

call GEN_OC1
call PRS_ACC_INT
call GEN_B
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_W
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von W-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_W:

call GEN_OC1
call PRS_ACC_INT
call GEN_W
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von D-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_D:

call GEN_OC1
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_R
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX und addiert Register dazu.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_R:

mov ebp,ebx
call PRS_ACC_REG
add cl,[00402530H+EBP*2]
call GEN_B
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_R_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX, addiert Register dazu und
; generiert D-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_R_D:

mov ebp,ebx
call PRS_ACC_REG
add cl,[00402530H+EBP*2]
call GEN_B
call PRS_ACC_COMMA
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC_JMP_B
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX und berechnet relativen
; Jump B-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC_JMP_B:

call GEN_OC1
call PRS_ACC_INT
sub ecx,[00403B24H]
dec ecx
call GEN_B
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC_JMP_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX und berechnet relativen
; Jump D-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC_JMP_D:

call GEN_OC1
call PRS_ACC_INT
sub ecx,[00403B24H]
sub ecx,byte 4
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_00_RRR_101_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M.
; mod: 00, reg: Register, r/m: 101
; Dann wird Doubleword gelesen.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_00_RRR_101_D:

call GEN_OC1
call PRS_ACC_REG
shl ecx,3                       ;ModR/M reg
or ecx,byte 5                   ;00 %%% 101
call GEN_B
call PRS_ACC_COMMA
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_00_SYM_101_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M.
; mod: 00, reg: Symboltabelle, r/m: 101
; Dann wird Doubleword gelesen.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_00_SYM_101_D:

call GEN_OC1
call PRS_MR_SYM                 ;EBP erhaelt ModR/M reg
shl ebp,3
mov ecx,5                       ;00000101
add ecx,ebp
call GEN_B
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_11_SYM_RRR
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: 11, reg: Symboltabelle, r/m: Register
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_11_SYM_RRR:

call PRS_OC1_MR_11_SYM_RRR_SUB
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_11_SYM_RRR_B
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: 11, reg: Symboltabelle, r/m: Register
; Dann wird Byte gelesen.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_11_SYM_RRR_B:

call PRS_OC1_MR_11_SYM_RRR_SUB
call PRS_ACC_COMMA
call PRS_ACC_INT
call GEN_B
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_11_SYM_RRR_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: 11, reg: Symboltabelle, r/m: Register
; Dann wird Doubleword gelesen.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_11_SYM_RRR_D:

call PRS_OC1_MR_11_SYM_RRR_SUB
call PRS_ACC_COMMA
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_SY_RRT_RRS
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: Symboltabelle, reg: Quellregister, r/m: Zielregister.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_SY_RRT_RRS:

call GEN_OC1
call PRS_MR_SYM                 ;EBP erhaelt ModR/M mod
call PRS_ACC_REG
add ebp,ecx                     ;EBP erhaelt ModR/M r/m
call PRS_ACC_COMMA
call PRS_ACC_REG
shl ecx,3                       ;ModR/M reg
add ecx,ebp
call GEN_B
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_SY_RRS_RRT
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: Symboltabelle, reg: Zielregister, r/m: Quellregister.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_SY_RRS_RRT:

call PRS_OC1_MR_SY_RRS_RRT_SUB
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC1_MR_SY_RRS_RRT_D
;
; Erzeugt 1-Byte-Opcode zu Symbol EBX gefolgt von ModR/M:
; mod: Symboltabelle, reg: Zielregister, r/m: Quellregister.
; Dann wird Double-Word gelesen.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC1_MR_SY_RRS_RRT_D:

call PRS_OC1_MR_SY_RRS_RRT_SUB
call PRS_ACC_COMMA
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_OC2_D
;
; Erzeugt 2-Byte-Opcode zu Symbol EBX gefolgt von D-Wert.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_OC2_D:

call GEN_OC2
call PRS_ACC_INT
call GEN_D
jmp SCN_TOKEN

;----------------------------------------------------------------
; PRS_DB
;
; Liest Byte-Datentokens ein (Integer oder String) und schreibt
; sie in Zielfile.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

L7_PRS_DB:
mov esi,00402144H               ;Fehlermeldung
jmp SRC_ERR

L9_PRS_DB:
ret

L1_PRS_DB:
cmp ebx,byte 4                  ;EBX=TK_STR?
jnz L7_PRS_DB

call GEN_S

L8_PRS_DB:
call SCN_TOKEN
cmp ebx,byte 2                  ;EBX=TK_COMMA?
jnz L9_PRS_DB

PRS_DB:

mov [00403D00H],dword 256       ;Maximale Laenge String
call SCN_TOKEN
or ebx,ebx                      ;EBX=TK_EOF?
jz L9_PRS_DB

cmp ebx,byte 1                  ;EBX=TK_EOL?
jz L9_PRS_DB

cmp ebx,byte 5                  ;EBX=TK_INT?
jnz L1_PRS_DB

call GEN_B
jmp short L8_PRS_DB

;----------------------------------------------------------------
; PRS_DD
;
; Liest Doubleword-Integers ein und schreibt sie in Zielfile.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_DD:

call PRS_ACC_INT
or ebx,ebx                      ;EBX=TK_EOF?
jz L9_PRS_DB

cmp ebx,byte 1                  ;EBX=TK_EOL?
jz L9_PRS_DB

call GEN_D
call SCN_TOKEN
cmp ebx,byte 2                  ;EBX=TK_COMMA?
jz PRS_DD

ret

;----------------------------------------------------------------
; PRS_SETP
;
; Schreibt soviele 0 Bytes in Zielfile bis Position nach
; setp erreicht ist.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

L9_PRS_SETP:
jmp SCN_TOKEN

L0_PRS_SETP:
mov esi,00402130H               ;Fehlermeldung
jmp SRC_ERR

PRS_SETP:

call PRS_ACC_INT
mov ebx,ecx
sub ebx,[00403B24H]             ;Vergleicht neuer P mit akt.
jz L9_PRS_SETP
jc L0_PRS_SETP

L1_PRS_SETP:
xor ecx,ecx
call GEN_B
dec ebx
or ebx,ebx
jz L9_PRS_SETP
jmp short L1_PRS_SETP

;----------------------------------------------------------------
; PRS_SLOTP
;
; Slot (0-255) mit Position laden.
; Liest naechstes Token ein.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

PRS_SLOTP:

call PRS_ACC_INT
mov ebx,[00403B24H]
and ecx,255
mov edi,[00403B2CH]
mov [edi+ecx*4],ebx
jmp SCN_TOKEN



;----------------------------------------------------------------
; PRS_LINE
;
; Parst Zeile fuer Zeile.
; Springt bei Fehler direkt von hier zurueck.
; Zerstoert EBX, ECX, EDX, EDI.
;----------------------------------------------------------------

L9_PRS_LINE:
ret

L6_PRS_LINE:
mov esi,00402144H               ;Fehlermeldung
jmp SRC_ERR

PRS_LINE:

mov [00403B28H],esp             ;Stackpointer Fehlerbehandlung
call SRC_CHAR

L0_PRS_LINE:
call SCN_TOKEN

L1_PRS_LINE:
or ebx,ebx                      ;EBX=TK_EOF?
jz L9_PRS_LINE

cmp ebx,byte 1                  ;EBX=TK_EOL?
jz L0_PRS_LINE

cmp ebx,byte 32                 ;Symbol?
jc L6_PRS_LINE

sub ebx,byte 32
mov edx,[00402400H+EBX*4]
add edx,00400E00H
call edx
jmp short L1_PRS_LINE

ret

times 208 db 0
times 256 db 0
times 256 db 0
times 256 db 0
times 256 db 0
times 256 db 0
times 256 db 0



;----------------------------------------------------------------
; 00001000
; Main
;----------------------------------------------------------------

MAIN:

; Standard-Device File-Handles initialisieren

push byte -10                   ;STD_INPUT_HANDLE
call 0000320CH                  ;0040400C (GetStdHandle)
mov [00403B00H],eax

push byte -11                   ;STD_OUTPUT_HANDLE
call 0000320CH                  ;0040400C (GetStdHandle)
mov [00403B04H],eax

push byte -12                   ;STD_ERROR_HANDLE
call 0000320CH                  ;0040400C (GetStdHandle)
mov [00403B08H],eax


; Titel ausgeben

mov edi,00402000H
call OUT_STRZ


; Filename aus Kommandozeile parsen

call 00003200H                  ;00404000 (GetCommandLineA)
L0_MAIN:                        ;Erstes Space oder \0 suchen
inc eax
cmp [eax],byte 0
jz L2_MAIN
cmp [eax],byte 32
jnz L0_MAIN
dec eax
L1_MAIN:                        ;Erstes Nicht-Space suchen
inc eax
cmp [eax],byte 32
jz L1_MAIN

L2_MAIN:
mov edi,eax
call STR_LEN
and ecx,byte 0FH                ;Stringlaenge begrenzen
mov esi,edi
mov edi,00403E00H               ;SRC_BLOCK als Buffer
rep movsb
mov ebx,edi


; Input-Filename zusammenstellen und ausgeben

mov [ebx],dword '.asm'
mov [ebx+4], byte 0
mov edi,00402020H
mov [edi],dword ' Inp'
inc edi
call OUT_STRZ
mov edi,00403E00H               ;SRC_BLOCK als Buffer
call OUT_STRZ
call OUT_LN


; File zum Lesen oeffnen

mov edi,00403E00H               ;SRC_BLOCK als Buffer
call FILE_OPEN_READ
jnz L3_MAIN                     ;Fehler?
mov edi,00402032H               ;ja
call OUT_STRZ
mov eax,1
ret
L3_MAIN:
mov [00403B10H],eax


; Output-Filename zusammenstellen und ausgeben

mov [ebx],dword '.exe'
mov [ebx+4],byte 0
mov edi,00402020H
mov [edi],dword 'Outp'
call OUT_STRZ
mov edi,00403E00H               ;SRC_BLOCK als Buffer
call OUT_STRZ
call OUT_LN


; File zum Schreiben oeffnen

mov edi,00403E00H               ;SRC_BLOCK als Buffer
call FILE_OPEN_WRITE
jnz L4_MAIN                     ;Fehler?
mov edi,00402032H               ;ja
call OUT_STRZ
mov eax,1
ret
L4_MAIN:
mov [00403B20H],eax


; Speicher fuer SLOTs reservieren

push 4H                         ;PAGE_READWRITE
push 3000H                      ;MEM_COMMIT | MEM_RESERVE
push 1024                       ;Anzahl Bytes
push 0                          ;keine lpAddress vorgeben
call 00003206H                  ;00404006 (VirtualAlloc)
or eax,eax                      ;cmp eax,0
jnz L5_MAIN
mov eax,1
ret
L5_MAIN:
mov [00403B2CH],eax              ;Startadresse sichern


; SRC und GEN initialisieren

mov [00403B1CH],dword 0         ;SRC_LINE:=0
call SRC_BLOCK
jc L9_MAIN

; Parser starten

call PRS_LINE


L9_MAIN:


; Files schliessen

mov edx,[00403B10H]
call FILE_CLOSE
mov edx,[00403B20H]
call FILE_CLOSE


xor eax,eax                     ;EAX:=0

ret


times 186 db 0

times 256 db 0
times 256 db 0
times 256 db 0
times 256 db 0
times 256 db 0
times 256 db 0



;----------------------------------------------------------------
; Initialisierte Daten (00001800 - 000001E00)
;----------------------------------------------------------------

; VA: 00402000

db "qa 0.00.00 by Albin Schmutz",13,10,0,0,0

db "XXXXut-Filename: ",0                            ;VA: 00402020
db "Open file failed",0                             ;VA: 00402032
db "Read file failed",0                             ;VA: 00402043
db "Write file failed",0                            ;VA: 00402054

db 0,0,0,0,0,0,0,0,0,0

db "0123456789ABCDEF"                               ;VA: 00402070

; Fehlermeldungen

db "Line "                                          ;VA: 00402080
db ": "                                             ;VA: 00402085
db "unexpected character",0                         ;VA: 00402087
db "integer token with more than 11 characters",0   ;VA: 0040209C
db "integer token without H postfix",0              ;VA: 004020C7
db "unexpected eof in string",0                     ;VA: 004020E7
db "string too long",0                              ;VA: 00402100
db "unknown symbol",0                               ;VA: 00402110
db "integer expected",0                             ;VA: 0040211F
db "p to set < active p",0                          ;VA: 00402130
db "unexpected token",0                             ;VA: 00402144
db "unexpected register",0                          ;VA: 00402155
db "register expected",0                            ;VA: 00402169
db "comma expected",0                               ;VA: 0040217B

times 6 db 0

; Symboltabellen. Anzahl Symbole in SCN_SYM anpassen.

; Symbole Texte, VA: 00402190

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

times 8 db 0
times 8 db 0
times 8 db 0
times 8 db 0
times 8 db 0

; Symbole Sprungtabelle, VA: 00402400

dd PRS_OC1_D                    ;adda (add eax,i32)
dd PRS_OC1_MR_11_SYM_RRR_B      ;addb (add r32,i8)
dd PRS_OC1_MR_00_RRR_101_D      ;addmr (add [i32],r32)
dd PRS_OC1_MR_SY_RRT_RRS        ;addr (add r32,r32)
dd PRS_OC1_MR_11_SYM_RRR_B      ;andb (and r32,i8)
dd PRS_OC_JMP_D                 ;call i32
dd PRS_OC1                      ;clc
dd PRS_OC1                      ;cld
dd PRS_OC1_MR_11_SYM_RRR_D      ;cmp (cmp r32,i32)
dd PRS_OC1_MR_11_SYM_RRR_B      ;cmpb (cmp r32,i8)
dd PRS_OC1_MR_SY_RRT_RRS        ;cmpr (cmp r32,r32)
dd PRS_OC1_MR_00_RRR_101_D      ;cmprm (cmp r32,[i32])
dd PRS_OC1                      ;cmpsb
dd PRS_DB
dd PRS_DD
dd PRS_OC1_R                    ;dec (dec r32)
dd PRS_OC1_MR_11_SYM_RRR        ;div (div r32)
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_ERR_REG
dd PRS_OC1_R                    ;inc (inc r32)
dd PRS_OC1_MR_00_SYM_101_D      ;incm (inc [i32])
dd PRS_OC_JMP_B                 ;jc
dd PRS_OC_JMP_B                 ;jg
dd PRS_OC_JMP_D                 ;jmp (jmp i32)
dd PRS_OC2_D                    ;jmpm (jmp [i32])
dd PRS_OC_JMP_B                 ;jmps (jmp i8)
dd PRS_OC_JMP_B                 ;jnc
dd PRS_OC_JMP_B                 ;jnz
dd PRS_OC_JMP_B                 ;jz
dd PRS_OC_JMP_B                 ;loop
dd PRS_OC1_R_D                  ;mov (mov r32,i32)
dd PRS_OC1_D                    ;movam (mov eax,[i32])
dd PRS_OC1_MR_SY_RRS_RRT        ;movly (mov r8,[r32])
dd PRS_OC1_MR_SY_RRS_RRT_D      ;movlyd (mov r8,[i32+r32])
dd PRS_OC1_D                    ;movma (mov [i32],eax)
dd PRS_OC1_MR_00_RRR_101_D      ;movmr (mov [i32],r32)
dd PRS_OC1_MR_SY_RRT_RRS        ;movr (mov r32,r32)
dd PRS_OC1_MR_00_RRR_101_D      ;movrm (mov r32,[i32])
dd PRS_OC1_MR_SY_RRS_RRT        ;movry (mov r32,[r32])
dd PRS_OC1                      ;movsb
dd PRS_OC1_MR_SY_RRT_RRS        ;movyl (mov [r32],r8)
dd PRS_OC1_MR_SY_RRT_RRS        ;movyr (mov [r32],r32)
dd PRS_OC1_MR_11_SYM_RRR        ;mul (mul r32)
dd PRS_OC1_MR_11_SYM_RRR        ;not (not r32)
dd PRS_OC1_MR_11_SYM_RRR_B      ;orb (or r32,i8)
dd PRS_OC1_MR_SY_RRT_RRS        ;orr (or r32,r32)
dd PRS_OC1_R                    ;pop (pop r32)
dd PRS_OC1_R                    ;push (push r32)
dd PRS_OC1_B                    ;pushb (push i8)
dd PRS_OC1_D                    ;pushd (push i32)
dd PRS_OC1                      ;repnz
dd PRS_OC1                      ;repz
dd PRS_OC1                      ;ret
dd PRS_OC1_W                    ;retn (ret i16)
dd PRS_OC1                      ;scasb
dd PRS_SETP
dd PRS_OC1_MR_11_SYM_RRR_B      ;shl (shl r32,i8)
dd PRS_OC1_MR_11_SYM_RRR        ;shls (shl r32,1)
dd PRS_OC1_MR_11_SYM_RRR_B      ;shr (shr r32,i8)
dd PRS_OC1_MR_11_SYM_RRR        ;shrs (shr r32,1)
dd PRS_SLOTP
dd PRS_OC1                      ;stc
dd PRS_OC1                      ;std
dd PRS_OC1_MR_11_SYM_RRR_B      ;subb (sub r32,i8)
dd PRS_OC1_MR_SY_RRT_RRS        ;subr (sub r32,r32)
dd PRS_OC1_MR_00_RRR_101_D      ;subrm (sub r32,[i32])
dd PRS_OC1_MR_SY_RRT_RRS        ;xorr (xor r32,r32)

times 12 db 0

; Symbole Opcodewerte, VA: 00402530

db 05H,0                        ;adda
db 83H,0                        ;addb
db 01H,192                      ;addmr
db 01H,192                      ;addr
db 83H,4                        ;andb
db 0E8H,0                       ;call
db 0F8H,0                       ;clc
db 0FCH,0                       ;cld
db 81H,7                        ;cmp
db 83H,7                        ;cmpb
db 39H,192                      ;cmpr
db 3BH,7                        ;cmprm
db 0A6H,0                       ;cmpsb
db 0,0
db 0,0
db 48H,0                        ;dec
db 0F7H,6                       ;div
db 0,0                          ;Register EAX
db 5,0                          ;Register EBP
db 3,0                          ;Register EBX
db 1,0                          ;Register ECX
db 7,0                          ;Register EDI
db 2,0                          ;Register EDX
db 6,0                          ;Register ESI
db 4,0                          ;Register ESP
db 40H,0                        ;inc
db 0FFH,0                       ;incm
db 72H,0                        ;jc
db 7FH,0                        ;jg
db 0E9H,0                       ;jmp
db 0FFH,25H                     ;jmpy
db 0EBH,0                       ;jmps
db 73H,0                        ;jnz
db 75H,0                        ;jnz
db 74H,0                        ;jz
db 0E2H,0                       ;loop
db 0B8H,0                       ;mov
db 0A1H,0                       ;movam
db 8AH,0                        ;movly
db 8AH,128                      ;movlyd
db 0A3H,0                       ;movma
db 89H,0                        ;movmr
db 89H,192                      ;movr
db 8BH,0                        ;movrm
db 8BH,0                        ;movry
db 0A4H,0                       ;movsb
db 88H,0                        ;movyl
db 89H,0                        ;movyr
db 0F7H,4                       ;mul
db 0F7H,2                       ;not
db 83H,1                        ;orb
db 09H,192                      ;orr
db 58H,0                        ;pop
db 50H,0                        ;push
db 6AH,0                        ;pushb
db 68H,0                        ;pushd
db 0F2H,0                       ;repnz
db 0F3H,0                       ;repz
db 0C3H,0                       ;ret
db 0C2H,0                       ;retn
db 0AEH,0                       ;scasb
db 0,0
db 0C1H,4                       ;shl
db 0D1H,4                       ;shls
db 0C1H,5                       ;shr
db 0D1H,5                       ;shrs
db 0,0
db 0F9H,0                       ;stc
db 0FDH,0                       ;std
db 83H,5                        ;subb
db 29H,192                      ;subr
db 2BH,7                        ;subrm
db 31H,192                      ;xorr

times 14 db 0
times 16 db 0
times 16 db 0
times 16 db 0

;----------------------------------------------------------------
; Uninitialisierte Daten
;----------------------------------------------------------------

; 00403B00 IO_STDIN
; 00403B04 IO_STDOUT
; 00403B08 IO_STDERR
; 00403B0C IO_RES
; 00403B10 SRC_FILE File-Handle der Quelldatei
; 00403B14 SRC_EOB  SRC_BLOCK + Anzahl gelesene Zeichen
; 00403B18 SRC_POS  Aktives Zeichen in SRC_BLOCK
; 00403B1C SRC_LINE Aktive Zeilennummer
; 00403B20 GEN_FILE File-Handle der Zieldatei
; 00403B24 GEN_P Programmposition
; 00403B28 ERR_SP Stackpointer fuer Fehlerbehandlung
; 00403B2C SLOT_ADDR Startadresse Slots

; 00403BF0 IO_BUF

; 00403D00 SCN_BUF bis 00403E00
; 00403E00 SRC_BLOCK bis 00404000

;----------------------------------------------------------------
; Import-Tabellen (00001E00 - 000001E40)
; 00001E00 - 000001E40
;----------------------------------------------------------------

; VA: 00404000

jmp [00404054H]                 ;00404000 (GetCommandLineA)
jmp [00404058H]                 ;00404006 (VirtualAlloc)
jmp [0040405CH]                 ;0040400C (GetStdHandle)
jmp [00404060H]                 ;00404012 (CloseHandle)
jmp [00404064H]                 ;00404018 (CreateFileA)
jmp [00404068H]                 ;0040401E (ReadFile)
jmp [0040406CH]                 ;00404024 (WriteFile)
db 0,0                          ;Filler


; VA: 0040402C
; Import table

dd 00004074H                    ;OriginalFirstThunk
dd 0                            ;TimeDateStamp
dd 0                            ;ForwarderChain
dd 00004094H                    ;Name
dd 00004054H                    ;FirstThunk

dd 0
dd 0
dd 0
dd 0
dd 0

; VA: 00404054
; IAT (array of IMAGE_THUNK_DATA structures)

dd 000040A1H
dd 000040B3H
dd 000040C2H
dd 000040D1H
dd 000040DFH
dd 000040EDH
dd 000040F8H
dd 0

; VA: 00404074
; Import lookup table (array of IMAGE_THUNK_DATA structures)

dd 000040A1H
dd 000040B3H
dd 000040C2H
dd 000040D1H
dd 000040DFH
dd 000040EDH
dd 000040F8H
dd 0

;----------------------------------------------------------------
; 00001E94 - 000002000
;----------------------------------------------------------------

; VA: 00404094

db "KERNEL32.dll",0

; VA: 004040A1

dw 0
db "GetCommandLineA",0

; VA: 004040B3

dw 0
db "VirtualAlloc",0

; VA: 004040C2

dw 0
db "GetStdHandle",0

; VA: 004040D1

dw 0
db "CloseHandle",0

; VA: 004040DF

dw 0
db "CreateFileA",0

; VA: 004040ED

dw 0
db "ReadFile",0

; VA: 004040F8

dw 0
db "WriteFile",0

times 252 db 0
