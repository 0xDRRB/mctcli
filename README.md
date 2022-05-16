# MCTcli
A simple (for now) tool inspired by [MIFARE Classic Tool](https://github.com/ikarus23/MifareClassicTool) on Android but in command-line (and written in C).
It's a tool to try to access the content of a MIFARE Classic tag (1K/S50 or 4K/S70) using [libFreeFare](https://github.com/nfc-tools/libfreefare), [libNFC](https://github.com/nfc-tools/libnfc) and a device supported by libNFC (tested with ACR122U, ASK/LoGO, SCL3711 and PN532-over-USBserial).

At this time `mctcli` can:
- try all keys in a dictionary (`keys.txt` by default, or use `-k file` with one of [those](https://github.com/RfidResearchGroup/proxmark3/tree/master/client/dictionaries))
- display keymap with permissions
- read and display tag content (with colors !)

`mctcli` will, one day (perhaps):
- save dumps to files
- read dumps from file
- write tags from dumps
- change permissions

Usage:

```
>>> List keys to try

$ ./mctcli -l
Key list:
    0: FF FF FF FF FF FF
    1: A0 B0 C0 D0 E0 F0
    2: A1 B1 C1 D1 E1 F1
    3: A0 A1 A2 A3 A4 A5
    4: B0 B1 B2 B3 B4 B5
    5: 4D 3A 99 C3 51 DD
    6: 1A 98 2C 7E 45 9A
    7: 00 00 00 00 00 00
    8: D3 F7 D3 F7 D3 F7
    9: AA BB CC DD EE FF
   10: 41 5A 54 45 4B 4D


>>> Map tag

$ ./mctcli -m
NFC reader: ASK / LoGO opened
0 : Mifare 1k (S50) with UID: 013c2e26
Mapping... Sector:16/16   Key:  1/1  Got it!
        key A         key B         ReadA    ReadB
00:  ffffffffffff  ffffffffffff     000F     0000
01:  ffffffffffff  ffffffffffff     000F     0000
02:  ffffffffffff  ffffffffffff     000F     0000
03:  ffffffffffff  ffffffffffff     000F     0000
04:  ffffffffffff  ffffffffffff     000F     0000
05:  ffffffffffff  ffffffffffff     000F     0000
06:  ffffffffffff  ffffffffffff     000F     0000
07:  ffffffffffff  ffffffffffff     000F     0000
08:  ffffffffffff  ffffffffffff     000F     0000
09:  ffffffffffff  ffffffffffff     000F     0000
10:  ffffffffffff  ffffffffffff     000F     0000
11:  ffffffffffff  ffffffffffff     000F     0000
12:  ffffffffffff  ffffffffffff     000F     0000
13:  ffffffffffff  ffffffffffff     000F     0000
14:  ffffffffffff  ffffffffffff     000F     0000
15:  ffffffffffff  ffffffffffff     000F     0000
Found all keys


>>> Try keys, map and display content:

$ ./mctcli -r
NFC reader: ASK / LoGO opened
0 : Mifare 1k (S50) with UID: 013c2e26
Mapping... Sector:16/16   Key:  1/1  Got it!
Reading: 64/64
+Sector: 0
013C2E26350804006263646566676869
00000000000000000000000000000000
00000000000000000000000000000000
FFFFFFFFFFFFFF078069FFFFFFFFFFFF
+Sector: 1
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
FFFFFFFFFFFFFF078069FFFFFFFFFFFF
+Sector: 2
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
FFFFFFFFFFFFFF078069FFFFFFFFFFFF
+Sector: 3
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
FFFFFFFFFFFFFF078069FFFFFFFFFFFF
+Sector: 4
00000000000000000000000000000000
[...]
```
