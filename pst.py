# -*- coding: utf-8 -*-
'''
Created on 7 juil. 2016

@author: Plouf  
'''
import binascii
from array import *
import struct
from _ctypes import buffer_info


def swap_order(d, wsz=4, gsz=2):
    return "".join(["".join([m[i:i+gsz]
                            for i in range(wsz-gsz, -gsz, -gsz)])
                            for m in [d[i:i+wsz] for i in range(0, len(d), wsz)]])


def swap_order16(d):
    return "".join(d[i:i+2] for i in range(len(d)-2,-1,-2))

TYPE = ""
file = "backup.pst"
f_in = open(file, 'rb')
print("**********  HEADER   ****************")
dwMagic = f_in.read(4)
# print(dwMagic.hex())
if "!BDN" == "".join("{:c}".format(c) for c in dwMagic):
    print("OK ! on lit un .pst")
else:
    print("Ben non ! marche pas !")
dwCRCPartial = f_in.read(4)
a = struct.unpack("<I", dwCRCPartial)
# a = swap_order(dwCRCPartial.hex(), 4, 2)
# print(int(a, 16),
print(a[0],
      "The 32-bit cyclic redundancy check (CRC) value of",
      " the 471 bytes of data starting from wMagicClient (0ffset 0x0008)")
'''for i in range(1,472):
    buff2.append(buff[471-i])
print(buff2)'''
# c = buff.hex()
wMagicClient = f_in.read(2)
if "534d" == "".join("{:02x}".format(c) for c in wMagicClient):
    print("OK wMagicClient == 53 4D ")
else:
    print("wMagicClient (2 bytes): MUST be { 0x53, 0x4D }")
wVer = sum(list(f_in.read(2)))
if wVer == 14 or wVer == 15:
    print("ANSI PST")
    TYPE = "ANSI"
elif wVer == 23:
    print("UNOCODE PST")
    TYPE ="UNICODE"
else:
    print("Ben Merde alors : ni ANSI ni UNICODE")
wVerClient = f_in.read(2)
print("Version ", struct.unpack('<h', wVerClient)[0])
bPlatformCreate = f_in.read(1).hex()
bPlatformAccess = f_in.read(1).hex()
# print(bPlatformAccess, bPlatformCreate)
dwReserved1 = f_in.read(4).hex()
# print(dwReserved1)
dwReserved2 = f_in.read(4).hex()
# print(dwReserved2)
bidUnused = f_in.read(8).hex()
if TYPE == "ANSI":
    bidNextB = f_in.read(4)
    bidNextP = f_in.read(4)
elif TYPE == "UNICODE":
    bidNextB = 0
    bidNextP = f_in.read(8)
    print("Next page BID", bidNextP.hex(), " == ", struct.unpack('<Q', bidNextP)[0])
dwUnique = f_in.read(4)
# print("Fichier modifié ",struct.unpack('<I', dwUnique)[0]," fois")
rgnid = list()
for i in range (0,32):
    rgnid.append(struct.unpack('<I', f_in.read(4))[0])
# print(rgnid)
qwUnused = f_in.read(8)
root = f_in.read(72)
dwAlign = f_in.read(4)
rgbFM = f_in.read(128).hex()
rgbFP = f_in.read(128).hex()
bSentinel = f_in.read(1).hex()
if bSentinel == "80":
    print("Sentinelle = ", bSentinel)
else:
    print("Pas de Sentinelle = ", bSentinel)
bCryptMethod = f_in.read(1).hex()
if bCryptMethod == "00":
    print("NDB_CRYPT_NONE")
elif bCryptMethod == "01":
    print("NDB_CRYPT_PERMUTE")
elif bCryptMethod == "02":
    print("NDB_CRYPT_CYCLIC")
rgbReserved = f_in.read(2)
bidNextB = struct.unpack('<Q', f_in.read(8))[0]
print("Next Bid = ", bidNextB)
dwCRCFul = f_in.read(4)
ullReserved = f_in.read(8)
dwReserved = f_in.read(4)
rgbReserved2 = f_in.read(3)
bReserved = f_in.read(1)
rgbReserved3 = f_in.read(32)
print("************* ROOT      ********************")
# root 
# print(root)
dwReserved = root[0:4]
ibFileEof = root[4:12]
print("Taille du fichier = ", struct.unpack('<Q', ibFileEof)[0])
ibAMapLast = root[12:20]
print("absolute file offset to the last AMap page of the PST file ", struct.unpack('<Q', ibAMapLast)[0])
cbAMapFree = root[20:28]
print("total free space in all AMaps, combined ", struct.unpack('<Q', cbAMapFree)[0])
cbPMapFree = root[28:36]
print("total free space in all PMaps, combined ", struct.unpack('<Q', cbPMapFree)[0])
BREFNBT = root[36:52]
# BREFNBT = int(swap_order(BREFNBT.hex(),32,2),16)
BREFNBT_bid, BREFNBT_ib = struct.unpack('<QQ', BREFNBT)
print('BREFNBT_bid => ', BREFNBT_bid, 'BREFNBT_ib => ', BREFNBT_ib)
BREFBBT = root[52:68]
#BREFBBT = int(swap_order(BREFBBT.hex(),32,2),16)
BREFBBT_bid, BREFBBT_ib = struct.unpack('<QQ', BREFBBT)
print('BREFBBT_bid => ', BREFBBT_bid, 'BREFBBT_ib => ', BREFBBT_ib)
fAMapValid = root[68:69]
print(fAMapValid)
bReserved = root[69:70]
wReserved = root[70:72]
# Utilisation
print("************* BNT ROOT ****************")
f_in.seek(BREFNBT_ib)
page = f_in.read(512)
#print(page)
print("__PAGE BTPAGE___")
page_btpage = page[488:488+8]
#print(page_btpage)
page_btpage_cEnt = struct.unpack('<B', page_btpage[0:1])[0]
page_btpage_cEntMax = struct.unpack('<B', page_btpage[1:2])[0]
page_btpage_cbEnt = struct.unpack('<B', page_btpage[2:3])[0]
page_btpage_cLevel = struct.unpack('<B', page_btpage[3:4])[0]
page_btpage_dwPadding = struct.unpack('<I', page_btpage[4:8])[0]
print("cEnt = ", page_btpage_cEnt, " cEntMax = ",page_btpage_cEntMax, " cbEnt = ", page_btpage_cbEnt, " cLevel = ", page_btpage_cLevel)
print("dwPadding => ", page_btpage_dwPadding)
print("__PAGE TRAILER___")
page_trailer = page[512- 16:512]
page_trailer_ptype = page_trailer[0:1]
page_trailer_ptyperepeat = page_trailer[1:2]
print("type = ",page_trailer_ptype, " et repeat :", page_trailer_ptyperepeat)
page_trailer_wSig = page_trailer[2:4]
print("wSig = ", page_trailer_wSig)
page_trailer_dwCRC = page_trailer[4:8]
print("dwCRC = ", page_trailer_dwCRC)
page_trailer_bid = page_trailer[8:16]
print(page_trailer_bid.hex())
page_trailer_bid = struct.unpack('<Q', page_trailer_bid)[0]
print(page_trailer_bid)
# *************  BNT tree ************************
r_old = 0
r = 0
nbt = list()
NBT_TREE = dict()
for i in range(0,page_btpage_cEnt):
    r += page_btpage_cbEnt
    nbt.append(struct.unpack('<QQQ', page[r_old:r]))
    r_old = r
    

