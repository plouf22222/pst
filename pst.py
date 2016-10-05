# -*- coding: utf-8 -*-
'''
Created on 7 juil. 2016

@author: Plouf
'''

import struct
import permute


def swap_order(d, wsz=4, gsz=2):
    return "".join(["".join([m[i:i + gsz]
                            for i in range(wsz - gsz, -gsz, -gsz)])
                    for m in [d[i:i + wsz] for i in range(0, len(d), wsz)]])


def swap_order16(d):
    return "".join(d[i:i + 2] for i in range(len(d) - 2, -1, -2))


def lire_page(f_in, a_lire, TREE, tree_type):
    retour = list()
    while len(a_lire) != 0:
        numero, position = a_lire.pop()
        f_in.seek(position)
        page = f_in.read(512)
        btpage = page[488:488 + 8]
        cEnt, cEntMax, cbEnt, cLevel, dwPadding = struct.unpack('<BBBBI', btpage)
        trailerpage = page[512 - 16:512]
        ptype, ptyper, wSig, dwCRC, bid = struct.unpack('<BBHIQ', trailerpage)
        if numero == bid:
            pass
            #  print("COOL ça marche : ",numéro, " == ", bid, "|| ", cEnt)
        else:
            print("BUG ! les pages ne sont pas identiques")
        if cLevel == 0:
            #  print("NBT ici !", cbEnt)
            r_old = 0
            r = 0
            for i in range(0, cEnt):
                r += cbEnt
                if tree_type == "NBT":
                    nid, zero, biddata, bidsub, nidparent, dwpad = (struct.unpack('<IIQQII', page[r_old:r]))
                    if nid in TREE:
                        print("BUG je pensais que le NID est unique ....")
                    else:
                        TREE[nid] = (biddata, bidsub, nidparent)
                elif tree_type == "BBT":
                    # bref = page[r_old:r_old + 16]
                    bref_bid, bref_ib, cb, cRef, dwPadding = struct.unpack('<QQHHI', page[r_old:r])
                    if bref_bid in TREE:
                        print("Bug je pensais que le Bref était unique .....")
                    else:
                        TREE[bref_bid] = (bref_ib, cb, cRef)
                r_old = r
        else:
            # print("Level ", cLevel, " .... reste à lire")
            r_old = 0
            r = 0
            for i in range(0, cEnt):
                r += cbEnt
                nbt = (struct.unpack('<QQQ', page[r_old:r]))
                # check if we are in the NBT tree
                #  print("Key=",nbt[i][0]," Bid=",nbt[i][1]," Ib=",nbt[i][2])
                r_old = r
                retour.append((nbt[1], nbt[2]))
    return retour


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
    TYPE = "UNICODE"
else:
    print("Ben Merde alors : ni ANSI ni UNICODE")
    exit()
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
#  print("Fichier modifié ",struct.unpack('<I', dwUnique)[0]," fois")
rgnid = list()
for i in range(0, 32):
    rgnid.append(struct.unpack('<I', f_in.read(4))[0])
print(rgnid)
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
# BREFBBT = int(swap_order(BREFBBT.hex(),32,2),16)
BREFBBT_bid, BREFBBT_ib = struct.unpack('<QQ', BREFBBT)
print('BREFBBT_bid => ', BREFBBT_bid, 'BREFBBT_ib => ', BREFBBT_ib)
fAMapValid = root[68:69]
print(fAMapValid)
bReserved = root[69:70]
wReserved = root[70:72]
# Utilisation
print("************* BNT ROOT ****************")
NBTREE = dict()
a_lire = list()
a_lire.append((BREFNBT_bid, BREFNBT_ib))
while len(a_lire) != 0:
    a_lire = lire_page(f_in, a_lire, NBTREE, "NBT")
# for key in sorted(NBTREE):
#    print(key, "==>",NBTREE[key])
print("*********** BNT TREE chargé ************")
print(len(NBTREE), " Enregistrements")
print("************* BBT ROOT ****************")
BBTREE = dict()
a_lire = list()
a_lire.append((BREFBBT_bid, BREFBBT_ib))
while len(a_lire) != 0:
    a_lire = lire_page(f_in, a_lire, BBTREE, "BBT")
print("*********** BBT TREE chargé ************")
print(len(BBTREE), " Enregistrements")
# for key in sorted(BBTREE):
#    print(key, "==>",BBTREE[key])
# for key in sorted(NBTREE):
#    a = '{:032b}'.format(key)
#    print((int(a[0:5])),' - ', a[5:])
# Pour l'instant pas de gestion de l'article BREF = car il n'y a pas de type différents
'''
for key in sorted(NBTREE):
    print("pour le NID = ", key, "=>", NBTREE[key])
    bid = NBTREE[key][0]
    if bid in BBTREE:
        print("touvé ", BBTREE[bid])
'''
print("pour le block au 21440 34 byte de data")
f_in.seek(21440)
test = permute(f_in.read(64), True)

print(test[0:34])
a, b, c, d = struct.unpack("<HHLQ", test[48:])
print(a, b, c, d)
hnhdr = test[:12]
a, b, c, d, e = struct.unpack("<HBBII", hnhdr)
print(a, b, c, d, e)

print("pour le block bid 70792 au 72641728 de 2756 data")
depart = 2756 + 16
for i in range(0, 64):
    if (depart + i) % 64 == 0:
        print("padding = ", i, " block = ", depart + i, " bytes.")
        break
f_in.seek(72641728)
test = permute(f_in.read(2816), True)
a, b, c, d = struct.unpack("<HHLQ", test[2816 - 16:])
print(a, b, c, d)
hnhdr = test[:12]
a, b, c, d, e = struct.unpack("<HBBII", hnhdr)
print(a, b, c, d, e)
# pour le NID =  2101284 => (14684, 14682, 32898)
# touvé  (10748608, 3444, 2)
print("pour le block bid 14684 au 10748608 de 3444 data")
depart = 3444 + 16
for i in range(0, 64):
    if (depart + i) % 64 == 0:
        print("padding = ", i, " block = ", depart + i, " bytes.")
        break
f_in.seek(10748608)
test = permute(f_in.read(depart + i), True)
a, b, c, d = struct.unpack("<HHLQ", test[(depart + i) - 16:])
print(a, b, c, d)
hnhdr = test[:12]
a, b, c, d, e = struct.unpack("<HBBII", hnhdr)
print(a, b, c, d, e)
