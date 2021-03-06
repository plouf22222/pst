# -*- coding: utf-8 -*-
'''
Created on 28 sept. 2016

@author: Plouf
'''


def ComputeSig(ib, bid):
    ib ^= bid
    return(((ib >> 16) ^ (ib & 0xFFFF)))


def test_ComputeSig():
    assert ComputeSig(8644, 79791104) == 41221


def test_ComputeSig1():
    assert ComputeSig(8708, 79787520) == 20677


if __name__ == "__main__":
    print("Function ComputeSig (DWORD ib, DWORD bid)")
    print("return a WORD signature")
    print("for ComputeSig(8644, 79791104) result is : ", ComputeSig(8644, 79791104))
