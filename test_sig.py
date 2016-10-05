'''
Created on 5 oct. 2016

@author: Plouf
'''
import unittest
from sig import ComputeSig


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_sig0(self):
        self.assertEqual(ComputeSig(8644, 79791104), 41221)

    def test_sig1(self):
        self.assertEqual(ComputeSig(8708, 79787520), 20677)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
