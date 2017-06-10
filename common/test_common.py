#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : test.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Thu 01 Jun 2017 02:34:35 PM CST
# Description : 
###############################################

import unittest
#from unittest.mock import MagicMock,patch
import mock

from common import ComLib


class ComLibTestCase(unittest.TestCase):

    def setUp(self):
        # prepare environment
        pass

    def tearDown(self):
        # clear environment
        pass

    def test_comCheckCall(self):
        suc_cmd = "ls /proc/meminfo"
        err_cmd = "ls /proc/meminfo_err"
        self.assertEqual(ComLib.comCheckCall(suc_cmd), ComLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall(err_cmd), ComLib.EFAILED)

    def test_getCmdOutput(self):
        suc_cmd = "ls /proc/meminfo"
        err_cmd = "ls /proc/meminfo_err"
        self.assertEqual(ComLib.getCmdOutput(err_cmd), (ComLib.EFAILED,""))
        self.assertEqual(ComLib.getCmdOutput(suc_cmd), (ComLib.ESUCCESS,"/proc/meminfo\n"))

if __name__ =='__main__':#
    suite = unittest.TestSuite()

    suite.addTest(ComLibTestCase("test_comCheckCall"))
    suite.addTest(ComLibTestCase("test_getCmdOutput"))
    #执行测试  
    runner = unittest.TextTestRunner()  
    runner.run(suite) 
    #unittest.main()
