#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : test.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Thu 01 Jun 2017 02:34:35 PM CST
# Description : 
###############################################
import os
import unittest
import subprocess

from ippy import IpLib

IFACE_EXIST1  = "eno33554984"
IFACE_EXIST2  = "eno16777736"
IFACE_NOT_EXIST  = "eno33333333"
IP_EXIST1 = "192.168.124.51/24"
IP_NEW_1 = "192.167.125.151/24"
IP_MASK_1 = "192.167.125.0/24"
IP_NEW_2 = "192.167.125.152/24"
IP_NOT_EXIST = "192.167.126.50/24"

def setReturn(ret, data=None):
    if data == None:
        return ret
    return ret, data

def retSuccess(data=None):
    if data == None:
        return IpLib.ESUCCESS
    return IpLib.ESUCCESS, data

class IpLibTestCase(unittest.TestCase):
    def setUp(self):
        # prepare environment
        self.ip = IpLib()

    def tearDown(self):
        # clear environment
        self.ip = None

    def test_comCheckCall(self):
        suc_cmd = "ip addr | grep %s" %IFACE_EXIST1
        err_cmd = "ip addr | grep %s" %IFACE_NOT_EXIST
        self.assertEqual(self.ip.comCheckCall(suc_cmd), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall(err_cmd), IpLib.EFAILED)

    def test_getCheckOutput(self):
        suc_cmd = "ls /proc/meminfo"
        err_cmd = "ls /proc/meminfo_err"
        self.assertEqual(self.ip.getCheckOutput(err_cmd), (IpLib.EFAILED,""))
        self.assertEqual(self.ip.getCheckOutput(suc_cmd), (IpLib.ESUCCESS,"/proc/meminfo\n"))

    def test_checkIpv4Valid(self):  
        self.assertTrue(self.ip.checkIpv4Valid("192.169.34.24"))
        self.assertTrue(self.ip.checkIpv4Valid("192.169.34.255"))
        self.assertTrue(self.ip.checkIpv4Valid("0.169.34.24"))
        self.assertFalse(self.ip.checkIpv4Valid("192.169.34.24/24"))
        self.assertFalse(self.ip.checkIpv4Valid(" 192.169.34.24"))
        self.assertFalse(self.ip.checkIpv4Valid("192.169.3 4.24"))
        self.assertFalse(self.ip.checkIpv4Valid("192.169.34.24 "))
        self.assertFalse(self.ip.checkIpv4Valid("-1.169.34.24"))

    def test_ipv4AddrToNet(self):
        self.assertEqual(self.ip.ipv4AddrToNet("192.169.34.3"), "192.169.34.3/32")
        self.assertEqual(self.ip.ipv4AddrToNet("192.169.34.3/24"), "192.169.34.0/24")
        self.assertEqual(self.ip.ipv4AddrToNet("192.169.34.3/16"), "192.169.0.0/16")
        self.assertEqual(self.ip.ipv4AddrToNet("192.169.34.3/8"), "192.0.0.0/8")
        self.assertEqual(self.ip.ipv4AddrToNet("192.169.34.3/0"), "0.0.0.0/0")

    def test_ipHasConfiguration(self):
        self.assertTrue(self.ip.ipHasConfiguration("192.169.34.3/32"))
        self.assertFalse(self.ip.ipHasConfiguration("192.169.34.3"))
        self.assertFalse(self.ip.ipHasConfiguration("192.169.34.3/16/24"))
        self.assertFalse(self.ip.ipHasConfiguration("192.169.34.3/a"))

    def test_checkIfaceStatus(self):
        subprocess.check_call("ifconfig %s down" %IFACE_EXIST1, shell=True)        
        self.assertFalse(self.ip.checkIfaceStatus(IFACE_EXIST1))
        subprocess.check_call("ifconfig %s up" %IFACE_EXIST1, shell=True)         
        self.assertTrue(self.ip.checkIfaceStatus(IFACE_EXIST1))        
        self.assertFalse(self.ip.checkIfaceStatus(IFACE_NOT_EXIST))

    def test_bringUpIface(self):
        subprocess.check_call("ifconfig %s down" %IFACE_EXIST1, shell=True)        
        self.assertEqual(self.ip.bringUpIface(IFACE_EXIST1), IpLib.ESUCCESS)
        subprocess.check_call("ifconfig %s up" %IFACE_EXIST1, shell=True)         
        self.assertEqual(self.ip.bringUpIface(IFACE_EXIST1), IpLib.ESUCCESS)        
        self.assertEqual(self.ip.bringUpIface(IFACE_NOT_EXIST), IpLib.EFAILED)

    def test_checkIpExists(self):
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST2))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, IFACE_NOT_EXIST))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, ""))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NOT_EXIST, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists("", IFACE_EXIST1))

    def test_addIpToIface(self):
        self.assertEqual(self.ip.addIpToIface("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, ""), IpLib.EINVALID)
        subprocess.check_call("ifconfig %s:t12 %s up" %(IFACE_EXIST1, IP_NEW_1), shell=True)   
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        subprocess.check_call("ifconfig %s:t12 down" %(IFACE_EXIST1), shell=True)
        file_name = IpLib.IPPY_RUNDIR + "/ippy_iface_%s.flock" %(IFACE_EXIST1)
        subprocess.check_call("touch %s" %(file_name), shell=True)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.EFAILED)
        subprocess.check_call("rm -rf %s" %(file_name), shell=True)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_NOT_EXIST), IpLib.EFAILED)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        subprocess.check_call("ip addr del %s dev %s" %(IP_NEW_1, IFACE_EXIST1), shell=True)
        #How do test this function when comCheckCall failed

    def test_delIpFromIface(self):
        self.assertEqual(self.ip.delIpFromIface("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_1, ""), IpLib.EINVALID)
        self.assertEqual(self.ip.delIpFromIface(IP_NOT_EXIST, IFACE_EXIST1), IpLib.ESUCCESS)
        # a test
        file_name = IpLib.IPPY_RUNDIR + "/ippy_iface_%s.flock" %(IFACE_EXIST1)
        subprocess.check_call("touch %s" %(file_name), shell=True)
        self.assertEqual(self.ip.delIpFromIface(IP_EXIST1, IFACE_EXIST1), IpLib.EFAILED)
        subprocess.check_call("rm -rf %s" %(file_name), shell=True)
        # a test:secondary
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_2, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_2, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        # a test
        cmd = "ifconfig %s:t12 %s up" %(IFACE_EXIST1, IP_NEW_1)
        self.assertEqual(self.ip.comCheckCall(cmd), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        # a test
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_2, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.delIpFromIface(IP_EXIST1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_2, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertEqual(self.ip.addIpToIface(IP_EXIST1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))

    def test_cleanUpTableIds(self):
        file_name = "/etc/iproute2/rt_tables"
        tmp_name = "/etc/iproute2/rt_tables.bak"
        #
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        #
        os.rename(file_name, tmp_name)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        os.rename(tmp_name, file_name)
        #
        str_line = "%d %s%s" %(10, IpLib.TABLE_ID_PREFIX, IP_NEW_1)
        self.assertEqual(self.ip.comCheckCall("echo '%s' >>/etc/iproute2/rt_tables" %str_line), IpLib.ESUCCESS)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        #
        str_line1 = "%d %s%s" %(10, IpLib.TABLE_ID_PREFIX, IP_NEW_1)
        str_line2 = "%d %s%s" %(11, IpLib.TABLE_ID_PREFIX, IP_NEW_2)
        self.assertEqual(self.ip.comCheckCall("echo '%s' >>/etc/iproute2/rt_tables" %str_line1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("echo '%s' >>/etc/iproute2/rt_tables" %str_line2), IpLib.ESUCCESS)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_2), IpLib.EFAILED)

    def test_ensureTableIdForIp(self):
        file_name = "/etc/iproute2/rt_tables"
        tmp_name = "/etc/iproute2/rt_tables.bak"
        self.assertEqual(self.ip.ensureTableIdForIp(""), IpLib.EINVALID)
        #
        os.rename(file_name, tmp_name)
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.EFAILED)
        os.rename(tmp_name, file_name)
        #
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        #
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        #
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.ensureTableIdForIp(ip_addr), IpLib.ESUCCESS)
        ip_addr = "192.169.128.251/24"
        self.assertEqual(self.ip.ensureTableIdForIp(ip_addr), IpLib.EFAILED)
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %ip_addr), IpLib.ESUCCESS)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)

    def test_eraseTableIdForIp(self):
        file_name = "/etc/iproute2/rt_tables"
        tmp_name = "/etc/iproute2/rt_tables.bak"
        self.assertEqual(self.ip.eraseTableIdForIp(""), IpLib.EINVALID)
        #
        os.rename(file_name, tmp_name)
        self.assertEqual(self.ip.eraseTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        os.rename(tmp_name, file_name)
        #
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        #
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.eraseTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.ensureTableIdForIp(ip_addr), IpLib.ESUCCESS)
            self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %ip_addr), IpLib.ESUCCESS)
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.eraseTableIdForIp(ip_addr), IpLib.ESUCCESS)
            self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %ip_addr), IpLib.EFAILED)


    def test_delRoutingForIp(self):
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)

        # a test
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        table_id = IpLib.TABLE_ID_PREFIX + IP_NEW_1
        cmmd = "ip rule add from %s pref 10000 table %s" %(IP_NEW_1, table_id)
        self.assertEqual(self.ip.comCheckCall(cmmd), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        self.assertEqual(self.ip.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)
        # a test
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        table_id = IpLib.TABLE_ID_PREFIX + IP_NEW_1
        cmmd = "ip rule add from %s pref 10000 table %s" %(IP_NEW_1, table_id)
        self.assertEqual(self.ip.comCheckCall(cmmd), IpLib.ESUCCESS)
        cmmd = "ip route add %s dev %s table %s" %(IP_MASK_1, IFACE_EXIST1, table_id)
        self.assertEqual(self.ip.comCheckCall(cmmd), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        self.assertEqual(self.ip.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)

    def test_addRoutingForIp(self):
        self.assertEqual(self.ip.addRoutingForIp(IP_NEW_1, IFACE_NOT_EXIST), IpLib.EFAILED)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)
        #
        self.assertEqual(self.ip.addRoutingForIp(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)

    def test_getIfaceFromIp(self):
        self.assertEqual(self.ip.getIfaceFromIp(IP_NEW_1), (IpLib.EFAILED,""))
        self.assertEqual(self.ip.getIfaceFromIp(IP_EXIST1), (IpLib.ESUCCESS, IFACE_EXIST1))

        self.assertEqual(self.ip.comCheckCall("ifconfig %s:t12 %s up" %(IFACE_EXIST1, IP_NEW_1)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.getIfaceFromIp(IP_NEW_1), (IpLib.ESUCCESS, "%s:t12" %IFACE_EXIST1))
        self.assertEqual(self.ip.comCheckCall("ifconfig %s:t12 down" %(IFACE_EXIST1)), IpLib.ESUCCESS)

    def test_getPublicIps(self):
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        self.assertEqual(self.ip.getPublicIps(), [])

        # test
        arr = []
        arr.append(IP_NEW_1)
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.getPublicIps(), arr)
        # test
        arr.append(IP_NEW_2)
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_2), IpLib.ESUCCESS)
        self.assertEqual(self.ip.getPublicIps(), arr)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)

if __name__ =='__main__':#
    suite = unittest.TestSuite()
    suite.addTest(IpLibTestCase("test_comCheckCall"))
    suite.addTest(IpLibTestCase("test_getCheckOutput"))
    suite.addTest(IpLibTestCase("test_checkIpv4Valid"))
    suite.addTest(IpLibTestCase("test_ipv4AddrToNet"))
    suite.addTest(IpLibTestCase("test_ipHasConfiguration"))
    suite.addTest(IpLibTestCase("test_checkIfaceStatus"))
    suite.addTest(IpLibTestCase("test_bringUpIface"))
    suite.addTest(IpLibTestCase("test_checkIpExists"))
    suite.addTest(IpLibTestCase("test_addIpToIface"))
    suite.addTest(IpLibTestCase("test_delIpFromIface"))
    suite.addTest(IpLibTestCase("test_cleanUpTableIds"))
    #suite.addTest(IpLibTestCase("test_ensureTableIdForIp"))
    #suite.addTest(IpLibTestCase("test_eraseTableIdForIp"))
    suite.addTest(IpLibTestCase("test_delRoutingForIp"))
    suite.addTest(IpLibTestCase("test_addRoutingForIp"))
    suite.addTest(IpLibTestCase("test_getIfaceFromIp"))
    suite.addTest(IpLibTestCase("test_getPublicIps"))

    #执行测试  
    runner = unittest.TextTestRunner()  
    runner.run(suite) 
