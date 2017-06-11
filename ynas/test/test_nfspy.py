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
import sys
import unittest
import mock

ROOT_PATH = os.path.abspath(os.path.realpath(os.path.dirname(__file__))) + "/.."
sys.path.append(ROOT_PATH + "/src")

from common import ComLib
from ippy import IpLib

IFACE_EXIST1  = "eno33554984"
IFACE_EXIST2  = "eno16777736"
IFACE_NOT_EXIST  = "eno33333333"
IP_EXIST1 = "192.168.124.200/24"
IP_NEW_1 = "192.167.125.151/24"
IP_MASK_1 = "192.167.125.0/24"
IP_NEW_2 = "192.167.125.152/24"
IP_NEW_3 = "192.167.125.153/24"
IP_NEW_4 = "192.167.125.154/24"
IP_NEW_5 = "192.167.125.155/24"
IP_NOT_EXIST = "192.167.126.50/24"


class IpLibTestCase(unittest.TestCase):

    def setUp(self):
        # prepare environment
        self.ip = IpLib()

    def tearDown(self):
        # clear environment
        self.ip = None

    def test_checkIpv4Valid(self):  
        self.assertTrue(self.ip.checkIpv4Valid("192.169.34.24"))
        self.assertTrue(self.ip.checkIpv4Valid("192.169.34.255"))
        self.assertTrue(self.ip.checkIpv4Valid("0.169.34.24"))
        self.assertFalse(self.ip.checkIpv4Valid("192.169.34.24.24"))
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
        self.assertEqual(ComLib.comCheckCall("ip link set %s down" %IFACE_EXIST1), IpLib.ESUCCESS)       
        self.assertFalse(self.ip.checkIfaceStatus(IFACE_EXIST1))
        self.assertEqual(ComLib.comCheckCall("ip link set %s up" %IFACE_EXIST1), IpLib.ESUCCESS) 
        self.assertTrue(self.ip.checkIfaceStatus(IFACE_EXIST1))        
        self.assertFalse(self.ip.checkIfaceStatus(IFACE_NOT_EXIST))

    def test_bringUpIface(self):
        self.assertEqual(ComLib.comCheckCall("ip link set %s down" %IFACE_EXIST1), IpLib.ESUCCESS) 
        self.assertEqual(self.ip.bringUpIface(IFACE_EXIST1), IpLib.ESUCCESS)      
        self.assertEqual(self.ip.bringUpIface(IFACE_NOT_EXIST), IpLib.EFAILED)

    def test_checkIpExists(self):
        self.assertFalse(self.ip.checkIpExists("", IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, ""))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST2))
        self.assertFalse(self.ip.checkIpExists(IP_EXIST1, IFACE_NOT_EXIST))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NOT_EXIST, IFACE_EXIST1))

    def test_addIpToIface(self):
        self.assertEqual(self.ip.addIpToIface("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.addIpToIface("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, ""), IpLib.EINVALID)
        self.assertEqual(ComLib.comCheckCall("ip addr add %s dev %s" %(IP_NEW_1, IFACE_EXIST1)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("ip addr del %s dev %s" %(IP_NEW_1, IFACE_EXIST1)), IpLib.ESUCCESS)
        file_name = IpLib.IPPY_RUNDIR + "/ippy_iface_%s.flock" %(IFACE_EXIST1)
        self.assertEqual(ComLib.comCheckCall("touch %s" %(file_name)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.EFAILED)
        self.assertEqual(ComLib.comCheckCall("rm -rf %s" %(file_name)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_NOT_EXIST), IpLib.EFAILED)
        self.assertEqual(self.ip.addIpToIface(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("ip addr del %s dev %s" %(IP_NEW_1, IFACE_EXIST1)), IpLib.ESUCCESS)
        #How do test this function when comCheckCall failed

    def test_delIpFromIface(self):
        self.assertEqual(self.ip.delIpFromIface("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.delIpFromIface(IP_NEW_1, ""), IpLib.EINVALID)
        self.assertEqual(self.ip.delIpFromIface(IP_NOT_EXIST, IFACE_EXIST1), IpLib.ESUCCESS)
        # a test
        file_name = IpLib.IPPY_RUNDIR + "/ippy_iface_%s.flock" %(IFACE_EXIST1)
        self.assertEqual(ComLib.comCheckCall("touch %s" %(file_name)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delIpFromIface(IP_EXIST1, IFACE_EXIST1), IpLib.EFAILED)
        self.assertEqual(ComLib.comCheckCall("rm -rf %s" %(file_name)), IpLib.ESUCCESS)
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
        self.assertEqual(ComLib.comCheckCall("ip addr add %s dev %s" %(IP_NEW_1, IFACE_EXIST1)), IpLib.ESUCCESS)
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
        self.assertEqual(ComLib.comCheckCall("echo '%s' >>/etc/iproute2/rt_tables" %str_line), IpLib.ESUCCESS)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        #
        str_line1 = "%d %s%s" %(10, IpLib.TABLE_ID_PREFIX, IP_NEW_1)
        str_line2 = "%d %s%s" %(11, IpLib.TABLE_ID_PREFIX, IP_NEW_2)
        self.assertEqual(ComLib.comCheckCall("echo '%s' >>/etc/iproute2/rt_tables" %str_line1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("echo '%s' >>/etc/iproute2/rt_tables" %str_line2), IpLib.ESUCCESS)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_2), IpLib.EFAILED)

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
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.ESUCCESS)
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
            self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %ip_addr), IpLib.ESUCCESS)
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
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.eraseTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.ensureTableIdForIp(ip_addr), IpLib.ESUCCESS)
            self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %ip_addr), IpLib.ESUCCESS)
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.eraseTableIdForIp(ip_addr), IpLib.ESUCCESS)
            self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %ip_addr), IpLib.EFAILED)


    def test_delRoutingForIp(self):
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)

        # a test
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        table_id = IpLib.TABLE_ID_PREFIX + IP_NEW_1
        cmmd = "ip rule add from %s pref 10000 table %s" %(IP_NEW_1, table_id)
        self.assertEqual(ComLib.comCheckCall(cmmd), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        self.assertEqual(ComLib.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)
        # a test
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        table_id = IpLib.TABLE_ID_PREFIX + IP_NEW_1
        cmmd = "ip rule add from %s pref 10000 table %s" %(IP_NEW_1, table_id)
        self.assertEqual(ComLib.comCheckCall(cmmd), IpLib.ESUCCESS)
        cmmd = "ip route add %s dev %s table %s" %(IP_MASK_1, IFACE_EXIST1, table_id)
        self.assertEqual(ComLib.comCheckCall(cmmd), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        self.assertEqual(ComLib.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)

    def test_addRoutingForIp(self):
        self.assertEqual(self.ip.addRoutingForIp(IP_NEW_1, IFACE_NOT_EXIST), IpLib.EFAILED)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)
        #
        self.assertEqual(self.ip.addRoutingForIp(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.delRoutingForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(ComLib.comCheckCall("ip rule list | grep -Fq '%s'" %IP_NEW_1), IpLib.EFAILED)

    def test_updateArpCache(self):
        self.assertEqual(self.ip.updateArpCache("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.updateArpCache("192.168.124.1", ""), IpLib.EINVALID)
        self.assertEqual(self.ip.updateArpCache("192.168.124.1", IFACE_EXIST1), IpLib.EFAILED)
        self.assertEqual(self.ip.updateArpCache("192.168.124.3", IFACE_EXIST1), IpLib.EFAILED)
        self.assertEqual(self.ip.updateArpCache("192.168.124.1", IFACE_EXIST1, IP_EXIST1), IpLib.EFAILED)

    def test_getIfaceFromIp(self):
        self.assertEqual(self.ip.getIfaceFromIp(IP_NEW_1), (IpLib.EFAILED,""))
        self.assertEqual(self.ip.getIfaceFromIp(IP_EXIST1), (IpLib.ESUCCESS, IFACE_EXIST1))

        self.assertEqual(ComLib.comCheckCall("ip addr add %s dev %s label %s:t12" %(IP_NEW_1,IFACE_EXIST1,IFACE_EXIST1)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.getIfaceFromIp(IP_NEW_1), (IpLib.ESUCCESS, "%s:t12" %IFACE_EXIST1))
        self.assertEqual(ComLib.comCheckCall("ip addr del %s dev %s" %(IP_NEW_1, IFACE_EXIST1)), IpLib.ESUCCESS)

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

    def test_takePublicIP(self):
        self.assertEqual(self.ip.takePublicIP("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, ""), IpLib.EINVALID)
        self.assertEqual(self.ip.takePublicIP(IP_EXIST1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_NOT_EXIST), IpLib.EFAILED)
        #test
        for i in range(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH+1):
            ip_addr = "192.169.127.%d/24" %i
            self.assertEqual(self.ip.ensureTableIdForIp(ip_addr), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.EFAILED)
        self.assertEqual(self.ip.cleanUpTableIds(), IpLib.ESUCCESS)
        #
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.releasePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        

    def test_releasePublicIP(self):
        self.assertEqual(self.ip.releasePublicIP("", IFACE_EXIST1), IpLib.EINVALID)
        self.assertEqual(self.ip.releasePublicIP(IP_EXIST1, ""), IpLib.EINVALID)
        self.assertEqual(self.ip.releasePublicIP(IP_EXIST1, IFACE_NOT_EXIST), IpLib.ESUCCESS)
        # test
        self.assertEqual(ComLib.comCheckCall("ip addr add %s dev %s" %(IP_NEW_1, IFACE_EXIST1)), IpLib.ESUCCESS)
        self.assertEqual(self.ip.releasePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        # test
        self.assertEqual(self.ip.ensureTableIdForIp(IP_NEW_1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.releasePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(ComLib.comCheckCall("grep -Fq '%s' /etc/iproute2/rt_tables" %IP_NEW_1), IpLib.EFAILED)
        # test
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.releasePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))

    def test_updatePublicIps(self):
        ips = []
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        # test
        ips = []
        ips.append(IP_NEW_1)
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        # test : add one
        ips = []
        ips.append(IP_NEW_1)
        ips.append(IP_NEW_2)
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        # test : add more
        ips = []
        ips.append(IP_NEW_1)
        ips.append(IP_NEW_2)
        ips.append(IP_NEW_3)
        ips.append(IP_NEW_4)
        ips.append(IP_NEW_5)
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_4, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_5, IFACE_EXIST1))
        # test delete one
        ips = []
        ips.append(IP_NEW_1)
        ips.append(IP_NEW_2)
        ips.append(IP_NEW_3)
        ips.append(IP_NEW_4)
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_4, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_5, IFACE_EXIST1))
        # test delete more
        ips = []
        ips.append(IP_NEW_1)
        ips.append(IP_NEW_2)
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_4, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_5, IFACE_EXIST1))
        # test delete and add
        ips = []
        ips.append(IP_NEW_3)
        ips.append(IP_NEW_4)
        ips.append(IP_NEW_5)
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_4, IFACE_EXIST1))
        self.assertTrue(self.ip.checkIpExists(IP_NEW_5, IFACE_EXIST1))
        # test : clear all
        ips = []
        self.assertEqual(self.ip.updatePublicIps(ips, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_4, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_5, IFACE_EXIST1))

    def test_releaseAllPublicIps(self):
        # test
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertEqual(self.ip.releaseAllPublicIps(), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        # test
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_2, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_3, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.releaseAllPublicIps(), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        # test 
        self.assertEqual(self.ip.takePublicIP(IP_NEW_1, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_2, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_3, IFACE_EXIST1), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_4, IFACE_EXIST2), IpLib.ESUCCESS)
        self.assertEqual(self.ip.takePublicIP(IP_NEW_5, IFACE_EXIST2), IpLib.ESUCCESS)
        self.assertEqual(self.ip.releaseAllPublicIps(), IpLib.ESUCCESS)
        self.assertTrue(self.ip.checkIpExists(IP_EXIST1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_1, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_2, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_3, IFACE_EXIST1))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_4, IFACE_EXIST2))
        self.assertFalse(self.ip.checkIpExists(IP_NEW_5, IFACE_EXIST2))


    @mock.patch.object(IpLib, 'checkIfaceStatus')
    @mock.patch.object(IpLib, 'bringUpIface')
    @mock.patch.object(IpLib, 'checkIpExists')
    @mock.patch.object(IpLib, 'takePublicIP')
    def test_checkIpConn(self,
                         mock_takePublicIP,
                         mock_checkIpExists,
                         mock_bringUpIface,
                         mock_checkIfaceStatus
                         ):
        # test
        mock_checkIfaceStatus.return_value = False
        mock_bringUpIface.return_value = IpLib.EFAILED
        self.assertFalse(self.ip.checkIpConn(IP_EXIST1, IFACE_NOT_EXIST))
        # test
        mock_checkIfaceStatus.return_value = True
        mock_checkIpExists.return_value = True
        self.assertTrue(self.ip.checkIpConn(IP_EXIST1, IFACE_NOT_EXIST))
        # test
        mock_checkIfaceStatus.return_value = True
        mock_checkIpExists.return_value = False
        mock_takePublicIP.return_value = IpLib.EFAILED
        self.assertFalse(self.ip.checkIpConn(IP_EXIST1, IFACE_NOT_EXIST))
        # test
        mock_checkIfaceStatus.return_value = True
        mock_checkIpExists.return_value = False
        mock_takePublicIP.return_value = IpLib.ESUCCESS
        self.assertTrue(self.ip.checkIpConn(IP_EXIST1, IFACE_NOT_EXIST))


if __name__ =='__main__':#
    suite = unittest.TestSuite()

    suite.addTest(IpLibTestCase("test_checkIpv4Valid"))
    suite.addTest(IpLibTestCase("test_ipv4AddrToNet"))
    suite.addTest(IpLibTestCase("test_ipHasConfiguration"))
    suite.addTest(IpLibTestCase("test_checkIfaceStatus"))
    suite.addTest(IpLibTestCase("test_bringUpIface"))
    suite.addTest(IpLibTestCase("test_checkIpExists"))
    suite.addTest(IpLibTestCase("test_addIpToIface"))
    suite.addTest(IpLibTestCase("test_delIpFromIface"))
    suite.addTest(IpLibTestCase("test_cleanUpTableIds"))
    suite.addTest(IpLibTestCase("test_ensureTableIdForIp"))
    suite.addTest(IpLibTestCase("test_eraseTableIdForIp"))
    suite.addTest(IpLibTestCase("test_delRoutingForIp"))
    suite.addTest(IpLibTestCase("test_addRoutingForIp"))
    suite.addTest(IpLibTestCase("test_updateArpCache"))
    suite.addTest(IpLibTestCase("test_getIfaceFromIp"))
    suite.addTest(IpLibTestCase("test_getPublicIps"))
    suite.addTest(IpLibTestCase("test_takePublicIP"))
    suite.addTest(IpLibTestCase("test_releasePublicIP"))
    suite.addTest(IpLibTestCase("test_updatePublicIps"))
    suite.addTest(IpLibTestCase("test_releaseAllPublicIps"))
    suite.addTest(IpLibTestCase("test_checkIpConn"))

    #执行测试  
    runner = unittest.TextTestRunner()  
    runner.run(suite) 
    #unittest.main()
