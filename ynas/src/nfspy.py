#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : nfspy.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Sun 14 May 2017 02:27:16 PM CST
# Description : ip routing
###############################################
import os
import sys
import platform
import logging
import logging.config

from common import ComLib

ROOT_PATH = os.path.abspath(os.path.realpath(os.path.dirname(__file__))) + "/.."
logging.config.fileConfig(ROOT_PATH + "/logger.conf")
logger = logging.getLogger("ippy")

class NfsPy(object):
	ESUCCESS	= 0
	EFAILED		= -1
	EINVALID	= -2
	ENOSUPPORT	= -3

	IPPY_RUNDIR	= "/run"

	def __init__(self):
		pass

	@staticmethod
	def cmdNfsSvc(action):
		"""
			do action for nfs service
			"start": start nfs
			"stop" : stop nfs
			"restart": restart nfs
		"""
		pf = platform.dist()[0]
		if pf == "centos":
			if action == "start":
				ret = ComLib.comCheckCall("systemctl start nfs-server.service")
			elif action == "stop":
				ret = ComLib.comCheckCall("systemctl stop nfs-server.service")
			elif action == "restart":
				ret = ComLib.comCheckCall("systemctl restart nfs-server.service")
			else:
				logger.error("Not support this action %s" %(pf))
				ret = NfsPy.ENOSUPPORT
		else:
			logger.error("Not support this platform %s" %(pf))
			ret = NfsPy.ENOSUPPORT

		return ret

	@staticmethod
	def cmdReloadConfig():
		"""
			do action for nfs service
			"start": start nfs
			"stop" : stop nfs
			"restart": restart nfs
		"""
		pf = platform.dist()[0]
		if pf == "centos":
			ret = ComLib.comCheckCall("exportfs -ra")
		else:
			logger.error("Not support this platform %s" %(pf))
			ret = NfsPy.ENOSUPPORT

		return ret


