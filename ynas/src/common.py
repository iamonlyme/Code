#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : common.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Sat 10 Jun 2017 08:18:07 PM CST
# Description : 
###############################################

import os
import sys
import subprocess
import logging
import logging.config

ROOT_PATH = os.path.abspath(os.path.realpath(os.path.dirname(__file__))) + "/.."
logging.config.fileConfig(ROOT_PATH + "/logger.conf")
logger = logging.getLogger("ippy")

class ComLib(object):
    ESUCCESS    = 0
    EFAILED     = -1
    EINVALID    = -2

    @staticmethod
    def comCheckCall(command):
        try:
            logger.debug(command)
            subprocess.check_call(command, \
                                stdout=open('/dev/null','w'), \
                                stderr=subprocess.STDOUT, \
                                shell=True)
        except subprocess.CalledProcessError:
            logger.exception("%s failed" %(command))
            return ComLib.EFAILED
        return ComLib.ESUCCESS

    @staticmethod
    def getCmdOutput(command):
        try:
            logger.debug(command)
            output = subprocess.check_output(command, stderr=open('/dev/null','w'), shell=True)
        except:
            logger.exception("%s failed" %(command))
            return ComLib.EFAILED, ""
        return ComLib.ESUCCESS, output