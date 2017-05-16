#!/usr/bin/python
# -*- coding:utf-8 -*-
###############################################
# File Name   : ippy.py
# Author      : Youner Liu
# Mail        : lewiyon@126.com
# Created Time: Sun 14 May 2017 02:27:16 PM CST
# Description : ip routing
###############################################
import os
import stat
import re
import socket
import subprocess

class IpLib(object):
	ESUCCESS	= 0
	EFAILED		= -1
	EINVALID	= -2

	MAX_IPV4_ADDRESS = 0xffffffff
	TABLE_ID_PREFIX				= "ippy_"
	PER_IP_ROUTING_RULE_PREF	= 10000
	PER_IP_ROUTING_TABLE_ID_LOW	= 10
	PER_IP_ROUTING_TABLE_ID_HIGH	=250
	IPPY_ETCDIR	= "/run"

	def __init__(self):
		pass

	def comCheckCall(self, command):
		try:
			print(command)
			subprocess.check_call(command, shell=True)
		except:
			print("[info]%s failed" %(command))
			return IpLib.EFAILED
		return IpLib.ESUCCESS

	def comCheckOutput(self, command):
		try:
			print(command)
			output = subprocess.check_output(command, shell=True)
		except:
			print("[info]%s failed" %(command))
			return IpLib.EFAILED, ""
		return IpLib.ESUCCESS, output

	def checkIpv4Valid(self, ip):
		"""
			check ipv4 address valid
		"""
		if len(ip) != len(ip.replace(" ", "")):
			return False
		segs = ip.split(".")
		if len(segs) != 4:
			return False
		for seg in segs:
			try:
				i_seg = int(seg)
			except:
				return False
			if i_seg < 0 or i_seg > 255:
				return False

		return True

	def Ipv4AddrToNet(self,ip):
		"""
			This prints the config for an IP, which is either relevant entries
			from the config file or, if set to the magic link local value, some
			link local routing config for the IP.
			ip looks like "192.169.34.211/24"
		"""
		addr, maskbit = ip.split("/")
		segs = addr.split(".")
		addr_ul = 0
		for seg in segs:
			i_seg = int(seg)
			addr_ul = (addr_ul << 8) + i_seg

		mask = IpLib.MAX_IPV4_ADDRESS << (32 - int(maskbit))
		net_ul = addr_ul & mask
		net_addr = ""
		count = 0
		while count < 4:
			if not net_addr:
				net_addr = str((net_ul & 255))
			else:
				net_addr = str((net_ul & 255)) + "." + net_addr
			net_ul = net_ul >> 8
			count = count + 1

		return net_addr + "/" + maskbit

	def ipHasConfiguration(self, ip):
		try:
			addr, maskbit = ip.split("/")
			if not maskbit.isdigit():
				return False
		except:
			return False
		return True

	def getConfigForIP(self, ip):
		"""
			This prints the config for an IP, which is either relevant entries
			from the config file or, if set to the magic link local value, some
			link local routing config for the IP.
			ip looks like "192.169.34.211/24"
		"""
		addr, maskbit = ip.split("/")
		addrlist = addr.split(".")
		dest = ip
		if maskbit == "8":
			dest = addrlist[0] + ".0.0.0/8"
		elif maskbit == "16":
			dest = addrlist[0] + "." + addrlist[1] + ".0.0/16"
		elif maskbit == "24":
			dest = addrlist[0] + "." + addrlist[1] + "." + addrlist[2] + ".0/24"
		elif maskbit == "32":
			dest = addr + "/32"

		return addr, dest

	def checkIfaceStatus(self, iface):
		"""
		check iface status, False - Down; True - UP
		"""
		cmmd = "ip link show %s | grep 'state UP'" %(iface)
		ret = self.comCheckCall(cmmd)
		if ret != IpLib.ESUCCESS:
			return False
		else:
			return True

	def checkIpExists(self, ip, iface):
		"""
			whether ip is on iface;
			if yes return True, else return False
		"""
		cmmd = "ip addr list dev '%s' | grep -Fq 'inet %s '" %(iface, ip)
		ret = self.comCheckCall(cmmd)
		if ret != IpLib.ESUCCESS:
			return False
		else:
			return True

	def addIpToIface(self, ip, iface):
		"""
			add ip to iface
			ip looks like "192.169.34.128/24"
		"""
		if not ip or not self.ipHasConfiguration(ip):
			print("[Error]IP is invalid")
			return IpLib.EINVALID

		if self.checkIpExists(ip, iface):
			print("%s has been on dev %s" %(ip, iface))
			return IpLib.ESUCCESS

		lockfile = IpLib.IPPY_ETCDIR + "/ippy_iface_%s.flock" %(iface)
		try:
			fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
		except:
			print("[Error]race failed for %s" %(iface))
			return IpLib.EFAILED

		# Ensure interface is up
		cmmd = "ip link set %s up" %(iface)
		ret = self.comCheckCall(cmmd)
		if ret != IpLib.ESUCCESS:
			print("[Error]failed to bringup interface %s" %(iface))
		else:
			# add ip address to interface
			cmmd = "ip addr add %s brd + dev %s" %(ip, iface)
			ret = self.comCheckCall(cmmd)
			if ret != IpLib.ESUCCESS:
				print("[Error]Failed to add %s on dev %s" %(ip, iface))

		os.close(fd)
		os.unlink(lockfile)
		return ret

	def delIpFromIface(self, ip, iface):
		"""
			delete ip from iface
			ip looks like "192.169.34.128/24"
		"""
		if not self.checkIpExists(ip, iface):
			print("Could not find %s on dev %s" %(ip, iface))
			return IpLib.ESUCCESS

		lockfile = IpLib.IPPY_ETCDIR + "/ippy_iface_%s.flock" %(iface)
		try:
			fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_RDWR)
		except:
			print("[Error]race failed for %s" %(iface))
			return IpLib.EFAILED

		"""
		"ip addr del" will delete all secondary IPs if this is the
		primary.  To work around this _very_ annoying behaviour we
		have to keep a record of the secondaries and re-add them
		afterwards.  Yuck!
		"""
		secondaries=[]
		cmmd = "ip addr list dev '%s' primary | grep -Fq 'inet %s '" %(iface, ip)
		ret = self.comCheckCall(cmmd)
		if ret != IpLib.ESUCCESS:
			# not primary
			cmmd = "ip addr list dev '%s' secondary | grep 'inet '" %(iface)
			ret, output = self.comCheckOutput(cmmd)
			if ret != IpLib.ESUCCESS:
				print("[Error] failed to list secondary addr for %s" %(iface))
			elif not output:
				print("[Error] No secondary addr for %s" %(iface))
			else:			
				lines = output.split("\n")
				for line in lines:
					if not line:
						continue
					try:
						m = re.match("\s+(\S+)\s+(\S+)", line)
						if m.group(1) and m.group(2):
							inet = m.group(1)
							snd_ip = m.group(2)
						else :
							continue					
					except:
						continue
					if inet == "inet":
						secondaries.append(snd_ip)

		local_rc = 0
		cmmd = "ip addr del '%s' dev '%s'" %(ip, iface)
		ret = self.comCheckCall(cmmd)
		if ret != IpLib.ESUCCESS:
			print("[Error]Failed to del %s on dev %s" %(ip, iface))
			local_rc = 1

		for snd_ip in secondaries:
			if snd_ip == ip:
				continue
			cmmd = "ip addr list dev '%s' secondary | grep -Fq 'inet %s'" %(iface, snd_ip)
			ret = self.comCheckCall(cmmd)
			if ret == IpLib.ESUCCESS:
				print("Kept secondary %s on dev %s" %(snd_ip, iface))
			else:
				print("Re-adding secondary address %s to dev %s" %(snd_ip, iface))
				cmmd = "ip addr add %s brd + dev %s" %(snd_ip, iface)
				ret = self.comCheckCall(cmmd)
				if ret != IpLib.ESUCCESS:
					print("[Error]Failed to re-add address %s to dev %s" %(snd_ip, iface))
					local_rc = 1
			# end if

		os.close(fd)
		os.unlink(lockfile)
		if local_rc:
			ret = IpLib.EFAILED
		return ret

	def CleanUpTableIds(self, ip):
		"""
			Clean up all the table ids that we might own.
		"""
		file_name = "/etc/iproute2/rt_tables"
		if not os.path.isfile(file_name):
			print("%s not exist." %(file_name))
			return IpLib.ESUCCESS

		try:
			fp = open(file_name, "r+")
		except:
			print("[Error]open %s failed" %(file_name))
			return IpLib.EFAILED

		new_lines = []
		lines = fp.readlines()
		for line in lines :
			if line and line[0] != "#" :
				m = re.search(IpLib.TABLE_ID_PREFIX, line)
				if m:
					continue
			new_lines.append(line)

		fp.seek(0, 0)
		fp.truncate()
		fp.writelines(new_lines)
		fp.flush()
		fp.close()
		return IpLib.ESUCCESS

	def eraseTableIdForIp(self, ip):
		"""
			Clean up all the table ids that we might own.
		"""
		file_name = "/etc/iproute2/rt_tables"
		if not os.path.isfile(file_name):
			print("%s not exist." %(file_name))
			return IpLib.ESUCCESS

		try:
			fp = open(file_name, "r+")
		except:
			print("[Error]open %s failed" %(file_name))
			return IpLib.EFAILED

		keywords = IpLib.TABLE_ID_PREFIX + ip
		new_lines = []
		lines = fp.readlines()
		for line in lines :
			if line and line[0] != "#" :
				m = re.search(keywords, line)
				if m:
					continue
			new_lines.append(line)

		fp.seek(0, 0)
		fp.truncate()
		fp.writelines(new_lines)
		fp.flush()
		fp.close()
		return IpLib.ESUCCESS

	def ensureTableIdForIp(self, ip):
		"""
			Setup a table id to use for the given IP.  We don't need to know it,
			it just needs to exist in /etc/iproute2/rt_tables.  Fail if no free
			table id could be found in the configured range.
		"""
		route_dir = "/etc/iproute2"
		if not os.path.isdir(route_dir):
			os.mkdir(route_dir)

		file_name = route_dir + "/rt_tables"
		try:
			fp = open(file_name, "r+")
		except:
			print("[Error]open %s failed" %(file_name))
			return IpLib.EFAILED

		new_label = IpLib.TABLE_ID_PREFIX + ip
		id_array = []
		lines = fp.readlines()
		for line in lines :
			# blank line
			if not lines:
				continue
			# Skip comments
			if line[0] == "#":
				continue
			try:
				m = re.match("(\S+)\s+(\S+)", line)
				if m.group(1) and m.group(2):
					t_id = int(m.group(1))
					t_label = m.group(2)
				else :
					continue					
			except:
				continue

			# Found existing: done
			if t_label == new_label:
				print("%s has been in %s" %(new_label, file_name))
				fp.close()
				return IpLib.ESUCCESS
			if IpLib.PER_IP_ROUTING_TABLE_ID_LOW <= t_id and t_id <= IpLib.PER_IP_ROUTING_TABLE_ID_HIGH:
				id_array.append(t_id)

		new_id = IpLib.PER_IP_ROUTING_TABLE_ID_LOW
		while new_id <= IpLib.PER_IP_ROUTING_TABLE_ID_HIGH:
			if new_id not in id_array:
				break
			else:
				new_id = new_id + 1

		# If the new table id is legal then add it to the file and print it.
		if new_id <= IpLib.PER_IP_ROUTING_TABLE_ID_HIGH:
			new_line = "%d %s\n" %(new_id, new_label)
			fp.seek(0, 2) # file end
			fp.write(new_line)
			ret = IpLib.ESUCCESS
		else:
			print("[Error]out of table ids in range %d -%d " 
				%(IpLib.PER_IP_ROUTING_TABLE_ID_LOW, IpLib.PER_IP_ROUTING_TABLE_ID_HIGH))
			ret = IpLib.EFAILED

		fp.flush()
		fp.close()
		return ret

	def delRoutingForIp(self, ip):
		"""
			delete route for ip
		"""
		pref = IpLib.PER_IP_ROUTING_RULE_PREF
		table_id = IpLib.TABLE_ID_PREFIX + ip
		cmmd = "ip rule del from %s pref %s table %s" %(ip, pref, table_id)
		if self.comCheckCall(cmmd) != IpLib.ESUCCESS:
			print("[Error]failed to del rule for %s" %(ip))
			return IpLib.EFAILED

		# This should never usually fail, so don't redirect output.
		# However, it can fail when deleting a rogue IP, since there will
		# be no routes for that IP.  In this case it should only fail when
		# the rule deletion above has already failed because the table id
		# is invalid.  Therefore, go to a little bit of trouble to indent
		# the failure message so that it is associated with the above
		# warning message and doesn't look too nasty.
		# ip route flush table $_table_id 2>&1 | sed -e 's@^.@  &@'
		cmmd = "ip route flush table %s" %(table_id)
		if self.comCheckCall(cmmd) != IpLib.ESUCCESS:
			print("[Error]failed to flush rule for deleting %s" %(table_id))
			return IpLib.EFAILED

		if self.eraseTableIdForIp(ip) != IpLib.ESUCCESS:
			print("[Error]eraseTableIdForIp failed")
			return IpLib.EFAILED

		return IpLib.ESUCCESS

	def addRoutingForIp(self, ip, iface, gateway=None):

		if self.ensureTableIdForIp(ip) != IpLib.ESUCCESS:
			return IpLib.EFAILED

		#if self.delRoutingForIp(ip):
		#	print("[Error]failed delRoutingForIp for %s " %(ip))

		pref = IpLib.PER_IP_ROUTING_RULE_PREF
		table_id = IpLib.TABLE_ID_PREFIX + ip
		cmmd = "ip rule add from %s pref %s table %s" %(ip, pref, table_id)
		if self.comCheckCall(cmmd) != IpLib.ESUCCESS:
			print("[Error]failed to add rule for %s" %(ip))
			return IpLib.EFAILED

		net_wlan = self.Ipv4AddrToNet(ip)
		# Add routes to table for any lines matching the IP.
		if gateway:
			route = "%s +via %s dev %s table %s" %(net_wlan, gateway, iface, table_id)
		else:
			route = "%s dev %s table %s" %(net_wlan, iface, table_id)
		cmmd = "ip route add %s" %(route)
		if self.comCheckCall(cmmd) != IpLib.ESUCCESS:
			print("[Error]failed to add route: %s" %(route))
			return IpLib.EFAILED
		return IpLib.ESUCCESS

	def flushRulesAndRoutes(self):
		"""
			flush rules and routes
		"""
		cmmd = "ip rule show"
		ret, output = self.comCheckOutput(cmmd)
		if ret != IpLib.ESUCCESS:
			print("[Error] failed to show ip rules")
			return ret
		if not output:
			print("[Error] No ip rules")
			return ret
		lines = output.split("\n")
		for line in lines:
			if not line:
				continue
			try:
				m = re.match("(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
				if not m.group(1) or not m.group(2) \
					or not m.group(3) or not m.group(4) or not m.group(5):
					continue
			except:
				continue

			# Only remove rules that match our priority/preference.
			tb_id_str = "%s:" %(m.group(1))
			if tb_id_str != IpLib.PER_IP_ROUTING_RULE_PREF:
				continue

			ip = m.group(3)
			tb_name = m.group(3)
			print('Removing ip rule for public address %s for routing table %s' %(ip, tb_name))
			cmmd = "ip rule del from %s table %s pref %s" %(ip, tb_name, IpLib.PER_IP_ROUTING_RULE_PREF)
			if self.comCheckCall(cmmd) != IpLib.ESUCCESS:
				print("[Error]failed to delete rule for %s" %(ip))
				ret = IpLib.EFAILED
			cmmd = "ip route flush table %s" %(tb_name)
			if self.comCheckCall(cmmd) != IpLib.ESUCCESS:
				print("[Error]failed to flush table %s" %(tb_name))
				ret = IpLib.EFAILED

		return ret

	def updateArpCache(self, dest_ip, iface=None, src_ip=None):
		"""
			update arp cache
		"""
		if iface != None:
			cmmd = "arping -c 1 -I %s" %(iface)
		if src_ip != None:
			cmmd = cmmd + " -s %s" %(src_ip)
		cmd = cmmd + "  %s" %(dest_ip)

		count = 1
		ret = self.comCheckCall(cmmd)
		while (count < 2) and (ret != IpLib.EFAILED):
			count = count + 1
			ret = self.comCheckCall(cmmd)

		return ret

	def getIfaceFromIp(self, ip):
		"""
		"""
		iface = ""
		cmmd = "ip addr show| grep 'inet %s '" %(ip)
		ret, output = self.comCheckOutput(cmmd)
		if ret != IpLib.ESUCCESS or not output:
			print("Could not find %s in addr list" %(ip))
			return ret, iface
		output = output.replace("\n", "")
		words = output.split(" ")
		index = len(words) - 1
		while (not words[index]) and index >= 0:
			index = index - 1

		if index >= 0:
			iface = words[index]

		return ret, iface
			
	def getPublicIps(self):
		"""
			get public ips via this module
		"""
		ips = []
		file_name = "/etc/iproute2/rt_tables"
		try:
			fp = open(file_name, "r+")
		except:
			print("[Error]open %s failed" %(file_name))
			return ips

		keywords = IpLib.TABLE_ID_PREFIX
		new_lines = []
		lines = fp.readlines()
		for line in lines :
			if line and line[0] != "#" :
				m = re.search(keywords, line)
				if m:
					new_lines.append(line)
			continue
		fp.close()

		for line in new_lines:
			try:
				m = re.match("(\S+)\s+(\S+)", line)
				if m.group(1) and m.group(2):
					list = m.group(2).split("_")
					ips.append(list[1])
			except:
				continue

		return ips

	def releasePublicIP(self, ip, iface, gw=None):
		"""
			release publip address
		"""
		if not ip or not self.ipHasConfiguration(ip):
			print("[Error]IP is invalid")
			return IpLib.EINVALID

		if not self.checkIpExists(ip, iface):
			print("Could not find %s on dev %s" %(ip, iface))
			return IpLib.ESUCCESS

		# delete ip address
		ret = self.delIpFromIface(ip, iface)
		if ret != IpLib.ESUCCESS:
			print("[Error]delIpFromIface failed!")
		else:
			ret = self.delRoutingForIp(ip)
			if ret != IpLib.ESUCCESS:
				print("[Error]delRoutingForIp failed!")

		return ret

	def takePublicIP(self, ip, iface, gateway=None):
		"""
			update publip ip address
		"""
		if not ip or not self.ipHasConfiguration(ip):
			print("[Error]IP is invalid")
			return IpLib.EINVALID

		if self.checkIpExists(ip, iface):
			print("%s has been on dev %s" %(ip, iface))
			return IpLib.ESUCCESS

		# add ip address
		ret = self.addIpToIface(ip, iface)
		if ret != IpLib.ESUCCESS:
			print("[Error]addIpToIface failed!")
		else:
			ret = self.addRoutingForIp(ip, iface, gateway)
			if ret != IpLib.ESUCCESS:
				print("[Error]addRoutingForIp failed!")

		return ret

	def releaseAllPublicIps(self):
		"""
			release all public addresses via ippy
		"""
		last_ret = IpLib.ESUCCESS
		ips = self.getPublicIps()
		if not ips:
			print("No ips here")
			return last_ret
		
		for ip in ips:
			ret, iface = self.getIfaceFromIp(ip)
			if ret != IpLib.ESUCCESS:
				last_ret = ret
			elif self.releasePublicIP(ip, iface) != IpLib.ESUCCESS:
				print("[Error]releasePublicIP %s failed" %(ip))
				ret = IpLib.EFAILED
			else:
				continue

		return last_ret

	def checkPublicIpConn(self, ip, iface):
		"""
			check publip address status
		"""
		if self.checkIfaceStatus(iface) and self.checkIpExists(ip, iface):
			return True
		else:
			return False

