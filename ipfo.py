# -*- coding: utf-8 -*-
import sys
#reload(sys)  
#sys.setdefaultencoding('utf-8')
import requests.packages.urllib3
from json import dumps, loads
import requests
import os
import optparse
import re
from colorama import Fore, Back, Style
import string
import itertools
from optparse import OptionGroup
from kr import kre
import ipaddress

Tversion = 'VERSION 0.1'
kc = kre()



#################################

def keyF(ftype,key):
	if (ftype == 'add'):
		if (key):
			kc.kadd(key.lower())
		else:
			print (Fore.RED+'[!] For this API-KEY Function, You should provide API-KEY as an input argument'+Style.RESET_ALL)
	elif (ftype == 'del'):
		if (key):
			kc.kdel(key.lower())
		else:
			print (Fore.RED+'[!] For this API-KEY Function, You should provide API-KEY as an input argument'+Style.RESET_ALL)
	elif (ftype == 'help'):
		kc.help_menu()
	elif (ftype == 'list'):
		kc.klist()
	else:
		print (Fore.RED+'[!] There is something WRONG with the data that you entered'+Style.RESET_ALL)
		sys.exit()


#################################


def gatherMUL(mulips):
	iparray = []
	for ip in mulips.split(','):
		iparray.append(ip)
	iplist = list(set(iparray))
	iplist.remove('')
	iplist = [item for item in iplist if ' ' not in item]
	if (kc.ckfile()):
		SumorFull = str(raw_input(Fore.YELLOW+'''\n[?!] Here you are going to choose that you want full report or just a short summery of that.
WARNING: THE FULL REPORT IS WORKING IF YOU ARE USING PAID API KEY VERSION.
IF YOUR API KEY IS NOT PAID VERSION, DO NOT USE FULL REPORT.
IT WILL NOT GONNA WORK AND WILL CRASH.
Use 'f' for full report and 's' for summery. '''+Style.RESET_ALL))
		print ('\n')
		if (len(kc.tkeys) == 1):
			for ipi in range(len(iplist)):
				maipgather(iplist[ipi],kc.tkeys[0],SumorFull)
		else:
			apikey = kc.chokey()
			for ipi in range(len(iplist)):
				maipgather(iplist[ipi],apikey,SumorFull)
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()



#################################

def gatherC(cIdR):
	netip = ipaddress.ip_network(cIdR.decode(sys.stdin.encoding or 'utf-8'))
	if (kc.ckfile()):
		SumorFull = str(raw_input(Fore.YELLOW+'''\n[?!] Here you are going to choose that you want full report or just a short summery of that.
WARNING: THE FULL REPORT IS WORKING IF YOU ARE USING PAID API KEY VERSION.
IF YOUR API KEY IS NOT PAID VERSION, DO NOT USE FULL REPORT.
IT WILL NOT GONNA WORK AND WILL CRASH.
Use 'f' for full report and 's' for summery. '''+Style.RESET_ALL))
		print ('\n')
		if (len(kc.tkeys) == 1):
			for seip in netip:
				maipgather(str(seip),kc.tkeys[0],SumorFull)
		else:
			apikey = kc.chokey()
			for seip in netip:
				maipgather(str(seip),apikey,SumorFull)
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()
	sys.exit()



#################################

def gatherSIP(sigip):
	if (kc.ckfile()):
		SumorFull = str(raw_input(Fore.YELLOW+'''\n[?!] Here you are going to choose that you want full report or just a short summery of that.
WARNING: THE FULL REPORT IS WORKING IF YOU ARE USING PAID API KEY VERSION.
IF YOUR API KEY IS NOT PAID VERSION, DO NOT USE FULL REPORT.
IT WILL NOT GONNA WORK AND WILL CRASH.
Use 'f' for full report and 's' for summery. '''+Style.RESET_ALL))
		print ('\n')
		if (len(kc.tkeys) == 1):
			maipgather(sigip,kc.tkeys[0],SumorFull)
		else:
			apikey = kc.chokey()
			maipgather(sigip,apikey,SumorFull)
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()


#################################

def gatherASN(Sasn):
	if (kc.ckfile()):
		SumorFull = str(raw_input(Fore.YELLOW+'''\n[?!] Here you are going to choose that you want full report or just a short summery of that.
WARNING: AS MENTIONED AT FIRST, GATHERING INFO USING ASN OPTIONS
IS AVAILABLE ONLY IF YOU ARE USING PAID PLANS.
IF NOT, PLEASE DO NOT USE ASN OPTIONS.
IT WILL NOT GONNA WORK AND WILL CRASH.
Use 'f' for full report and 's' for summery. '''+Style.RESET_ALL))
		print ('\n')
		if (len(kc.tkeys) == 1):
			masngather(sigip,kc.tkeys[0],SumorFull)
		else:
			apikey = kc.chokey()
			masngather(sigip,apikey,SumorFull)
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()


#################################

def gatherMULASN(asnlst):
	asnarray = []
	for ans in asnlst.split(','):
		asnarray.append(ans)
	asnlist = list(set(asnarray))
	asnlist.remove('')
	asnlist = [item for item in asnlist if ' ' not in item]
	if (kc.ckfile()):
		SumorFull = str(raw_input(Fore.YELLOW+'''\n[?!] Here you are going to choose that you want full report or just a short summery of that.
WARNING: AS MENTIONED AT FIRST, GATHERING INFO USING ASN OPTIONS
IS AVAILABLE ONLY IF YOU ARE USING PAID PLANS.
IF NOT, PLEASE DO NOT USE ASN OPTIONS.
IT WILL NOT GONNA WORK AND WILL CRASH.
Use 'f' for full report and 's' for summery. '''+Style.RESET_ALL))
		print ('\n')
		if (len(kc.tkeys) == 1):
			for nsa in range(len(asnlist)):
				masngather(asnlist[nsa],kc.tkeys[0],SumorFull)
		else:
			apikey = kc.chokey()
			for nsa in range(len(asnlist)):
				masngather(asnlist[nsa],apikey,SumorFull)
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()



#################################

def gatherR(iprnag):
	rang_part = []
	ip_part = []
	for part in iprnag.split('-'):
		rang_part.append(part)
	last_num = int(rang_part[1])
	for lsc in rang_part[0].split('.'):
		ip_part.append(lsc)
	start_num = int(ip_part[3])
	ranges = last_num - start_num + 1
	###
	if (kc.ckfile()):
		SumorFull = str(raw_input(Fore.YELLOW+'''\n[?!] Here you are going to choose that you want full report or just a short summery of that.
WARNING: THE FULL REPORT IS WORKING IF YOU ARE USING PAID API KEY VERSION.
IF YOUR API KEY IS NOT PAID VERSION, DO NOT USE FULL REPORT.
IT WILL NOT GONNA WORK AND WILL CRASH.
Use 'f' for full report and 's' for summery. '''+Style.RESET_ALL))
		print ('\n')
		if (len(kc.tkeys) == 1):
			for ipi in range(ranges):
				Last_IPart = int(ip_part[3]) + ipi
				TIp = ip_part[0]+'.'+ip_part[1]+'.'+ip_part[2]+'.'+str(Last_IPart)
				maipgather(TIp,kc.tkeys[0],SumorFull)
		else:
			apikey = kc.chokey()
			for ipi in range(ranges):
				Last_IPart = int(ip_part[3]) + ipi
				TIp = ip_part[0]+'.'+ip_part[1]+'.'+ip_part[2]+'.'+str(Last_IPart)
				maipgather(TIp,apikey,SumorFull)
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()

#################################

def maipgather(skw,api_token,SumorFull):
	if (SumorFull.lower()=='s'):
		try:
			responseDATA = requests.get('http://ipinfo.io/'+skw+'/json?token='+api_token)
			if (responseDATA.status_code == 401):
				try:
					print (Fore.RED+'[!] '+str(responseDATA.json()['error'])+Style.RESET_ALL)
				except Exception as e:
					print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
				sys.exit()
			responseDATA = loads(responseDATA.text)   # responseDATA.text OR responseDATA.content
			if (responseDATA.get('error', None)):
				print (Fore.RED+'[!] '+str(responseDATA['error'])+Style.RESET_ALL)
			else:
				print (Fore.GREEN+'Ip: '+str(responseDATA['ip'])+Fore.YELLOW+'    Country: '+str(responseDATA['country'])+'    City: '+str(responseDATA['city'])+'    Region: '+str(responseDATA['region'])+Fore.BLUE+'    Location(lot/lon): '+str(responseDATA['loc'])+Fore.MAGENTA+'    ORG: '+str(responseDATA['org'])+Style.RESET_ALL)
		except Exception as e:
			print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)
	elif (SumorFull.lower()=='f'):
		try:
			responseDATA = requests.get('http://ipinfo.io/'+skw+'/json?token='+api_token)
			if (responseDATA.status_code == 401):
				try:
					print (Fore.RED+'[!] '+str(responseDATA.json()['error'])+Style.RESET_ALL)
				except Exception as e:
					print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
				sys.exit()
			responseDATA = loads(responseDATA.text)   # responseDATA.text OR responseDATA.content
			if (responseDATA.get('error', None)):
				print (Fore.RED+'[!] '+str(responseDATA['error'])+Style.RESET_ALL)
			else:
				print (Fore.GREEN+'Ip: '+str(responseDATA['ip'])+Fore.YELLOW+'    Country: '+str(responseDATA['country'])+'    City: '+str(responseDATA['city'])+'    Region: '+str(responseDATA['region'])+Fore.BLUE+'    Location(lot/lon): '+str(responseDATA['loc'])+Fore.MAGENTA+'    ORG: '+str(responseDATA['org'])+Style.RESET_ALL)
				print (Fore.GREEN+'ASN: '+str(responseDATA['asn']['asn'])+Fore.YELLOW+'    ASN Name: '+str(responseDATA['asn']['name'])+'    Domain: '+str(responseDATA['asn']['domain'])+Fore.BLUE+'    Route: '+str(responseDATA['asn']['route'])+Fore.MAGENTA+'    Type: '+str(responseDATA['asn']['type'])+Style.RESET_ALL)
				print (Fore.GREEN+'Company Name: '+str(responseDATA['company']['name'])+Fore.YELLOW+'    Company Domain: '+str(responseDATA['company']['domain'])+Fore.MAGENTA+'    Company Type: '+str(responseDATA['company']['type'])+Style.RESET_ALL)
		except Exception as e:
			print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)
	else:
		print (Fore.RED+'[!] You did not provide suitable answer for question about report type'+Style.RESET_ALL)
		sys.exit()

#################################


def masngather(skw,api_token,SumorFull):
	if (SumorFull.lower()=='s'):
		try:
			responseDATA = requests.get('http://ipinfo.io/'+skw+'/json?token='+api_token)
			if (responseDATA.status_code == 401):
				try:
					print (Fore.RED+'[!] '+str(responseDATA.json()['error'])+Style.RESET_ALL)
				except Exception as e:
					print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
				sys.exit()
			responseDATA = loads(responseDATA.text)   # responseDATA.text OR responseDATA.content
			if (responseDATA.get('error', None)):
				print (Fore.RED+'[!] '+str(responseDATA['error'])+Style.RESET_ALL)
			else:
				print (Fore.GREEN+'ASN: '+str(responseDATA['asn'])+Fore.YELLOW+'    Country: '+str(responseDATA['country'])+'    Name: '+str(responseDATA['name'])+'    Allocated: '+str(responseDATA['allocated'])+Fore.BLUE+'    Registry: '+str(responseDATA['registry'])+Fore.MAGENTA+'    Domain: '+str(responseDATA['domain'])+'    Number of IPs: '+str(responseDATA['num_ips'])+Style.RESET_ALL)
		except Exception as e:
			print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)
	elif (SumorFull.lower()=='f'):
		try:
			responseDATA = requests.get('http://ipinfo.io/'+skw+'/json?token='+api_token)
			if (responseDATA.status_code == 401):
				try:
					print (Fore.RED+'[!] '+str(responseDATA.json()['error'])+Style.RESET_ALL)
				except Exception as e:
					print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
				sys.exit()
			responseDATA = loads(responseDATA.text)   # responseDATA.text OR responseDATA.content
			if (responseDATA.get('error', None)):
				print (Fore.RED+'[!] '+str(responseDATA['error'])+Style.RESET_ALL)
			else:
				print (Fore.GREEN+'ASN: '+str(responseDATA['asn'])+Fore.YELLOW+'    Country: '+str(responseDATA['country'])+'    Name: '+str(responseDATA['name'])+'    Allocated: '+str(responseDATA['allocated'])+Fore.BLUE+'    Registry: '+str(responseDATA['registry'])+Fore.MAGENTA+'    Domain: '+str(responseDATA['domain'])+'    Number of IPs: '+str(responseDATA['num_ips'])+Style.RESET_ALL)
				for prfx in range(len(responseDATA['prefixes'])):
					print (Fore.BLUE+'Prefix '+prfx+':'+Style.RESET_ALL)
					print (Fore.GREEN+'\tNetblock: '+str(responseDATA['prefixes'][prfx]['netblock'])+Style.RESET_ALL)
					print (Fore.YELLOW+'\tId: '+str(responseDATA['prefixes'][prfx]['id'])+Style.RESET_ALL)
					print (Fore.BLUE+'\tName: '+str(responseDATA['prefixes'][prfx]['name'])+Style.RESET_ALL)
					print (Fore.MAGENTA+'\tCountry: '+str(responseDATA['prefixes'][prfx]['country'])+Style.RESET_ALL)
				for prfx6 in range(len(responseDATA['prefixes6'])):
					print (Fore.BLUE+'\nPrefix(V6) '+prfx+':'+Style.RESET_ALL)
					print (Fore.GREEN+'\tNetblock: '+str(responseDATA['prefixes6'][prfx6]['netblock'])+Style.RESET_ALL)
					print (Fore.YELLOW+'\tId: '+str(responseDATA['prefixes6'][prfx6]['id'])+Style.RESET_ALL)
					print (Fore.BLUE+'\tName: '+str(responseDATA['prefixes6'][prfx6]['name'])+Style.RESET_ALL)
					print (Fore.MAGENTA+'\tCountry: '+str(responseDATA['prefixes6'][prfx6]['country'])+Style.RESET_ALL)
				for peer in range(len(responseDATA['peers'])):
					print (Fore.GREEN+'\n Peer Number '+peer+': '+str(responseDATA['peers'][peer][0])+Style.RESET_ALL)
				for upstream in range(len(responseDATA['asn']['upstreams'])):
					print (Fore.GREEN+'\n Upstream '+upstream+': '+str(responseDATA['upstreams'][upstream][0])+Style.RESET_ALL)
		except Exception as e:
			print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)
	else:
		print (Fore.RED+'[!] You did not provide suitable answer for question about report type'+Style.RESET_ALL)
		sys.exit()


#################################

if __name__=='__main__':
	print (Fore.CYAN + '''
				.___        _____       
				|   |______/ ____\____  
				|   \____ \   __\/  _ \ 
				|   |  |_> >  | (  <_> )
				|___|   __/|__|  \____/ 
				    |__|                  
                                  
				        coded by Z3r0''')
	print (Fore.RED + '''\t\t\t\t\tCodename - ZEROARY''')
	print (Fore.CYAN + '''
		This is ' Ipfo '. With this you can gather information about IP(s) and ASN(s).
		This script uses your ipinfo.io API key(s) to intract with it and gather
		informations that you want.
		Be sure that you imported your API key(s).
		You can use different API key and change API key that you want to use.

		WARNING: REMEMBER THAT FULL REPORT AND ALL ASN OPTIONS WORK ONLY IF YOU ARE USING PAY PLANED API KEY(s)
		DO NOT USE THESE OPTIONS IF YOU NOT USE PAY PLANED API KEY(s). IT WILL NOT WORK AND GONNA CRASH.
		'''+Style.RESET_ALL)
	parser = optparse.OptionParser( version = Tversion )
	group = OptionGroup(parser,'Main Options')
	group.add_option('--sglip', action='store', dest='sglip' , help='Single Ip Address.EXMP: 1.1.1.2    This will gather info of specified ip')
	group.add_option('--mulip', action='store', dest='mulip' , help='Multiple Ip Address.EXMP: 1.1.1.2,3.4.5.4    This will gather info of these 2 ip')
	group.add_option('--ipr', action='store', dest='iprange' , help='Define Ip Range.EXMP: 192.168.1.8-12   This will gather info of 8, 9, 10, 11 and 12')
	group.add_option('--cidr', action='store', dest='cidr' , help='You can use CIDR(Ip/Mask) to gather info of whole subnet.EXMP: 192.168.1.0/24')
	group.add_option('--asn', action='store', dest='asn' , help='Use to gather info of an ASN.EXMP: AS15169')
	group.add_option('--mulasn', action='store', dest='mulasn' , help='Use to gather info of multiple ASNs.EXMP: AS15169,AS15170,AS15171')
	parser.add_option_group(group)
	group = OptionGroup(parser,'Api-Key Options')
	group.add_option('--kf', action='store', dest='keyfunk' , help='Add or Delete Key(s), print API-KEY help menu and also list all KEYs [default is list KEYs - add|del|help|list]' , type='string')
	group.add_option('--api', action='store', dest='api_key' , help='API-KEY')
	parser.add_option_group(group)
	options,_ = parser.parse_args()
	###
	if (options.mulip and not (options.sglip and options.mulasn and options.iprange and options.cidr and options.keyfunk and options.asn and options.api_key)):
		gatherMUL(options.mulip)
	###
	elif (options.iprange and not (options.sglip and options.mulasn and options.mulip and options.cidr and options.keyfunk and options.asn and options.api_key)):
		gatherR(options.iprange)
	###
	elif (options.cidr and not (options.sglip and options.mulasn and options.mulip and options.iprange and options.keyfunk and options.asn and options.api_key)):
		gatherC(options.cidr)
	###
	elif (options.asn and not (options.sglip and options.mulasn and options.mulip and options.iprange and options.keyfunk and options.cidr and options.api_key)):
		gatherASN(options.asn)
	###
	elif (options.sglip and not (options.asn and options.mulasn and options.mulip and options.iprange and options.keyfunk and options.cidr and options.api_key)):
		gatherSIP(options.sglip)
	###
	elif (options.mulasn and not (options.sglip and options.asn and options.mulip and options.iprange and options.keyfunk and options.cidr and options.api_key)):
		gatherMULASN(options.mulasn)
	###
	elif (options.keyfunk and not (options.sglip and options.mulasn and options.iprange and options.cidr and options.mulip and options.asn and options.api_key)):
		keyF(options.keyfunk.lower(),options.api_key)
	###
	else:
		parser.print_help()
		sys.exit()
	print(Style.RESET_ALL)
