#!/usr/bin/python

## SSH/TMSH BIG-IP Cleanerk
## Author: Chad Jenison (c.jenison@f5.com)
## Script that connects to BIG-IP over network (via SSH) and then uses TMSH commands to enumerate virtual servers and then identifies candidate virtual servers for deletion
## Version: 1.1 - Fixed operation on 10.2.x BIG-IPs (due to lack of support for "list ltm virtual one-line" and changes in "show ltm virtual field-fmt" between 10.x and 11.x+
## Version: 1.2 - Add prompt to save configuration to files (using tmsh save sys config) a the end of execution
## Version: 1.3 - Add detection of tmsh as login prompt and issue "run /util bash" since script is written using "tmsh " in front of all TMSH commands:w
## Version: 1.4 - Add handling of partitions 
## Version: 1.5 - Added print messages to indicate progress (due to this tool being used with large config and reverse DNS timeouts potentially lasting a while, execution can take a while)
## Version: 1.6 - Added --nprompt argument which auto-confirms choices rather than prompting users for confirmation of acts (deletion of configuration objects and saving of configuration)
## Version: 1.7 - Fixed version 1.6

import argparse
import sys
import socket
import getpass
import paramiko
import time


# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        ## Lines added per request from Oracle for "No Prompt" mode.
        if args.noprompt:
            return True
        else:
            sys.stdout.write(question + prompt)
            choice = raw_input().lower() 
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid.keys():
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def determineShell():
    stdin, stdout, stderr = sshSession.exec_command('tmsh show sys version')
    output = ""
    for line in stderr.read().splitlines():
        output = output + line
    if output.find('Syntax Error') == -1:
        return 'bash'
    else:
        print ('Login shell for user %s is not bash; this script requires login shell of bash (Advanced Shell)')
        return 'tmsh'
        
        
def removeVirtual(virtualName, partition, vip, service, currentConns, totalConns, availabilityState, enabledState, reverseDns):
    #Gather Up Pool and iRules used by the virtual server being removed
    stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; list ltm virtual %s%s' % (commandPrefix, partition, virtualName, commandPostfix))
    inRules = False
    rules = []
    pool = ''
    for line in stdout.read().splitlines():
        if line.lstrip().startswith('pool '):
            pool = line.lstrip().split(' ')[1].rstrip()
        elif inRules:
            if line.lstrip().rstrip() == '}':
                inRules = False
            else:
                if not line.lstrip().rstrip().startswith('_sys'):
                    rules.append(line.lstrip().rstrip())
        elif line.lstrip().startswith('rules {'):
            inRules = True 
    if args.remove:
       print ('--Status Information from CSV File - NOT CURRENT--')
    else:
       print ('--Status Information - CURRENT--')
    print ('Virtual Name: %s' % (virtualName))
    print ('Partition: %s' % (partition))
    print ('VIP: %s' % (vip))
    print ('Service: %s' % (service))
    print ('Current Conns: %s' % (currentConns))
    print ('Total Conns: %s' % (totalConns))
    print ('Availability State: %s' % (availabilityState))
    print ('Enabled State: %s' % (enabledState))
    print ('Reverse DNS: %s' % (reverseDns))
    if pool != '':
        print ('Pool: %s' % (pool))
    else:
        print ('Pool: **None**')
    if rules:
        for rule in rules:
             print ('iRule: %s' % (rule)) 
    queryString = ('Remove Virtual Server: %s?' % (virtualName))
    if query_yes_no(queryString, default="no"):
        stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; delete ltm virtual %s%s' % (commandPrefix, partition, virtualName, commandPostfix))
        #Check for Errors in deleting configuration objects
        for line in stderr.read().splitlines():
            if ": " in line:
                print ('Virtual Server Delete encountered error: %s' % (line))
        if pool != '':
	    queryString = ('Remove Pool: %s?' % (pool))
	    if query_yes_no(queryString, default="no"):
		stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; delete ltm pool %s%s' % (commandPrefix, partition, pool, commandPostfix))
		for line in stderr.read().splitlines():
		    if ": " in line:
			print ('Pool Delete encountered error: %s' % (line))
        for rule in rules:
            queryString = ('Remove Rule: %s?' % (rule))
            if query_yes_no(queryString, default="no"):
                stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; delete ltm rule %s%s' % (commandPrefix, partition, rule, commandPostfix))
                for line in stderr.read().splitlines():
                    if ": " in line:
                        print ('Rule %s Delete encountered error: %s' % (rule, line))

parser = argparse.ArgumentParser(description='A tool to identify and remove stale virtual servers from F5 BIG-IP Systems (should work with any BIG-IP that runs 10.0+ and has TMSH)', epilog='Use this tool with caution')
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--scan', action='store_true', help='scan for unused virtual servers and output to file')
mode.add_argument('--remove', action='store_true', help='remove unused virtual servers based on input file')
mode.add_argument('--scanandremove', action='store_true', help='scan for unused virtual servers and immediately remove')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)
parser.add_argument('--file', help='filename in cwd CSV formatted; file is output filename if scanning; file is input filename if removing', default='ssh_bigip_cleaner.csv')
parser.add_argument('--noprompt', action='store_true', help='Do not prompt for confirmation of configuration removal')
virtualselector = parser.add_argument_group(title='Criteria for Selecting Stale Virtual Servers')
virtualselector.add_argument('--vipNoDns', action='store_true', help='select virtual server for removal solely based on VIP Reverse DNS Unknown')
virtualselector.add_argument('--vipNoDnsVsEnabled', action='store_true', help='select virtual server for removal based on VIP Reverse DNS Unknown AND Virtual Enabled')
virtualselector.add_argument('--vipNoDnsVsDisabled', action='store_true', help='select virtual server for removal based on VIP Reverse DNS Unknown AND Virtual Disabled')
virtualselector.add_argument('--vipNoDnsVsAvailable', action='store_true', help='select virtual server for removal based on VIP Reverse DNS Unknown AND Virtual has Available Status')
virtualselector.add_argument('--vipNoDnsVsOffline', action='store_true', help='select virtual server for removal based on VIP Reverse DNS Unknown AND Virtual has Offline Status')
virtualselector.add_argument('--vs0TotalConns', action='store_true', help='select virtual server for removal based on Virtual 0 Total Conns')
virtualselector.add_argument('--vs0CurConns', action='store_true', help='select virtual server for removal based on Virtual 0 Current Conns')
virtualselector.add_argument('--vsDisabled', action='store_true', help='select virtual server for removal based on Virtual Server Disabled')
virtualselector.add_argument('--vsOffline', action='store_true', help='select virtual server for removal based on Virtual Server Offline')

args = parser.parse_args()

passwd = getpass.getpass("Password for " + args.user + ":")

sshSession=paramiko.SSHClient()
sshSession.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshSession.connect(args.bigip, username=args.user, password=passwd, look_for_keys=False, allow_agent=False)
configChanged = False
if determineShell() == 'bash':
    loginShell = 'bash'
    commandPrefix = 'tmsh -c \"'
    commandPostfix = '\"'
else:
    loginShell = 'tmsh' 
    commandPrefix = ''
    commandPostfix = ''

if args.scan or args.scanandremove:
    partitions = []
    if loginShell == 'bash':
        stdin, stdout, stderr = sshSession.exec_command('tmsh list auth partition')
    elif loginShell == 'tmsh':
        stdin, stdout, stderr = sshSession.exec_command('list auth partition')
    for line in stderr.read().splitlines():
        print ('StdErr: %s' % (line))
    for line in stdout.read().splitlines():
        if line.startswith('auth partition '):
            partitions.append(line.split(' ')[2])
    print ('Partitions Found: %s' % (partitions))
    if args.scan:
        fileOut = open('%s' % (args.file), 'w')
    for partition in partitions:
	stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; list ltm virtual%s' % (commandPrefix, partition, commandPostfix))
	allvirtuals = []
	for line in stdout.read().splitlines():
	    if line.startswith('ltm virtual'):
		virtual = []
		virtual.append(line.split(' ')[2])
		allvirtuals.append(virtual)

	for virtual in allvirtuals:
	    stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; list ltm virtual %s%s' % (commandPrefix, partition, virtual[0], commandPostfix))
            print ('Retrieving Config for Virtual: %s\n' % (virtual[0]))
	    for line in stdout.read().splitlines():
		if line.lstrip().startswith('destination'):
		    virtual.append(line.lstrip().split(' ')[1]) 
		    virtual.append(line.lstrip().split(' ')[1].split(':')[0]) 
		    virtual.append(line.lstrip().split(' ')[1].split(':')[1].rstrip()) 
	    stdin, stdout, stderr = sshSession.exec_command('%scd /%s ; show ltm virtual %s field-fmt%s' % (commandPrefix, partition, virtual[0], commandPostfix))
	    for line in stdout.read().splitlines():
		if line.lstrip().startswith('clientside.cur-conns'):
		    virtual.append(line.lstrip().split(' ')[1].rstrip())
		elif line.lstrip().startswith('clientside.tot-conns'):
		    virtual.append(line.lstrip().split(' ')[1].rstrip())
		#11.x+ Format
		elif line.lstrip().startswith('status.availability-state'):
		    virtual.append(line.lstrip().split(' ')[1].rstrip())
		#10.x format
		elif line.lstrip().startswith('virtual-server.status.availability-state'):
		    virtual.append(line.lstrip().split(' ')[1].rstrip())
		#11.x+ Format
		elif line.lstrip().startswith('status.enabled-state'):
		    virtual.append(line.lstrip().split(' ')[1].rstrip())
		#10.x Format
		elif line.lstrip().startswith('virtual-server.status.enabled-state'):
		    virtual.append(line.lstrip().split(' ')[1].rstrip())
	    try:
		name, alias, addresslist = socket.gethostbyaddr(virtual[2])
		virtual.append(name)
	    except socket.error:
		virtual.append('unknown')
            print ('Info for virtual: %s - %s\n' % (virtual[0], virtual))

	for virtual in allvirtuals:
	    if (args.vipNoDns and virtual[8] == 'unknown') or (args.vipNoDnsVsEnabled and virtual[8] == 'unknown' and virtual[7] == 'enabled') or (args.vipNoDnsVsDisabled and virtual[8] == 'unknown' and virtual[7] == 'disabled') or (args.vipNoDnsVsAvailable and virtual[8] == 'unknown' and virtual[6] == 'available') or (args.vipNoDnsVsOffline and virtual[8] == 'unknown' and virtual[6] == 'offline') or (args.vs0TotalConns and virtual[5] == '0') or (args.vs0CurConns and virtual[4] == '0') or (args.vsDisabled and virtual[7] == 'disabled') or (args.vsOffline and virtual[6] == 'offline'):
		if args.scan:
		    fileOut.write('VirtualName,%s,VIP,%s,Service,%s,CurrentConns,%s,TotalConns,%s,AvailabilityState,%s,EnabledState,%s,ReverseDNS,%s,Partition,%s\n' % (virtual[0], virtual[2], virtual[3], virtual[4], virtual[5], virtual[6], virtual[7], virtual[8],partition))
		else:
		    removeVirtual(virtual[0], partition, virtual[2], virtual[3], virtual[4], virtual[5], virtual[6], virtual[7], virtual[8])
    if args.scan:
	fileOut.close()

if args.remove:
   fileIn = open('%s' % (args.file), 'r')
   for line in fileIn:
       removeVirtual(line.split(',')[1], line.split(',')[17], line.split(',')[3], line.split(',')[5], line.split(',')[7], line.split(',')[9], line.split(',')[11], line.split(',')[13], line.split(',')[15].rstrip())

if args.scanandremove or args.remove:
    queryString = 'Do you want to save changes to configuration files?'
    if query_yes_no(queryString, default="yes"):
        if loginShell == 'bash':
            stdin, stdout, stderr = sshSession.exec_command("tmsh save sys config")
        elif loginShell == 'tmsh':
            stdin, stdout, stderr = sshSession.exec_command("save sys config")

##SUBLIST FIELD NUMBERS BELOW
#            print ('Virtual Name: %s' % (virtual[0]))
#            print ('VIP: %s' % (virtual[2]))
#            print ('Service: %s' % (virtual[3]))
#            print ('Current Conns: %s' % (virtual[4]))
#            print ('Total Conns: %s' % (virtual[5]))
#            print ('Availability State: %s' % (virtual[6]))
#            print ('Enabled State: %s' % (virtual[7]))
#	     print ('Reverse DNS: %s' % (virtual[8]))
