#!/usr/bin/env python2
#
# openvpn-snmp agentx
# Copyright (c) 2015 Philipp Helo Rehs
# Based on python-netsnmpagent simple example agent
# https://github.com/pief/python-netsnmpagent
# Copyright (c) 2013 Pieter Hollants <pieter@hollants.com>
# Licensed under the GNU Public License (GPL) version 3
#

import sys, os, signal
import optparse
import pprint
import json
import re

# Make sure we use the local copy, not a system-wide one
sys.path.insert(0, os.path.dirname(os.getcwd()))
import netsnmpagent

prgname = sys.argv[0]

# Process command line arguments
parser = optparse.OptionParser()
parser.add_option(
	"-m",
	"--mastersocket",
	dest="mastersocket",
	help="Sets the transport specification for the master agent's AgentX socket",
	default="/var/run/agentx/master"
)
parser.add_option(
	"-p",
	"--persistencedir",
	dest="persistencedir",
	help="Sets the path to the persistence directory",
	default="/var/lib/net-snmp"
)
parser.add_option(
	"-c",
	"--configfile",
	dest="configfile",
	help="path of the json configuration file",
	default="openvpn.json"
)
(options, args) = parser.parse_args()

# Get terminal width for usage with pprint
rows,columns = os.popen("stty size", "r").read().split()

# First, create an instance of the netsnmpAgent class. We specify the
# fully-qualified path to SIMPLE-MIB.txt ourselves here, so that you
# don't have to copy the MIB to /usr/share/snmp/mibs.
try:
	agent = netsnmpagent.netsnmpAgent(
		AgentName      = "OpenVpnAgent",
		MasterSocket   = options.mastersocket,
		PersistenceDir = options.persistencedir,
		MIBFiles       = [ os.path.abspath(os.path.dirname(sys.argv[0])) +
		                   "/openvpn.mib" ]
	)
except netsnmpagent.netsnmpAgentException as e:
	print "{0}: {1}".format(prgname, e)
	sys.exit(1)

serverTable = agent.Table(
	oidstr = "OPENVPN-MIB::openvpnServerTable",
	indexes = [
		agent.Unsigned32()
	],
	columns = [
		(2, agent.DisplayString()),
		(3, agent.Integer32(0)),
		(4, agent.Unsigned32(0)),
		(5, agent.Unsigned32(0))
	],
	counterobj = agent.Unsigned32(
		oidstr = "OPENVPN-MIB::openvpnServerTableLength"
	)
)

userTable = agent.Table(
	oidstr = "OPENVPN-MIB::openvpnUserTable",
	indexes = [
		agent.Unsigned32()
	],
	columns = [
		(2, agent.DisplayString()),
		(3, agent.DisplayString()),
		(4, agent.Unsigned32(0)),
		(5, agent.Unsigned32(0))
	],
	counterobj = agent.Unsigned32(
		oidstr = "OPENVPN-MIB::openvpnUserTableLength"
	)
)

# Finally, we tell the agent to "start". This actually connects the
# agent to the master agent.
try:
	agent.start()
except netsnmpagent.netsnmpAgentException as e:
	print "{0}: {1}".format(prgname, e)
	sys.exit(1)

print "{0}: AgentX connection to snmpd established.".format(prgname)

# Helper function that dumps the state of all registered SNMP variables
def DumpRegistered():
	for context in agent.getContexts():
		print "{0}: Registered SNMP objects in Context \"{1}\": ".format(prgname, context)
		vars = agent.getRegistered(context)
		pprint.pprint(vars, width=columns)
		print
DumpRegistered()

# Install a signal handler that terminates our simple agent when
# CTRL-C is pressed or a KILL signal is received
def TermHandler(signum, frame):
	global loop
	loop = False
signal.signal(signal.SIGINT, TermHandler)
signal.signal(signal.SIGTERM, TermHandler)

# Install a signal handler that dumps the state of all registered values
# when SIGHUP is received
def HupHandler(signum, frame):
	DumpRegistered()
signal.signal(signal.SIGHUP, HupHandler)

def logFileParser(lines):
	regex = r'^([\w\.[a-z]+),([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+),([0-9]+),([0-9]+),(.*)'
	userlist = []
	server = {'send': 0, 'recv': 0};
	for line in lines:
		m = re.match(regex, line)
		if m is not None:
			t_send = m.group(4)
			t_recv = m.group(3)
			user = {'name': m.group(1),'ip': m.group(2), 'recv': t_recv, 'send': t_send, 'date': m.group(5)}
			userlist.append(user)
			server['send'] = server['send'] + int(t_send)
			server['recv'] = server['recv'] + int(t_recv)
	
	server['users'] = userlist;
	return server;
			
			

# The simple agent's main loop. We loop endlessly until our signal
# handler above changes the "loop" variable.
print "{0}: Serving SNMP requests, send SIGHUP to dump SNMP object state, press ^C to terminate...".format(prgname)

with open(options.configfile) as data_file:    
    serverList = json.load(data_file)

loop = True
while (loop):
	# Block and process SNMP requests, if available
	agent.check_and_process()
	
	serverTable.clear();
	userTable.clear();
	user_index = 1;
	for i in range(0, len(serverList['servers'])):
		s = serverList['servers'][i]
		if os.access(s['logFile'],os.R_OK):
			fh = open(s['logFile'],"r")
			fileContent = fh.readlines();
			serverData = logFileParser(fileContent);
			tmpRow = serverTable.addRow([agent.Unsigned32(i)])
			tmpRow.setRowCell(2, agent.DisplayString(s['name']))
			tmpRow.setRowCell(3, agent.Integer32(len(serverData['users'])))
			tmpRow.setRowCell(4, agent.Unsigned32(serverData['send']))
			tmpRow.setRowCell(5, agent.Unsigned32(serverData['recv']))
			for u in serverData['users']:
				tmpUser = userTable.addRow([agent.Unsigned32(user_index)])
				tmpUser.setRowCell(2, agent.DisplayString(u['name']))
				tmpUser.setRowCell(3, agent.DisplayString(s['name']))
				tmpUser.setRowCell(4, agent.Unsigned32(int(u['send'])))
				tmpUser.setRowCell(5, agent.Unsigned32(int(u['recv'])))
				user_index = user_index+1
		else:
			print "{0} is not readable".format(s['logFile'])


print "{0}: Terminating.".format(prgname)
agent.shutdown()
