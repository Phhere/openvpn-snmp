#!/usr/bin/env python2
#
# openvpn-snmp agentx
# Copyright (c) 2015 Philipp Helo Rehs
#
# Based on python-netsnmpagent simple example agent
# https://github.com/pief/python-netsnmpagent
# Copyright (c) 2013 Pieter Hollants <pieter@hollants.com>
# Licensed under the GNU Public License (GPL) version 3
#

import sys
import os
import signal
import optparse
import json
import re
import logging
import netsnmpagent
try:
    import daemon
except ImportError: # pragma: no cover
    daemon = False

logging.basicConfig(level=logging.INFO,filename="test.log")
logger = logging.getLogger(__name__)


class OpenVpnAgentX(object):
    def __init__(self):
        self._parse_args();
        self.run()

    def _parse_args(self):
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
        parser.add_option(
            "-f",
            "--foreground",
            dest="foreground",
            help="run in foreground",
	    default=False
        )
        (self.options, args) = parser.parse_args()
	if not os.access(self.options.mastersocket, os.R_OK):
		logger.critical("Can't connect to MasterSocket, run as root");
		sys.exit(1)



    def _parse_config(self):
        with open(self.options.configfile) as data_file:
            self.serverList = json.load(data_file)

    def _create_snmp_objects(self):
        try:
            self.agent = netsnmpagent.netsnmpAgent(
                AgentName="OpenVpnAgent",
                MasterSocket=self.options.mastersocket,
                PersistenceDir=self.options.persistencedir,
                MIBFiles=[os.path.abspath(os.path.dirname(sys.argv[0])) +
                          "/openvpn.mib"]
            )
        except netsnmpagent.netsnmpAgentException as e:
            logger.critical(e)
            sys.exit(1)

        self.snmp = dict();
        self.snmp['serverTable'] = self.agent.Table(
            oidstr="OPENVPN-MIB::openvpnServerTable",
            indexes=[
                self.agent.Unsigned32()
            ],
            columns=[
                (2, self.agent.DisplayString()),
                (3, self.agent.Integer32(0)),
                (4, self.agent.Unsigned32(0)),
                (5, self.agent.Unsigned32(0))
            ],
            counterobj=self.agent.Unsigned32(
                oidstr="OPENVPN-MIB::openvpnServerTableLength"
            )
        )

        self.snmp['userTable'] = self.agent.Table(
            oidstr="OPENVPN-MIB::openvpnUserTable",
            indexes=[
                self.agent.Unsigned32()
            ],
            columns=[
                (2, self.agent.DisplayString()),
                (3, self.agent.DisplayString()),
                (4, self.agent.Unsigned32(0)),
                (5, self.agent.Unsigned32(0))
            ],
            counterobj=self.agent.Unsigned32(
                oidstr="OPENVPN-MIB::openvpnUserTableLength"
            )
        )
        try:
            self.agent.start()
        except netsnmpagent.netsnmpAgentException as e:
            logger.critical(e)
            sys.exit(1)

        logger.info("AgentX connection to snmpd established.")

    def _signalHandler(signum, frame):
            self._loop = False

    def run(self):
        self._loop = True
        self._parse_config()
        if daemon and not self.options.foreground:
            context = daemon.DaemonContext()
            context.signal_map = {
                signal.SIGTERM: self._signalHandler,
                signal.SIGHUP: 'terminate',
                signal.SIGUSR1: self._parse_config,
            }
            with context:
                self._create_snmp_objects()
                self._runLoop()
        else:
            self._create_snmp_objects()
            logging.info("Running in foreground")
            self._runLoop()

    def _runLoop(self):
        while (self._loop):
            # Block and process SNMP requests, if available
            self.agent.check_and_process()

            self.snmp['serverTable'].clear()
            self.snmp['userTable'].clear()
            user_index = 1
            for i in range(0, len(self.serverList['servers'])):
                s = self.serverList['servers'][i]
                if os.access(s['logFile'], os.R_OK):
                    fh = open(s['logFile'], "r")
                    fileContent = fh.readlines()
                    serverData = self.parse_openvpn_status_file(fileContent)
                    tmpRow = self.snmp['serverTable'].addRow([self.agent.Unsigned32(i)])
                    tmpRow.setRowCell(2, self.agent.DisplayString(s['name']))
                    tmpRow.setRowCell(3, self.agent.Integer32(len(serverData['users'])))
                    tmpRow.setRowCell(4, self.agent.Unsigned32(serverData['send']))
                    tmpRow.setRowCell(5, self.agent.Unsigned32(serverData['recv']))
                    for u in serverData['users']:
                        tmpUser = self.snmp['userTable'].addRow([self.agent.Unsigned32(user_index)])
                        tmpUser.setRowCell(2, self.agent.DisplayString(u['name']))
                        tmpUser.setRowCell(3, self.agent.DisplayString(s['name']))
                        tmpUser.setRowCell(4, self.agent.Unsigned32(u['send']))
                        tmpUser.setRowCell(5, self.agent.Unsigned32(u['recv']))
                        user_index = user_index+1
                else:
                    logger.warning("{0} is not readable".format(s['logFile']))

        logger.info("Terminating.")
        self.agent.shutdown()

    def parse_openvpn_status_file(self, lines):
        regex = r'^([\w\.[a-z]+),([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+),([0-9]+),([0-9]+),(.*)'
        userlist = []
        server = {'send': 0, 'recv': 0}
        for line in lines:
            m = re.match(regex, line)
            if m is not None:
                t_send = int(m.group(4))
                t_recv = int(m.group(3))
                user = {
                    'name': m.group(1),
                    'ip': m.group(2),
                    'recv': t_recv,
                    'send': t_send,
                    'date': m.group(5)
                }
                userlist.append(user)
                server['send'] = server['send'] + t_send
                server['recv'] = server['recv'] + t_recv

        server['users'] = userlist
        return server


app = OpenVpnAgentX()
app.run()

'''
# First, create an instance of the netsnmpAgent class. We specify the
# fully-qualified path to SIMPLE-MIB.txt ourselves here, so that you
# don't have to copy the MIB to /usr/share/snmp/mibs.
try:
    agent = netsnmpagent.netsnmpAgent(
        AgentName="OpenVpnAgent",
        MasterSocket=options.mastersocket,
        PersistenceDir=options.persistencedir,
        MIBFiles=[os.path.abspath(os.path.dirname(sys.argv[0])) +
                  "/openvpn.mib"]
    )
except netsnmpagent.netsnmpAgentException as e:
    logger.critical(e)
    sys.exit(1)

serverTable = agent.Table(
    oidstr="OPENVPN-MIB::openvpnServerTable",
    indexes=[
        agent.Unsigned32()
    ],
    columns=[
        (2, agent.DisplayString()),
        (3, agent.Integer32(0)),
        (4, agent.Unsigned32(0)),
        (5, agent.Unsigned32(0))
    ],
    counterobj=agent.Unsigned32(
        oidstr="OPENVPN-MIB::openvpnServerTableLength"
    )
)

userTable = agent.Table(
    oidstr="OPENVPN-MIB::openvpnUserTable",
    indexes=[
        agent.Unsigned32()
    ],
    columns=[
        (2, agent.DisplayString()),
        (3, agent.DisplayString()),
        (4, agent.Unsigned32(0)),
        (5, agent.Unsigned32(0))
    ],
    counterobj=agent.Unsigned32(
        oidstr="OPENVPN-MIB::openvpnUserTableLength"
    )
)

# Finally, we tell the agent to "start". This actually connects the
# agent to the master agent.
try:
    agent.start()
except netsnmpagent.netsnmpAgentException as e:
    logger.critical(e)
    sys.exit(1)

logger.info("AgentX connection to snmpd established.")

# Helper function that dumps the state of all registered SNMP variables


def DumpRegistered():
    for context in agent.getContexts():
        logger.debug("Registered SNMP objects in Context \"{0}\": ".format(context))
        vars = agent.getRegistered(context)
        logger.debug(vars)

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
    server = {'send': 0, 'recv': 0}
    for line in lines:
        m = re.match(regex, line)
        if m is not None:
            t_send = m.group(4)
            t_recv = m.group(3)
            user = {
                'name': m.group(1),
                'ip': m.group(2),
                'recv': t_recv,
                'send': t_send,
                'date': m.group(5)
            }
            userlist.append(user)
            server['send'] = server['send'] + int(t_send)
            server['recv'] = server['recv'] + int(t_recv)

    server['users'] = userlist
    return server

with open(options.configfile) as data_file:
    serverList = json.load(data_file)

loop = True
while (loop):
    # Block and process SNMP requests, if available
    agent.check_and_process()

    serverTable.clear()
    userTable.clear()
    user_index = 1
    for i in range(0, len(serverList['servers'])):
        s = serverList['servers'][i]
        if os.access(s['logFile'], os.R_OK):
            fh = open(s['logFile'], "r")
            fileContent = fh.readlines()
            serverData = logFileParser(fileContent)
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
            logger.warning("{0} is not readable".format(s['logFile']))


logger.info("Terminating.")
agent.shutdown()
'''
