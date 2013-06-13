# -*- coding: utf-8 -*-
##############################################################################
#
# Copyright (c) 2012 Vifib SARL and Contributors. All Rights Reserved.
#
# WARNING: This program as such is intended to be used by professional
# programmers who take the whole responsibility of assessing all potential
# consequences resulting from its eventual inadequacies and bugs
# End users who are looking for a ready-to-use solution with commercial
# guarantees and support are strongly advised to contract a Free Software
# Service Company
#
# This program is Free Software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
##############################################################################

import argparse
import ConfigParser
import os
import sys

from slapos.cli_legacy.bang import main as bang
from slapos.cli_legacy.console import console
from slapos.cli_legacy.request import request
from slapos.cli_legacy.remove import remove
from slapos.cli_legacy.supply import supply
from slapos.cli_legacy.format import main as format
from slapos.cli_legacy.slapgrid import runComputerPartition as instance
from slapos.cli_legacy.slapgrid import runSoftwareRelease as software
from slapos.cli_legacy.slapgrid import runUsageReport as report
from slapos.cli_legacy.svcbackend import supervisord
from slapos.cli_legacy.svcbackend import supervisorctl
from slapos.cli_legacy.register import main as register
from slapos.version import version

# Note: this whole file is a hack. We should better try dedicated library
# like https://github.com/dhellmann/cliff or https://github.com/docopt/docopt.

GLOBAL_SLAPOS_CONFIGURATION = os.environ.get(
    'SLAPOS_CONFIGURATION',
    '/etc/opt/slapos/slapos.cfg')
USER_SLAPOS_CONFIGURATION = os.environ.get(
    'SLAPOS_CLIENT_CONFIGURATION',
    os.environ.get('SLAPOS_CONFIGURATION', '~/.slapos/slapos.cfg'))


class EntryPointNotImplementedError(NotImplementedError):
  def __init__(self, *args, **kw_args):
    NotImplementedError.__init__(self, *args, **kw_args)


def checkSlaposCfg():
  """
  Check if a slapos configuration file was given as a argument.
  If a slapos configuration file is given it return True else False
  """
  # XXX-Cedric: dangerous but quick way to achieve way to not provide
  # configuration file for each command without changing underlying code.
  # It the long term, it should be done in a better way (no guessing).
  for element in sys.argv:
    if '.cfg' in element:
      if os.path.exists(element):
        configp = ConfigParser.SafeConfigParser()
        configp.read(element)
        if configp.has_section('slapos'):
          return True
  return False


def checkOption(option):
  """
  Check if a given option is already in call line
  Add it and its values if missing
  """
  option = option.split()
  key = option[0]
  for element in sys.argv:
    if key in element:
      return True
  sys.argv.append(key)
  if len(option) > 1:
    sys.argv = sys.argv + option[1:]
  return True


def call(fun, config_path=False, option=None):
  """
  Add missing options to sys.argv
  Add config if asked and it is missing
  Call function fun
  """
  if option is None:
    option = []
  for element in option:
    checkOption(element)
  if config_path:
    if not checkSlaposCfg():
      sys.argv = [sys.argv[0]] + [os.path.expanduser(config_path)] + sys.argv[1:]
  fun()
  sys.exit(0)


def dispatch(command, is_node_command):
  """ Dispatch to correct SlapOS module.
  Here we could use introspection to get rid of the big "if" statements,
  but we want to control every input.
  Here we give default option and configuration file if they are needed, i.e
  If configuration file is not given: define it arbitrarily, and so on.
  """
  if is_node_command:

    if os.getuid() != 0:
      sys.stderr.write('This command must be run as root.\n')
      sys.exit()

    if command == 'register':
      call(register)
    elif command == 'software':
      call(software, config_path=GLOBAL_SLAPOS_CONFIGURATION,
           option=['--pidfile /opt/slapos/slapgrid-sr.pid'])
    elif command == 'instance':
      call(instance, config_path=GLOBAL_SLAPOS_CONFIGURATION,
           option=['--pidfile /opt/slapos/slapgrid-cp.pid'])
    elif command == 'report':
      call(report, config_path=GLOBAL_SLAPOS_CONFIGURATION,
           option=['--pidfile /opt/slapos/slapgrid-ur.pid'])
    elif command == 'bang':
      call(bang, config_path=GLOBAL_SLAPOS_CONFIGURATION)
    elif command == 'format':
      call(format, config_path=GLOBAL_SLAPOS_CONFIGURATION, option=['-c', '-v'])
    elif command == 'supervisord':
      call(supervisord, config_path=GLOBAL_SLAPOS_CONFIGURATION)
    elif command == 'supervisorctl':
      call(supervisorctl, config_path=GLOBAL_SLAPOS_CONFIGURATION)
    elif command in ['start', 'stop', 'restart', 'status', 'tail']:
      # Again, too hackish
      sys.argv[-2:-2] = [command]
      call(supervisorctl, config_path=GLOBAL_SLAPOS_CONFIGURATION)
    else:
      return False
  elif command == 'request':
    call(request, config_path=USER_SLAPOS_CONFIGURATION)
  elif command == 'supply':
    call(supply, config_path=USER_SLAPOS_CONFIGURATION)
  elif command == 'remove':
    call(remove, config_path=USER_SLAPOS_CONFIGURATION)
  elif command == 'start':
    raise EntryPointNotImplementedError(command)
  elif command == 'stop':
    raise EntryPointNotImplementedError(command)
  elif command == 'destroy':
    raise EntryPointNotImplementedError(command)
  elif command == 'console':
    call(console, config_path=USER_SLAPOS_CONFIGURATION)
  else:
    return False


def main():
  """
  Main entry point of SlapOS Node. Used to dispatch commands to python
  module responsible of the operation.
  """
  # If "node" arg is the first: we strip it and set a switch
  if len(sys.argv) > 1 and sys.argv[1] == "node":
    sys.argv.pop(1)
    # Hackish way to show status if no argument is specified
    if len(sys.argv) is 1:
      sys.argv.append('status')
    is_node = True
  else:
    is_node = False

  usage = """SlapOS %s command line interface.
For more informations, refer to SlapOS documentation.

Client subcommands usage:
  slapos request <instance-name> <software-url> [--configuration arg1=value1 arg2=value2 ... argN=valueN]
  slapos supply <software-url> <node-id>
  slapos console
Node subcommands usage:
  slapos node
  slapos node register <node-id>
  slapos node software
  slapos node instance
  slapos node report
  slapos node format
  slapos node start <process>
  slapos node stop <process>
  slapos node restart <process>
  slapos node tail [process]
  slapos node status <process>
  slapos node supervisorctl
  slapos node supervisord
""" % version

  # Parse arguments
  # XXX remove the "positional arguments" from help message
  ap = argparse.ArgumentParser(usage=usage)
  ap.add_argument('command')
  ap.add_argument('argument_list', nargs=argparse.REMAINDER)

  args = ap.parse_args()
  # Set sys.argv for the sub-entry point that we will call
  command_line = [args.command]
  command_line.extend(args.argument_list)
  sys.argv = command_line

  try:
    if not dispatch(args.command, is_node):
      ap.print_help()
      sys.exit(1)
  except EntryPointNotImplementedError, exception:
    print ('The command %s does not exist or is not yet implemented. Please '
           'have a look at http://community.slapos.org to read documentation or '
           'forum. Please also make sure that SlapOS Node is up to '
           'date.' % exception)
    sys.exit(1)
