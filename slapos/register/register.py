# -*- coding: utf-8 -*-
# vim: set et sts=2:
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

# XXX dry_run will happily register a new node on the slapos master. Isn't it supposed to be no-op?


import ConfigParser
import getpass
import os
import shutil
import stat
import sys
import tempfile
import subprocess
from subprocess import CalledProcessError

import requests


def check_credentials(url, login, password):
  """Check if login and password are correct"""
  req = requests.get(url, auth=(login, password), verify=False)
  return 'Logout' in req.text


def get_certificates(logger, master_url_web, node_name, token=None, login=None, password=None):
  """Download certificates from SlapOS Master"""

  if token:
    req = requests.post('/'.join([master_url_web, 'add-a-server/WebSection_registerNewComputer']),
                        data={'title': node_name},
                        headers={'X-Access-Token': token},
                        verify=False)
  else:
    register_server_url = '/'.join([master_url_web, ("add-a-server/WebSection_registerNewComputer?dialog_id=WebSection_viewServerInformationDialog&dialog_method=WebSection_registerNewComputer&title={}&object_path=/erp5/web_site_module/hosting/add-a-server&update_method=&cancel_url=https%3A//www.vifib.net/add-a-server/WebSection_viewServerInformationDialog&Base_callDialogMethod=&field_your_title=Essai1&dialog_category=None&form_id=view".format(node_name))])
    req = requests.get(register_server_url, auth=(login, password), verify=False)

  if not req.ok and 'Certificate still active.' in req.text:
    # raise a readable exception if the computer name is already used,
    # instead of an opaque 500 Internal Error.
    # this will not work with the new API.
    logger.error('The node name "%s" is already in use. Please change the name, or revoke the active certificate if you want to replace the node.' % node_name)
    sys.exit(1)

  if req.status_code == 403:
    if token:
      msg = 'Please check the authentication token or require a new one.'
    else:
      msg = 'Please check username and password.'
    logger.error('Access denied to the SlapOS Master. %s', msg)
    sys.exit(1)
  else:
    req.raise_for_status()

  return req.text


def parse_certificates(source):
  """Parse html gotten from SlapOS Master to make certificate and key files"""
  c_start = source.find("Certificate:")
  c_end = source.find("</textarea>", c_start)
  k_start = source.find("-----BEGIN PRIVATE KEY-----")
  k_end = source.find("</textarea>", k_start)
  return source[c_start:c_end], source[k_start:k_end]


def get_computer_name(certificate):
  """Parse certificate to get computer name and return it"""
  k = certificate.find("COMP-")
  i = certificate.find("/email", k)
  return certificate[k:i]


def save_former_config(conf):
  """Save former configuration if found"""
  # Check for config file in /etc/opt/slapos/
  if os.path.exists('/etc/opt/slapos/slapos.cfg'):
    former = '/etc/opt/slapos'
  else:
    return

  saved = former + '.old'
  while True:
    if os.path.exists(saved):
      print "Slapos configuration detected in %s" % saved
      if saved[-1] != 'd':
        saved = saved[:-1] + str(int(saved[-1]) + 1)
      else:
        saved += '.1'
    else:
        break
  conf.logger.info("Former slapos configuration detected in %s moving to %s" % (former, saved))
  shutil.move(former, saved)


def get_slapos_conf_example():
  """
  Get slapos.cfg.example and return its path
  """
  _, path = tempfile.mkstemp()
  with open(path, 'wb') as fout:
    req = requests.get('http://git.erp5.org/gitweb/slapos.core.git/blob_plain/HEAD:/slapos.cfg.example')
    fout.write(req.content)
  return path


def slapconfig(conf):
  """Base Function to configure slapos in /etc/opt/slapos"""
  dry_run = conf.dry_run
  # Create slapos configuration directory if needed
  slap_conf_dir = os.path.normpath(conf.slapos_configuration)

  # Make sure everybody can read slapos configuration directory:
  # Add +x to directories in path
  directory = os.path.dirname(slap_conf_dir)
  while True:
    if os.path.dirname(directory) == directory:
      break
    # Do "chmod g+xro+xr"
    os.chmod(directory, os.stat(directory).st_mode | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)
    directory = os.path.dirname(directory)

  if not os.path.exists(slap_conf_dir):
    conf.logger.info("Creating directory: %s" % slap_conf_dir)
    if not dry_run:
      os.mkdir(slap_conf_dir, 0o711)

  user_certificate_repository_path = os.path.join(slap_conf_dir, 'ssl')
  if not os.path.exists(user_certificate_repository_path):
    conf.logger.info("Creating directory: %s" % user_certificate_repository_path)
    if not dry_run:
      os.mkdir(user_certificate_repository_path, 0o711)

  key_file = os.path.join(user_certificate_repository_path, 'key')
  cert_file = os.path.join(user_certificate_repository_path, 'certificate')
  for src, dst in [
          (conf.key, key_file),
          (conf.certificate, cert_file)
          ]:
    conf.logger.info("Copying to %r, and setting minimum privileges" % dst)
    if not dry_run:
      with open(dst, 'w') as destination:
        destination.write(''.join(src))
      os.chmod(dst, 0o600)
      os.chown(dst, 0, 0)

  certificate_repository_path = os.path.join(slap_conf_dir, 'ssl', 'partition_pki')
  if not os.path.exists(certificate_repository_path):
    conf.logger.info("Creating directory: %s" % certificate_repository_path)
    if not dry_run:
      os.mkdir(certificate_repository_path, 0o711)

  # Put slapos configuration file
  slap_conf_file = os.path.join(slap_conf_dir, 'slapos.cfg')
  conf.logger.info("Creating slap configuration: %s" % slap_conf_file)

  # Get example configuration file
  slapos_cfg_example = get_slapos_conf_example()
  new_configp = ConfigParser.RawConfigParser()
  new_configp.read(slapos_cfg_example)
  os.remove(slapos_cfg_example)

  for section, key, value in [
          ('slapos', 'computer_id', conf.computer_id),
          ('slapos', 'master_url', conf.master_url),
          ('slapos', 'key_file', key_file),
          ('slapos', 'cert_file', cert_file),
          ('slapos', 'certificate_repository_path', certificate_repository_path),
          ('slapformat', 'interface_name', conf.interface_name),
          ('slapformat', 'ipv4_local_network', conf.ipv4_local_network),
          ('slapformat', 'partition_amount', conf.partition_number),
          ('slapformat', 'create_tap', conf.create_tap)
          ]:
    new_configp.set(section, key, value)

  if conf.ipv6_interface:
    new_configp.set('slapformat', 'ipv6_interface', conf.ipv6_interface)

  if not dry_run:
    with open(slap_conf_file, 'w') as fout:
      new_configp.write(fout)

  conf.logger.info("SlapOS configuration: DONE")


class RegisterConfig(object):
  """
  Class containing all parameters needed for configuration
  """

  def __init__(self, logger):
    self.logger = logger

  def setConfig(self, options):
    """
    Set options given by parameters.
    """
    # Set options parameters
    for option, value in options.__dict__.items():
      setattr(self, option, value)

  def COMPConfig(self, slapos_configuration, computer_id, certificate, key):
    self.slapos_configuration = slapos_configuration
    self.computer_id = computer_id
    self.certificate = certificate
    self.key = key

  def displayUserConfig(self):
    self.logger.debug("Computer Name: %s" % self.node_name)
    self.logger.debug("Master URL: %s" % self.master_url)
    self.logger.debug("Number of partition: %s" % self.partition_number)
    self.logger.info("Using Interface %s" % self.interface_name)
    self.logger.debug("Ipv4 sub network: %s" % self.ipv4_local_network)
    self.logger.debug("Ipv6 Interface: %s" % self.ipv6_interface)


def gen_auth(conf):
  ask = True
  if conf.login:
    if conf.password:
      yield conf.login, conf.password
      ask = False
    else:
      yield conf.login, getpass.getpass()
  while ask:
    yield raw_input('SlapOS Master Login: '), getpass.getpass()


def do_register(conf):
  """Register new computer on SlapOS Master and generate slapos.cfg"""

  if conf.token == 'ask':
    while True:
      conf.token = raw_input('SlapOS Token: ').strip()
      if conf.token:
        break

  if conf.token:
    certificate_key = get_certificates(conf.logger, conf.master_url_web, conf.node_name, token=conf.token)
  else:
    for login, password in gen_auth(conf):
      if check_credentials(conf.master_url_web, login, password):
        break
      conf.logger.warning('Wrong login/password')
    else:
      return 1

    certificate_key = get_certificates(conf.logger, conf.master_url_web, conf.node_name, login=login, password=password)

  # Parse certificate and key and get computer id
  certificate, key = parse_certificates(certificate_key)
  COMP = get_computer_name(certificate)
  # Getting configuration parameters
  conf.COMPConfig(slapos_configuration='/etc/opt/slapos/',
                  computer_id=COMP,
                  certificate=certificate,
                  key=key)
  # Save former configuration
  if not conf.dry_run:
    save_former_config(conf)
  # Prepare Slapos Configuration
  slapconfig(conf)

  print "Node has successfully been configured as %s." % COMP
  # XXX hardcoded value, relying on package installation
  # We shall fix that later
  print "Running starting script"
  if os.path.isfile("/usr/sbin/slapos-start"):
    try:
      subprocess.check_call("/usr/sbin/slapos-start")
    except CalledProcessError:
      print "Error while trying to run /usr/sbin/slapos-start"
  else:
    print "Missing file /usr/sbin/slapos-start"
  return 0
