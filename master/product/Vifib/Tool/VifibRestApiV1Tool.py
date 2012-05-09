# -*- coding: utf-8 -*-
##############################################################################
#
# Copyright (c) 2012 Nexedi SA and Contributors. All Rights Reserved.
#                    Łukasz Nowak <luke@nexedi.com>
#                    Romain Courteaud <romain@nexedi.com>
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
# as published by the Free Software Foundation; either version 2
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

from Acquisition import Implicit
from Products.ERP5Type.Tool.BaseTool import BaseTool
from AccessControl import ClassSecurityInfo, getSecurityManager, Unauthorized
from Products.ERP5Type.Globals import InitializeClass
from Products.ERP5Type import Permissions
from ComputedAttribute import ComputedAttribute
from zLOG import LOG, ERROR
import xml_marshaller
import json
import transaction

class WrongRequest(Exception):
  pass

def requireHeader(header_dict):
  def outer(fn):
    def wrapperRequireHeader(self, *args, **kwargs):
      problem_dict = {}
      for header, value in header_dict.iteritems():
        if self.REQUEST.getHeader(header) != value:
          problem_dict[header] = 'Header with value %r is required.' % value
      if not problem_dict:
        return fn(self, *args, **kwargs)
      else:
        self.REQUEST.response.setStatus(400)
        self.REQUEST.response.setBody(json.dumps(problem_dict))
        return self.REQUEST.response

    wrapperRequireHeader.__doc__ = fn.__doc__
    return wrapperRequireHeader
  return outer

def requireJson(json_dict):
  def outer(fn):
    def wrapperRequireJson(self, *args, **kwargs):
      self.REQUEST.stdin.seek(0)
      try:
        self.jbody = json.load(self.REQUEST.stdin)
      except Exception:
        self.REQUEST.response.setStatus(400)
        self.REQUEST.response.setBody(json.dumps(
          {'error': 'Data is not json object.'}))
        return self.REQUEST.response
      else:
        error_dict = {}
        for key, type_ in json_dict.iteritems():
          if key not in self.jbody:
            error_dict[key] = 'Missing.'
          elif not isinstance(self.jbody[key], type_):
            error_dict[key] = '%s is not %s.' % (type(self.jbody[key]).__name__,
              type_.__name__)
        if error_dict:
          self.REQUEST.response.setStatus(400)
          self.REQUEST.response.setBody(json.dumps(error_dict))
          return self.REQUEST.response
        return fn(self, *args, **kwargs)
    wrapperRequireJson.__doc__ = fn.__doc__
    return wrapperRequireJson
  return outer

def responseSupport(anonymous=False):
  def outer(fn):
    def wrapperResponseSupport(self, *args, **kwargs):
      response = self.REQUEST.response
      response.setHeader('Content-Type', 'application/json')
      response.setHeader('Access-Control-Allow-Headers',
        self.REQUEST.getHeader('Access-Control-Allow-Headers'))
      response.setHeader('Access-Control-Allow-Origin', '*')
      response.setHeader('Access-Control-Allow-Methods', 'DELETE, PUT, POST, '
        'GET, OPTIONS')
      if not anonymous and getSecurityManager().getUser().getId() is None:
        # force login
        response.setStatus(401)
        response.setHeader('WWW-Authenticate', 'Bearer realm="%s"'%
          self.absolute_url())
        response.setHeader('Location', self.getPortalObject()\
          .portal_preferences.getPreferredRestApiV1TokenServerUrl())
        return response
      return fn(self, *args, **kwargs)
    wrapperResponseSupport.__doc__ = fn.__doc__
    return wrapperResponseSupport
  return outer

def extractInstance(fn):
  def wrapperExtractInstance(self, *args, **kwargs):
    if not self.REQUEST['traverse_subpath']:
      self.REQUEST.response.setStatus(404)
      return self.REQUEST.response
    instance_path = self.REQUEST['traverse_subpath'][:2]
    try:
      self.software_instance = self.restrictedTraverse(instance_path)
      if getattr(self.software_instance, 'getPortalType', None) is None or \
        self.software_instance.getPortalType() not in ('Software Instance',
          'Slave Instance'):
        raise WrongRequest('%r is not an instance' % instance_path)
    except WrongRequest:
      LOG('VifibRestApiV1Tool', ERROR,
        'Problem while trying to find instance:', error=True)
      self.REQUEST.response.setStatus(404)
    except (Unauthorized, KeyError):
      self.REQUEST.response.setStatus(404)
    except Exception:
      LOG('VifibRestApiV1Tool', ERROR,
        'Problem while trying to find instance:', error=True)
      self.REQUEST.response.setStatus(500)
      self.REQUEST.response.setBody(json.dumps({'error':
        'There is system issue, please try again later.'}))
    else:
      self.REQUEST['traverse_subpath'] = self.REQUEST['traverse_subpath'][2:]
      return fn(self, *args, **kwargs)
    return self.REQUEST.response
  wrapperExtractInstance.__doc__ = fn.__doc__
  return wrapperExtractInstance
class GenericPublisher(Implicit):
  @responseSupport(True)
  def OPTIONS(self, *args, **kwargs):
    """HTTP OPTIONS implementation"""
    self.REQUEST.response.setStatus(204)
    return self.REQUEST.response

  def __before_publishing_traverse__(self, self2, request):
    path = request['TraversalRequestNameStack']
    subpath = path[:]
    path[:] = []
    subpath.reverse()
    request.set('traverse_subpath', subpath)

class InstancePublisher(GenericPublisher):
  """Instance publisher"""

  @requireHeader({'Accept': 'application/json',
    'Content-Type': 'application/json'})
  @requireJson(dict(log=unicode))
  @extractInstance
  def __bang(self):
    person = self.getPortalObject().ERP5Site_getAuthenticatedMemberPersonValue()
    if person is None:
      transaction.abort()
      LOG('VifibRestApiV1Tool', ERROR,
        'Currenty logged in user %r has no Person document.'%
          self.getPortalObject().getAuthenticatedMember())
      self.REQUEST.response.setStatus(500)
      self.REQUEST.response.setBody(json.dumps({'error':
        'There is system issue, please try again later.'}))
      return self.REQUEST.response
    try:
      self.software_instance.reportComputerPartitionBang(comment=self.jbody['log'])
    except Exception:
      LOG('VifibRestApiV1Tool', ERROR,
        'Problem while trying to generate instance dict:', error=True)
      self.REQUEST.response.setStatus(500)
      self.REQUEST.response.setBody(json.dumps({'error':
        'There is system issue, please try again later.'}))
    else:
      self.REQUEST.response.setStatus(204)
    return self.REQUEST.response

  @requireHeader({'Accept': 'application/json',
    'Content-Type': 'application/json'})
  @requireJson(dict(
    slave=bool,
    software_release=unicode,
    title=unicode,
    software_type=unicode,
    parameter=dict,
    sla=dict,
    status=unicode
  ))
  def __request(self):
    response = self.REQUEST.response
    person = self.getPortalObject().ERP5Site_getAuthenticatedMemberPersonValue()
    if person is None:
      transaction.abort()
      LOG('VifibRestApiV1Tool', ERROR,
        'Currenty logged in user %r has no Person document.'%
          self.getPortalObject().getAuthenticatedMember())
      response.setStatus(500)
      response.setBody(json.dumps({'error':
        'There is system issue, please try again later.'}))
      return response

    request_dict = {}
    for k_j, k_i in (
        ('software_release', 'software_release'),
        ('title', 'software_title'),
        ('software_type', 'software_type'),
        ('parameter', 'instance_xml'),
        ('sla', 'sla_xml'),
        ('slave', 'shared'),
        ('status', 'state')
      ):
      if k_j in ('sla', 'parameter'):
        request_dict[k_i] = xml_marshaller.xml_marshaller.dumps(
          self.jbody[k_j])
      else:
        request_dict[k_i] = self.jbody[k_j]

    try:
      person.requestSoftwareInstance(**request_dict)
    except Exception:
      transaction.abort()
      LOG('VifibRestApiV1Tool', ERROR,
        'Problem with person.requestSoftwareInstance:', error=True)
      response.setStatus(500)
      response.setBody(json.dumps({'error':
        'There is system issue, please try again later.'}))
      return response

    response.setStatus(202)
    response.setBody(json.dumps({'status':'processing'}))
    return response

  @requireHeader({'Accept': 'application/json'})
  @extractInstance
  def __instance_info(self):
    certificate = False
    if self.REQUEST['traverse_subpath'] and self.REQUEST[
        'traverse_subpath'][-1] == 'certificate':
      certificate = True
    try:
      if certificate:
        d = {
          "ssl_key": self.software_instance.getSslKey(),
          "ssl_certificate": self.software_instance.getSslCertificate()
        }
      else:
        d = {
          "title": self.software_instance.getTitle(),
          "status": self.software_instance.getSlapState(),
          "software_release": "", # not ready yet
          "software_type": self.software_instance.getSourceReference(),
          "slave": self.software_instance.getPortalType() == 'Slave Instance',
          "connection": self.software_instance.getConnectionXmlAsDict(),
          "parameter": self.software_instance.getInstanceXmlAsDict(),
          "sla": self.software_instance.getSlaXmlAsDict(),
          "children_list": [q.absolute_url() for q in \
            self.software_instance.getPredecessorValueList()],
          "partition": { # not ready yet
            "public_ip": [],
            "private_ip": [],
            "tap_interface": "",
          }
        }
    except Exception:
      LOG('VifibRestApiV1Tool', ERROR,
        'Problem while trying to generate instance dict:', error=True)
      self.REQUEST.response.setStatus(500)
      self.REQUEST.response.setBody(json.dumps({'error':
        'There is system issue, please try again later.'}))
    else:
      self.REQUEST.response.setStatus(200)
      self.REQUEST.response.setBody(json.dumps(d))
    return self.REQUEST.response

  @responseSupport()
  def __call__(self):
    """Instance GET/POST support"""
    if self.REQUEST['REQUEST_METHOD'] == 'POST':
      if self.REQUEST['traverse_subpath'] and \
        self.REQUEST['traverse_subpath'][-1] == 'bang':
        self.__bang()
      else:
        self.__request()
    elif self.REQUEST['REQUEST_METHOD'] == 'GET' and \
      self.REQUEST['traverse_subpath']:
      self.__instance_info()


class VifibRestApiV1Tool(BaseTool):
  """SlapOS REST API V1 Tool"""

  id = 'portal_vifib_rest_api_v1'
  meta_type = 'ERP5 Vifib Rest API V1 Tool'
  portal_type = 'Vifib Rest API V1 Tool'
  security = ClassSecurityInfo()
  security.declareObjectProtected(Permissions.AccessContentsInformation)
  allowed_types = ()

  security.declarePublic('instance')
  @ComputedAttribute
  def instance(self):
    """Instance publisher"""
    return InstancePublisher().__of__(self)

  security.declarePrivate('manage_afterAdd')
  def manage_afterAdd(self, item, container) :
    """Init permissions right after creation.

    Permissions in slap tool are simple:
     o Each member can access the tool.
     o Only manager can view and create.
     o Anonymous can not access
    """
    item.manage_permission(Permissions.AddPortalContent,
          ['Manager'])
    item.manage_permission(Permissions.AccessContentsInformation,
          ['Member', 'Manager'])
    item.manage_permission(Permissions.View,
          ['Manager',])
    BaseTool.inheritedAttribute('manage_afterAdd')(self, item, container)

InitializeClass(VifibRestApiV1Tool)
