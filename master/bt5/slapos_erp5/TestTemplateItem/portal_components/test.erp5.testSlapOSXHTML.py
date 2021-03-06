# -*- coding: utf-8 -*-
"""Tests all forms.
"""
import unittest

from Products.ERP5.tests import testXHTML
from Products.SlapOS.tests.testSlapOSMixin import \
  testSlapOSMixin
  
class TestSlapOSXHTML(testSlapOSMixin, testXHTML.TestXHTML):

  def afterSetUp(self):
    testSlapOSMixin.afterSetUp(self)
    # Live tests all uses the same request. For now we remove cell from
    # previous test that can cause problems in this test.
    self.portal.REQUEST.other.pop('cell', None)

def test_suite():
  from Products.ERP5 import ERP5Site
  portal_templates = ERP5Site.getSite().portal_templates
  dependency_list = portal_templates.getInstalledBusinessTemplate(
      "slapos_erp5").getTestDependencyList()
  bt5_list = [p[1] for p in portal_templates.resolveBusinessTemplateListDependency(
      dependency_list)]
  testXHTML.addTestMethodDynamically(
    TestSlapOSXHTML,
    testXHTML.validator,
    bt5_list)

  suite = unittest.TestSuite()
  suite.addTest(unittest.makeSuite(TestSlapOSXHTML))
  return suite