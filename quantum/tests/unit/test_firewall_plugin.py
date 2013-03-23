# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the spec
#
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

import copy

import mock
from oslo.config import cfg
from webob import exc
import webtest

from quantum.api import extensions
from quantum.api.v2 import attributes
from quantum.common import config
from quantum.extensions import firewall
from quantum import manager
from quantum.openstack.common import uuidutils
from quantum.plugins.common import constants
from quantum.tests import base
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_extensions
from quantum.tests.unit import testlib_api


_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class FirewallTestExtensionManager(object):

    def get_resources(self):
        return firewall.Firewall.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class FirewallExtensionTestCase(testlib_api.WebTestCase):
    fmt = 'json'

    def setUp(self):
        super(FirewallExtensionTestCase, self).setUp()
        plugin = 'quantum.extensions.firewall.FirewallPluginBase'
        # Ensure 'stale' patched copies of the plugin are never returned
        manager.QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Create the default configurations
        args = ['--config-file', test_api_v2.etcdir('quantum.conf.test')]
        config.parse(args)

        # Stubbing core plugin with Firewall plugin
        cfg.CONF.set_override('core_plugin', plugin)
        cfg.CONF.set_override('service_plugins', [plugin])

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()
        instance = self.plugin.return_value
        instance.get_plugin_type.return_value = constants.FIREWALL

        ext_mgr = FirewallTestExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)
        super(FirewallExtensionTestCase, self).setUp()

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None
        cfg.CONF.reset()
        super(FirewallExtensionTestCase, self).tearDown()

    def _test_entity_delete(self, entity):
        """ does the entity deletion based on naming convention  """
        entity_id = _uuid()
        res = self.api.delete(_get_path('firewall/' + entity + 's',
                                        id=entity_id, fmt=self.fmt))
        delete_entity = getattr(self.plugin.return_value, "delete_" + entity)
        delete_entity.assert_called_with(mock.ANY, entity_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

    def test_create_firewall_rule(self):
        rule_id = _uuid()
        data = {'firewall_rule': {'description': 'descr_firewall_rule1',
                                  'direction': 'ingress',
                                  'protocol': 'tcp',
                                  'source_ip_address': '192.168.0.1',
                                  'destination_ip_address': '127.0.0.1',
                                  'port_range_min': 1,
                                  'port_range_max': 65000,
                                  'application': 'app',
                                  'action': 'allow',
                                  'dynamic_attributes': '',
                                  'tenant_id': _uuid()}}
        return_value = copy.copy(data['firewall_rule'])
        return_value.update({'id': rule_id})

        instance = self.plugin.return_value
        instance.create_firewall_rule.return_value = return_value
        res = self.api.post(_get_path('firewall/firewall_rules', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_firewall_rule.assert_called_with(mock.ANY,
                                                         firewall_rule=data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('firewall_rule', res)
        self.assertEqual(res['firewall_rule'], return_value)

    def test_firewall_rule_list(self):
        rule_id = _uuid()
        return_value = [{'tenant_id': _uuid(),
                         'id': rule_id}]

        instance = self.plugin.return_value
        instance.get_firewall_rules.return_value = return_value

        res = self.api.get(_get_path('firewall/firewall_rules', fmt=self.fmt))

        instance.get_firewall_rules.assert_called_with(mock.ANY,
                                                       fields=mock.ANY,
                                                       filters=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)

    def test_firewall_rule_get(self):
        rule_id = _uuid()
        return_value = {'tenant_id': _uuid(),
                        'id': rule_id}

        instance = self.plugin.return_value
        instance.get_firewall_rule.return_value = return_value

        res = self.api.get(_get_path('firewall/firewall_rules',
                                     id=rule_id, fmt=self.fmt))

        instance.get_firewall_rule.assert_called_with(mock.ANY,
                                                      rule_id,
                                                      fields=mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('firewall_rule', res)
        self.assertEqual(res['firewall_rule'], return_value)

    def test_firewall_rule_update(self):
        rule_id = _uuid()
        update_data = {'firewall_rule': {'action': 'deny'}}
        return_value = {'tenant_id': _uuid(),
                        'id': rule_id}

        instance = self.plugin.return_value
        instance.update_firewall_rule.return_value = return_value

        res = self.api.put(_get_path('firewall/firewall_rules', id=rule_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_firewall_rule.assert_called_with(mock.ANY,
                                                         rule_id,
                                                         firewall_rule=
                                                         update_data)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('firewall_rule', res)
        self.assertEqual(res['firewall_rule'], return_value)

    def test_firewall_rule_delete(self):
        self._test_entity_delete('firewall_rule')


class FirewallExtensionTestCaseXML(FirewallExtensionTestCase):
    fmt = 'xml'
