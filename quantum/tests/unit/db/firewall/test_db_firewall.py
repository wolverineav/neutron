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


import contextlib
import logging
import os

import webob.exc

from quantum.api.extensions import ExtensionMiddleware
from quantum.api.extensions import PluginAwareExtensionManager
from quantum.common import config
from quantum.db.firewall import firewall_db as fdb
import quantum.extensions
from quantum.extensions import firewall
from quantum.openstack.common import importutils
from quantum.plugins.common import constants
from quantum.tests.unit import test_db_plugin


LOG = logging.getLogger(__name__)
DB_FW_PLUGIN_KLASS = (
    "quantum.db.firewall.firewall_db.Firewall_db_mixin"
)
ROOTDIR = os.path.dirname(__file__) + '../../../..'
ETCDIR = os.path.join(ROOTDIR, 'etc')
extensions_path = ':'.join(quantum.extensions.__path__)
SHARED = True
PROTOCOL = 'tcp'
SOURCE_IP_ADDRESS_RAW = '1.1.1.1'
DESTINATION_IP_ADDRESS_RAW = '2.2.2.2'
SOURCE_PORT = 5000
DESTINATION_PORT = 6000
ACTION = 'allow'
AUDITED = True
ENABLED = True
ADMIN_STATE_UP = True


def etcdir(*p):
    return os.path.join(ETCDIR, *p)


class FirewallPluginDbTestCase(test_db_plugin.QuantumDbPluginV2TestCase):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.FIREWALL])
        for k in firewall.RESOURCE_ATTRIBUTE_MAP.keys()
    )
    resource_prefix_map['firewalls'] = ''

    def setUp(self, core_plugin=None, fw_plugin=None):
        if not fw_plugin:
            fw_plugin = DB_FW_PLUGIN_KLASS
        service_plugins = {'fw_plugin_name': fw_plugin}

        fdb.Firewall_db_mixin.supported_extension_aliases = ["fwaas"]
        super(FirewallPluginDbTestCase, self).setUp(
            service_plugins=service_plugins
        )

        self.plugin = fdb.Firewall_db_mixin()
        ext_mgr = PluginAwareExtensionManager(
            extensions_path,
            {constants.FIREWALL: self.plugin}
        )
        self.plugin = importutils.import_object(fw_plugin)
        ext_mgr = PluginAwareExtensionManager(
            extensions_path,
            {constants.FIREWALL: self.plugin}
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self._shared = SHARED
        self._protocol = PROTOCOL
        self._source_ip_address_raw = SOURCE_IP_ADDRESS_RAW
        self._destination_ip_address_raw = DESTINATION_IP_ADDRESS_RAW
        self._source_port = SOURCE_PORT
        self._destination_port = DESTINATION_PORT
        self._action = ACTION
        self._audited = AUDITED
        self._enabled = ENABLED
        self._admin_state_up = ADMIN_STATE_UP

    def _test_list_resources(self, resource, items,
                             quantum_context=None,
                             query_params=None):
        if resource.endswith('y'):
            resource_plural = resource.replace('y', 'ies')
        else:
            resource_plural = resource + 's'

        res = self._list(resource_plural,
                         quantum_context=quantum_context,
                         query_params=query_params)
        resource = resource.replace('-', '_')
        self.assertEqual(sorted([i['id'] for i in res[resource_plural]]),
                         sorted([i[resource]['id'] for i in items]))

    def _get_test_firewall_rule_attrs(self, name='firewall_rule1'):
        keys = [('name', name),
                ('tenant_id', self._tenant_id),
                ('shared', self._shared),
                ('protocol', self._protocol),
                ('source_ip_address', self._source_ip_address_raw),
                ('destination_ip_address', self._destination_ip_address_raw),
                ('source_port', self._source_port),
                ('destination_port', self._destination_port),
                ('action', self._action),
                ('enabled', self._enabled)]
        return keys

    def _get_test_firewall_policy_attrs(self, name='firewall_policy1'):
        keys = [('name', name),
                ('tenant_id', self._tenant_id),
                ('shared', self._shared),
                ('firewall_rules_list', []),
                ('audited', self._audited)]
        return keys

    def _get_test_firewall_attrs(self, name='firewall_1'):
        keys = [('name', name),
                ('tenant_id', self._tenant_id),
                ('admin_state_up', self._admin_state_up),
                ('status', 'PENDING_CREATE')]

        return keys

    def _create_firewall_policy(self, fmt, name, shared, firewall_rules_list,
                                audited, expected_res_status=None, **kwargs):
        data = {'firewall_policy': {'name': name,
                                    'tenant_id': self._tenant_id,
                                    'shared': shared,
                                    'firewall_rules_list': firewall_rules_list,
                                    'audited': audited}}
        if 'description' in kwargs and kwargs['description'] is not None:
            data['firewall_policy']['description'] = kwargs['description']

        fw_policy_req = self.new_create_request('firewall_policies', data, fmt)
        fw_policy_res = fw_policy_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(fw_policy_res.status_int, expected_res_status)

        return fw_policy_res

    def _replace_firewall_status(self, kvpairs, old_status, new_status):
        return [('status',
                 new_status) if (x == ('status',
                                       old_status)) else x for x in kvpairs]

    @contextlib.contextmanager
    def firewall_policy(self, fmt=None, name='firewall_policy1', shared=True,
                        firewall_rules_list=None, audited=True,
                        no_delete=False, **kwargs):
        if firewall_rules_list is None:
            firewall_rules_list = []
        if not fmt:
            fmt = self.fmt
        res = self._create_firewall_policy(fmt, name, shared,
                                           firewall_rules_list, audited,
                                           **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        firewall_policy = self.deserialize(fmt or self.fmt, res)
        try:
            yield firewall_policy
        finally:
            if not no_delete:
                self._delete('firewall_policies',
                             firewall_policy['firewall_policy']['id'])

    def _create_firewall_rule(self, fmt, name, shared, protocol,
                              source_ip_address, destination_ip_address,
                              source_port, destination_port, action, enabled,
                              expected_res_status=None, **kwargs):
        data = {'firewall_rule': {'name': name,
                                  'tenant_id': self._tenant_id,
                                  'shared': shared,
                                  'protocol': protocol,
                                  'source_ip_address': source_ip_address,
                                  'destination_ip_address':
                                  destination_ip_address,
                                  'source_port': source_port,
                                  'destination_port': destination_port,
                                  'action': action,
                                  'enabled': enabled}}
        if 'description' in kwargs and kwargs['description'] is not None:
            data['firewall_rule']['description'] = kwargs['description']

        fw_rule_req = self.new_create_request('firewall_rules', data, fmt)
        fw_rule_res = fw_rule_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(fw_rule_res.status_int, expected_res_status)

        return fw_rule_res

    @contextlib.contextmanager
    def firewall_rule(self, fmt=None, name='firewall_rule1', shared=SHARED,
                      protocol=PROTOCOL,
                      source_ip_address=SOURCE_IP_ADDRESS_RAW,
                      destination_ip_address=DESTINATION_IP_ADDRESS_RAW,
                      source_port=SOURCE_PORT,
                      destination_port=DESTINATION_PORT,
                      action=ACTION, enabled=ENABLED,
                      no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_firewall_rule(fmt, name, shared, protocol,
                                         source_ip_address,
                                         destination_ip_address,
                                         source_port, destination_port,
                                         action, enabled, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        firewall_rule = self.deserialize(fmt or self.fmt, res)
        try:
            yield firewall_rule
        finally:
            if not no_delete:
                self._delete('firewall_rules',
                             firewall_rule['firewall_rule']['id'])

    def _create_firewall(self, fmt, name, firewall_policy_id,
                         admin_state_up=True, expected_res_status=None,
                         **kwargs):
        data = {'firewall': {'name': name,
                             'firewall_policy_id': firewall_policy_id,
                             'admin_state_up': admin_state_up,
                             'tenant_id': self._tenant_id}}
        if 'description' in kwargs and kwargs['description'] is not None:
            data['firewall']['description'] = kwargs['description']

        firewall_req = self.new_create_request('firewalls', data, fmt)
        firewall_res = firewall_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(firewall_res.status_int, expected_res_status)

        return firewall_res

    @contextlib.contextmanager
    def firewall(self, fmt=None, name='firewall_1', firewall_policy_id=None,
                 admin_state_up=True, no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_firewall(fmt,
                                    name,
                                    firewall_policy_id,
                                    admin_state_up,
                                    **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        firewall = self.deserialize(fmt or self.fmt, res)
        try:
            yield firewall
        finally:
            if not no_delete:
                self._delete('firewalls', firewall['firewall']['id'])


class TestFirewallDBPlugin(FirewallPluginDbTestCase):

    def test_create_firewall_policy(self):
        name = "firewall_policy1"
        keys = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(name=name, shared=self._shared,
                                  firewall_rules_list=None,
                                  audited=self._audited) as firewall_policy:
            for k, v in keys:
                self.assertEqual(firewall_policy['firewall_policy'][k], v)

    def test_create_firewall_policy_with_rules(self):
        name = "firewall_policy1"
        keys = self._get_test_firewall_policy_attrs(name)

        with contextlib.nested(self.firewall_rule(name='fwr1',
                                                  description='fwr',
                                                  no_delete=True),
                               self.firewall_rule(name='fwr2',
                                                  description='fwr',
                                                  no_delete=True),
                               self.firewall_rule(name='fwr3',
                                                  description='fwr',
                                                  no_delete=True)) as fr:
            fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
            keys = [('firewall_rules_list',
                     fw_rule_ids) if (x == ('firewall_rules_list',
                                            [])) else x for x in keys]
            with self.firewall_policy(name=name, shared=self._shared,
                                      firewall_rules_list=fw_rule_ids,
                                      audited=self._audited,
                                      no_delete=True) as fwp:
                for k, v in keys:
                    self.assertEqual(fwp['firewall_policy'][k], v)

    def test_show_firewall_policy(self):
        name = "firewall_policy1"
        keys = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(name=name, shared=self._shared,
                                  firewall_rules_list=None,
                                  audited=self._audited) as fwp:
            req = self.new_show_request('firewall_policies',
                                        fwp['firewall_policy']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['firewall_policy'][k], v)

    def test_list_firewall_policies(self):
        with contextlib.nested(self.firewall_policy(name='fwp1',
                                                    description='fwp'),
                               self.firewall_policy(name='fwp2',
                                                    description='fwp'),
                               self.firewall_policy(name='fwp3',
                                                    description='fwp')
                               ) as fw_policies:
            self._test_list_resources('firewall_policy',
                                      fw_policies,
                                      query_params='description=fwp')

    def test_update_firewall_policy(self):
        name = "new_firewall_policy1"
        keys = self._get_test_firewall_policy_attrs(name)

        with self.firewall_policy(shared=self._shared,
                                  firewall_rules_list=None,
                                  audited=self._audited) as fwp:
            data = {'firewall_policy': {'name': name}}
            req = self.new_update_request('firewall_policies', data,
                                          fwp['firewall_policy']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_policy_with_rules(self):
        keys = self._get_test_firewall_policy_attrs()

        with self.firewall_policy() as fwp:
            with contextlib.nested(self.firewall_rule(name='fwr1',
                                                      description='fwr',
                                                      no_delete=True),
                                   self.firewall_rule(name='fwr2',
                                                      description='fwr',
                                                      no_delete=True),
                                   self.firewall_rule(name='fwr3',
                                                      description='fwr',
                                                      no_delete=True)) as fr:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                keys = [('firewall_rules_list',
                         fw_rule_ids) if (x == ('firewall_rules_list',
                                                [])) else x for x in keys]
                data = {'firewall_policy':
                        {'firewall_rules_list': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['firewall_policy'][k], v)

    def test_update_firewall_policy_with_non_existing_rule(self):
        keys = self._get_test_firewall_policy_attrs()

        with self.firewall_policy() as fwp:
            with contextlib.nested(self.firewall_rule(name='fwr1',
                                                      description='fwr',
                                                      no_delete=True),
                                   self.firewall_rule(name='fwr2',
                                                      description='fwr',
                                                      no_delete=True)) as fr:
                fw_rule_ids = [r['firewall_rule']['id'] for r in fr]
                fw_rule_ids.append('12345')  # non-existent rule
                data = {'firewall_policy':
                        {'firewall_rules_list': fw_rule_ids}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                res = req.get_response(self.ext_api)
                #check that the firewall_rule was not found
                self.assertEqual(res.status_int, 404)
                #check if none of the rules got added to the policy
                req = self.new_show_request('firewall_policies',
                                            fwp['firewall_policy']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['firewall_policy'][k], v)

    def test_delete_firewall_policy(self):
        with self.firewall_policy(no_delete=True) as fwp:
            req = self.new_delete_request('firewall_policies',
                                          fwp['firewall_policy']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_delete_firewall_policy_with_firewall_association(self):
        keys = self._get_test_firewall_attrs()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            keys.append(('firewall_policy_id', fwp_id))
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=
                               self._admin_state_up):
                req = self.new_delete_request('firewall_policies', fwp_id)
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 409)

    def test_create_firewall_rule(self):
        name = "firewall_rule1"
        keys = self._get_test_firewall_rule_attrs(name)

        with self.firewall_rule(name=name, shared=self._shared,
                                protocol=self._protocol,
                                source_ip_address=
                                self._source_ip_address_raw,
                                destination_ip_address=
                                self._destination_ip_address_raw,
                                source_port=self._source_port,
                                destination_port=self._destination_port,
                                action=self._action,
                                enabled=self._enabled) as firewall_rule:
            for k, v in keys:
                self.assertEqual(firewall_rule['firewall_rule'][k], v)

    def test_show_firewall_rule_with_fw_policy_not_associated(self):
        name = "firewall_rule1"
        keys = self._get_test_firewall_rule_attrs(name)
        with self.firewall_rule(name=name, shared=self._shared,
                                protocol=self._protocol,
                                source_ip_address=
                                self._source_ip_address_raw,
                                destination_ip_address=
                                self._destination_ip_address_raw,
                                source_port=self._source_port,
                                destination_port=self._destination_port,
                                action=self._action,
                                enabled=self._enabled) as fw_rule:
            req = self.new_show_request('firewall_rules',
                                        fw_rule['firewall_rule']['id'],
                                        fmt=self.fmt)
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['firewall_rule'][k], v)

    def test_show_firewall_rule_with_fw_policy_associated(self):
        name = "firewall_rule1"
        keys = self._get_test_firewall_rule_attrs(name)
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            keys.append(('firewall_policy_id', fwp_id))
            with self.firewall_rule(name=name, shared=self._shared,
                                    protocol=self._protocol,
                                    source_ip_address=
                                    self._source_ip_address_raw,
                                    destination_ip_address=
                                    self._destination_ip_address_raw,
                                    source_port=self._source_port,
                                    destination_port=self._destination_port,
                                    action=self._action,
                                    enabled=self._enabled,
                                    no_delete=True) as fw_rule:
                data = {'firewall_policy':
                        {'firewall_rules_list':
                         [fw_rule['firewall_rule']['id']]}}
                req = self.new_update_request('firewall_policies', data,
                                              fwp['firewall_policy']['id'])
                req.get_response(self.ext_api)
                req = self.new_show_request('firewall_rules',
                                            fw_rule['firewall_rule']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['firewall_rule'][k], v)

    def test_list_firewall_rules(self):
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with contextlib.nested(self.firewall_rule(name='fwr1',
                                                      firewall_policy_id=
                                                      fwp_id,
                                                      description='fwr',
                                                      no_delete=True),
                                   self.firewall_rule(name='fwr2',
                                                      firewall_policy_id=
                                                      fwp_id,
                                                      description='fwr',
                                                      no_delete=True),
                                   self.firewall_rule(name='fwr3',
                                                      firewall_policy_id=
                                                      fwp_id,
                                                      description='fwr',
                                                      no_delete=True)) as fr:
                self._test_list_resources('firewall_rule', fr,
                                          query_params='description=fwr')

    def test_update_firewall_rule(self):
        name = "new_firewall_rule1"
        keys = self._get_test_firewall_rule_attrs(name)

        with self.firewall_rule(no_delete=True) as fwr:
            data = {'firewall_rule': {'name': name}}
            req = self.new_update_request('firewall_rules', data,
                                          fwr['firewall_rule']['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.ext_api))
            for k, v in keys:
                self.assertEqual(res['firewall_rule'][k], v)

    def test_delete_firewall_rule(self):
        with self.firewall_rule(no_delete=True) as fwr:
            req = self.new_delete_request('firewall_rules',
                                          fwr['firewall_rule']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)

    def test_create_firewall(self):
        name = "firewall1"
        keys = self._get_test_firewall_attrs(name)

        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            keys.append(('firewall_policy_id', fwp_id))
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               admin_state_up=
                               self._admin_state_up) as firewall:
                for k, v in keys:
                    self.assertEqual(firewall['firewall'][k], v)

    def test_show_firewall(self):
        name = "firewall1"
        keys = self._get_test_firewall_attrs(name)

        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            keys.append(('firewall_policy_id', fwp_id))
            with self.firewall(name=name,
                               firewall_policy_id=fwp_id,
                               admin_state_up=
                               self._admin_state_up) as firewall:
                req = self.new_show_request('firewalls',
                                            firewall['firewall']['id'],
                                            fmt=self.fmt)
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['firewall'][k], v)

    def test_list_firewalls(self):
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with contextlib.nested(self.firewall(name='fw1',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw'),
                                   self.firewall(name='fw2',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw'),
                                   self.firewall(name='fw3',
                                                 firewall_policy_id=fwp_id,
                                                 description='fw')) as fwalls:
                self._test_list_resources('firewall', fwalls,
                                          query_params='description=fw')

    def test_update_firewall(self):
        name = "new_firewall1"
        keys = self._get_test_firewall_attrs(name)

        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            keys.append(('firewall_policy_id', fwp_id))
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=
                               self._admin_state_up) as firewall:
                data = {'firewall': {'name': name}}
                req = self.new_update_request('firewalls', data,
                                              firewall['firewall']['id'])
                res = self.deserialize(self.fmt,
                                       req.get_response(self.ext_api))
                for k, v in keys:
                    self.assertEqual(res['firewall'][k], v)

    def test_delete_firewall(self):
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               no_delete=True) as firewall:
                req = self.new_delete_request('firewalls',
                                              firewall['firewall']['id'])
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)


class TestFirewallDBPluginXML(TestFirewallDBPlugin):
    fmt = 'xml'

    def test_show_firewall_rule_with_fw_policy_associated(self):
        #TODO(Sumit): XML formatting does not seem to be handling lists
        # correctly, hence skipping this test for now
        pass

    def test_update_firewall_policy_with_rules(self):
        #TODO(Sumit): XML formatting does not seem to be handling lists
        # correctly, hence skipping this test for now
        pass

    def test_create_firewall_policy_with_rules(self):
        #TODO(Sumit): XML formatting does not seem to be handling lists
        # correctly, hence skipping this test for now
        pass
