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
import mock

from quantum import context
from quantum.extensions import firewall
from quantum.plugins.common import constants as const
from quantum.services.firewall import fwaas_plugin
from quantum.tests import base
from quantum.tests.unit.db.firewall import test_db_firewall


FW_PLUGIN_KLASS = (
    "quantum.services.firewall.fwaas_plugin.FirewallPlugin"
)


class TestFirewallCallbacks(test_db_firewall.FirewallPluginDbTestCase):

    def setUp(self):
        super(TestFirewallCallbacks,
              self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.callbacks

    def test_set_firewall_status(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=
                               self._admin_state_up) as fw:
                fw_id = fw['firewall']['id']
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         const.ACTIVE)
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.ACTIVE)
                self.assertTrue(res)
                res = self.callbacks.set_firewall_status(ctx, fw_id,
                                                         const.ERROR)
                fw_db = self.plugin.get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.ERROR)
                self.assertTrue(res)

    def test_firewall_deleted(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=self._admin_state_up,
                               no_delete=True) as fw:
                fw_id = fw['firewall']['id']
                with ctx.session.begin(subtransactions=True):
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    fw_db['status'] = const.PENDING_DELETE
                    ctx.session.flush()
                    res = self.callbacks.firewall_deleted(ctx, fw_id)
                    self.assertTrue(res)
                    self.assertRaises(firewall.FirewallNotFound,
                                      self.plugin.get_firewall,
                                      ctx, fw_id)

    def test_firewall_deleted_error(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=self._admin_state_up,
                               no_delete=True) as fw:
                fw_id = fw['firewall']['id']
                res = self.callbacks.firewall_deleted(ctx, fw_id)
                self.assertFalse(res)
                fw_db = self.plugin._get_firewall(ctx, fw_id)
                self.assertEqual(fw_db['status'], const.ERROR)


class TestFirewallAgentApi(base.BaseTestCase):
    def setUp(self):
        super(TestFirewallAgentApi, self).setUp()
        self.addCleanup(mock.patch.stopall)

        self.api = fwaas_plugin.FirewallAgentApi('topic', 'host')
        self.mock_fanoutcast = mock.patch.object(self.api,
                                                 'fanout_cast').start()
        self.mock_msg = mock.patch.object(self.api, 'make_msg').start()

    def test_init(self):
        self.assertEqual(self.api.topic, 'topic')
        self.assertEqual(self.api.host, 'host')

    def _call_test_helper(self, method_name):
        rv = getattr(self.api, method_name)(mock.sentinel.context, 'test')
        self.assertEqual(rv, self.mock_fanoutcast.return_value)
        self.mock_fanoutcast.assert_called_once_with(
            mock.sentinel.context,
            self.mock_msg.return_value,
            topic='topic'
        )

        self.mock_msg.assert_called_once_with(
            method_name,
            firewall='test',
            host='host'
        )

    def test_create_firewall(self):
        self._call_test_helper('create_firewall')

    def test_update_firewall(self):
        self._call_test_helper('update_firewall')

    def test_delete_firewall(self):
        self._call_test_helper('delete_firewall')


class TestFirewallPluginBase(test_db_firewall.TestFirewallDBPlugin):

    def setUp(self):
        super(TestFirewallPluginBase, self).setUp(fw_plugin=FW_PLUGIN_KLASS)
        self.callbacks = self.plugin.callbacks

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
                keys = self._replace_firewall_status(keys,
                                                     const.PENDING_CREATE,
                                                     const.PENDING_UPDATE)
                for k, v in keys:
                    self.assertEqual(res['firewall'][k], v)

    def test_delete_firewall(self):
        ctx = context.get_admin_context()
        keys = self._get_test_firewall_attrs()

        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            keys.append(('firewall_policy_id', fwp_id))
            with self.firewall(firewall_policy_id=fwp_id,
                               admin_state_up=
                               self._admin_state_up) as firewall:
                fw_id = firewall['firewall']['id']
                keys = self._replace_firewall_status(keys,
                                                     const.PENDING_CREATE,
                                                     const.PENDING_DELETE)
                req = self.new_delete_request('firewalls', fw_id)
                req.get_response(self.ext_api)
                fw_db = self.plugin._get_firewall(ctx, fw_id)
                for k, v in keys:
                    self.assertEqual(fw_db[k], v)

    def test_delete_firewall_after_agent_delete(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
            with self.firewall(firewall_policy_id=fwp_id,
                               no_delete=True) as fw:
                fw_id = fw['firewall']['id']
                with ctx.session.begin(subtransactions=True):
                    fw_db = self.plugin._get_firewall(ctx, fw_id)
                    fw_db['status'] = const.PENDING_DELETE
                    ctx.session.flush()
                    req = self.new_delete_request('firewalls', fw_id)
                    res = req.get_response(self.ext_api)
                    self.assertEqual(res.status_int, 204)
                    self.assertRaises(firewall.FirewallNotFound,
                                      self.plugin.get_firewall,
                                      ctx, fw_id)

    def test_make_firewall_dict_with_in_place_rules(self):
        ctx = context.get_admin_context()
        with self.firewall_policy(no_delete=True) as fwp:
            fwp_id = fwp['firewall_policy']['id']
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
                data = {'firewall_policy':
                        {'firewall_rules_list': fw_rule_ids}}
                self.new_update_request('firewall_policies', data, fwp_id)
                keys = self._get_test_firewall_attrs()
                keys.append(('firewall_policy_id', fwp_id))
                with self.firewall(firewall_policy_id=fwp_id,
                                   admin_state_up=
                                   self._admin_state_up,
                                   no_delete=True) as fw:
                    fw_id = fw['firewall']['id']
                    fw_rules = (
                        self.plugin._make_firewall_dict_with_rules(ctx,
                                                                   fw_id)
                    )
                    self.assertEqual(fw_rules['id'], fw_id)
                    for r1, r2 in zip(fr, fw_rules['firewall_rules_list']):
                        rule = r1['firewall_rule']
                        for k in rule:
                            self.assertEqual(rule[k], r2[k])
