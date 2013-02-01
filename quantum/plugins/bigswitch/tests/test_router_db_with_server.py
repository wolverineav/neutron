# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Adapted from quantum.tests.unit.test_l3_plugin
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com
#

import logging
import os

import multiprocessing
from webob import exc

from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import api as db
from quantum.extensions import extensions
from quantum.extensions import l3
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
import quantum.plugins.bigswitch.tests.test_server as server
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.tests.unit import test_l3_plugin


LOG = logging.getLogger(__name__)


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class RouterDBTestCase(test_l3_plugin.L3NatDBTestCase):

    _ctrl = server.TestNetworkCtrl(port=8899,
                                   default_status='200 OK',
                                   default_response='{"status":"200 OK"}',
                                   debug=True)
    _ctrl.match(100, 'GET', '/test',
                lambda m, u, b, **k: ('200 OK', '["200 OK"]'))
    cntrl_proc = multiprocessing.Process(target=_ctrl.run, args=())
    cntrl_proc.daemon = True
    cntrl_proc.start()

    def setUp(self):

        super(RouterDBTestCase, self).setUp()

        db._ENGINE = None
        db._MAKER = None
        QuantumManager._instance = None
        extensions.PluginAwareExtensionManager._instance = None
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_config['config_files'] = [os.path.join(etc_path,
                                       'restproxy.ini.test')]
        test_config['plugin_name_v2'] = (
            'quantum.plugins.bigswitch.plugin.QuantumRestProxyV2')
        # for these tests we need to disable overlapping ips
        cfg.CONF.set_default('allow_overlapping_ips', False)
        ext_mgr = L3TestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        plugin = test_config.get('plugin_name_v2')
        args = ['--config-file', test_db_plugin.etcdir('quantum.conf.test')]
        # If test_config specifies some config-file, use it, as well
        for config_file in test_config.get('config_files', []):
            args.extend(['--config-file', config_file])
        config.parse(args=args)
        # Update the plugin
        cfg.CONF.set_override('core_plugin', plugin)
        self.api = APIRouter()

        ext_mgr = test_config.get('extension_manager', None)
        if ext_mgr:
            self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_router_remove_router_interface_wrong_subnet_returns_409(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.subnet(cidr='10.0.10.0/24') as s1:
                    with self.port(subnet=s1, no_delete=True) as p:
                        self._router_interface_action('add',
                                                      r['router']['id'],
                                                      None,
                                                      p['port']['id'])
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s['subnet']['id'],
                                                      p['port']['id'],
                                                      exc.HTTPConflict.code)
                        #remove properly to clean-up
                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      None,
                                                      p['port']['id'])

    def test_router_remove_router_interface_wrong_port_returns_404(self):
        with self.router() as r:
            with self.subnet() as s:
                with self.port(subnet=s, no_delete=True) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # create another port for testing failure case
                    res = self._create_port('json', p['port']['network_id'])
                    p2 = self.deserialize('json', res)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p2['port']['id'],
                                                  exc.HTTPNotFound.code)
                    # remove correct interface to cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    # remove extra port created
                    self._delete('ports', p2['port']['id'])

    def test_create_floatingip_no_ext_gateway_return_404(self):
        with self.subnet(cidr='10.0.10.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as private_port:
                with self.router() as r:
                    res = self._create_floatingip(
                        'json',
                        public_sub['subnet']['network_id'],
                        port_id=private_port['port']['id'])
                    # this should be some kind of error
                    self.assertEqual(res.status_int, exc.HTTPNotFound.code)

    def test_router_update_gateway(self):
        with self.router() as r:
            with self.subnet() as s1:
                with self.subnet(cidr='10.0.10.0/24') as s2:
                    self._set_net_external(s1['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s1['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEquals(net_id, s1['subnet']['network_id'])
                    self._set_net_external(s2['subnet']['network_id'])
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    net_id = (body['router']
                              ['external_gateway_info']['network_id'])
                    self.assertEquals(net_id, s2['subnet']['network_id'])
                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s2['subnet']['network_id'])

    def test_router_add_interface_overlapped_cidr(self):
        self.skipTest("Plugin does not support")

    def test_list_nets_external(self):
        self.skipTest("Plugin does not support")

    def test_router_update_gateway_with_existed_floatingip(self):
        self.skipTest("Plugin does not support")

    def tearDown(self):
        super(RouterDBTestCase, self).tearDown()

    def test_send_data(self):
        ctx = context.Context(None, None, is_admin=True)
        fmt='json'
        plugin_obj = QuantumManager.get_plugin()
        with self.router() as r:
            with self.subnet(cidr='10.0.10.0/24') as s:
                with self.router() as r1:
                    with self.subnet(cidr='10.0.20.0/24') as s1:
                        self._router_interface_action('add',
                                                      r1['router']['id'],
                                                      s1['subnet']['id'],
                                                      None)
                        body = self._router_interface_action('add',
                                                             r['router']['id'],
                                                             s['subnet']['id'],
                                                             None)
                        self.assertTrue('port_id' in body)

                        r_port_id = body['port_id']
                        body = self._show('ports', r_port_id)
                        self.assertEquals(body['port']['device_id'],
                                          r['router']['id'])

                        with self.subnet(cidr='11.0.0.0/24') as public_sub:
                            self._set_net_external(public_sub['subnet']['network_id'])
                            with self.port() as private_port:
                                sid = private_port['port']['fixed_ips'][0]['subnet_id']
                                private_sub = {'subnet': {'id': sid}}
                                self._add_external_gateway_to_router(
                                        r['router']['id'],
                                        public_sub['subnet']['network_id'])
                                self._router_interface_action('add', r['router']['id'],
                                                              private_sub['subnet']['id'],
                                                              None)

                                res = self._create_floatingip(
                                                fmt,
                                                public_sub['subnet']['network_id'],
                                                port_id=private_port['port']['id'])
                                self.assertEqual(res.status_int, exc.HTTPCreated.code)
                                floatingip = self.deserialize(fmt, res)

                                result = plugin_obj._send_all_data()
                                self.assertEquals(result[0], 200)

                                self._delete('floatingips', floatingip['floatingip']['id'])
                                self._remove_external_gateway_from_router(
                                            r['router']['id'],
                                            public_sub['subnet']['network_id'])
                                self._router_interface_action('remove',
                                                              r['router']['id'],
                                                              private_sub['subnet']['id'],
                                                              None)

                        self._router_interface_action('remove',
                                                      r['router']['id'],
                                                      s['subnet']['id'],
                                                      None)
                        self._show('ports',
                                   r_port_id,
                                   expected_code=exc.HTTPNotFound.code)
                        self._router_interface_action('remove',
                                                      r1['router']['id'],
                                                      s1['subnet']['id'],
                                                      None)
