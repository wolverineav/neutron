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

import ast
import json
from jsonschema import Validator
from mock import patch
from webob import exc

from quantum.api.extensions import PluginAwareExtensionManager
from quantum.api.v2.router import APIRouter
from quantum.common import config
from quantum.common.test_lib import test_config
from quantum import context
from quantum.db import api as db
from quantum.extensions import l3
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum.tests.unit import test_db_plugin
from quantum.tests.unit import test_extensions
from quantum.tests.unit import test_l3_plugin
from quantum.tests.unit.bigswitch import test_restproxy_plugin


LOG = logging.getLogger(__name__)


class HTTPResponseMock():
    status = 200
    reason = 'OK'

    def __init__(self, sock, debuglevel=0, strict=0, method=None,
                 buffering=False):
        pass

    def read(self):
        return "{'status': '200 OK'}"


class HTTPConnectionMock():

    def __init__(self, server, port, timeout):
        self._validator = Validator()
        pass

    def request(self, action, uri, body, headers):
        if uri is not '/quantum/v1.1/topology':
            return
        schema = {"type":"object","$schema": "http://json-schema.org/draft-03/schema","id": "#","required":true,"properties":{ "networks": { "type":"array", "id": "networks", "required":true, "items": { "type":"object", "id": "0", "required":false, "properties":{ "gateway": { "type":"string", "id": "gateway", "required":true }, "id": { "type":"string", "id": "id", "required":true }, "name": { "type":"string", "id": "name", "required":true }, "ports": { "type":"array", "id": "ports", "required":false, "items": { "type":"object", "id": "0", "required":false, "properties":{ "attachment": { "type":"object", "id": "attachment", "required":false, "properties":{ "id": { "type":"string", "id": "id", "required":true }, "mac": { "type":"string", "id": "mac", "required":true } } }, "device_id": { "type":"string", "id": "device_id", "required":false }, "device_owner": { "type":"string", "id": "device_owner", "required":false }, "fixed_ips": { "type":"array", "id": "fixed_ips", "required":true, "items": { "type":"object", "id": "0", "required":false, "properties":{ "ip_address": { "type":"string", "id": "ip_address", "required":false }, "subnet_id": { "type":"string", "id": "subnet_id", "required":false } } } }, "id": { "type":"string", "id": "id", "required":true }, "mac_address": { "type":"string", "id": "mac_address", "required":false }, "name": { "type":"string", "id": "name", "required":false }, "network_id": { "type":"string", "id": "network_id", "required":true }, "state": { "type":"string", "id": "state", "required":false }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } } }, "shared": { "type":"boolean", "id": "shared", "required":false }, "state": { "type":"string", "id": "state", "required":false }, "subnets": { "type":"array", "id": "subnets", "required":false, "items": { "type":"object", "id": "0", "required":false, "properties":{ "allocation_pools": { "type":"array", "id": "allocation_pools", "required":false, "items": { "type":"object", "id": "0", "required":false, "properties":{ "end": { "type":"string", "id": "end", "required":false }, "start": { "type":"string", "id": "start", "required":false } } } }, "cidr": { "type":"string", "id": "cidr", "required":true }, "dns_nameservers": { "type":"array", "id": "dns_nameservers", "required":false }, "enable_dhcp": { "type":"boolean", "id": "enable_dhcp", "required":false }, "gateway_ip": { "type":"string", "id": "gateway_ip", "required":false }, "host_routes": { "type":"array", "id": "host_routes", "required":false }, "id": { "type":"string", "id": "id", "required":true }, "ip_version": { "type":"number", "id": "ip_version", "required":false }, "name": { "type":"string", "id": "name", "required":false }, "network_id": { "type":"string", "id": "network_id", "required":true }, "shared": { "type":"boolean", "id": "shared", "required":false }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } } }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } } }, "routers": { "type":"array", "id": "routers", "required":true, "items": { "type":"object", "id": "0", "required":false, "properties":{ "external_gateway_info": { "type":"null", "id": "external_gateway_info", "required":false }, "id": { "type":"string", "id": "id", "required":true }, "interfaces": { "type":"array", "id": "interfaces", "required":true, "items": { "type":"object", "id": "0", "required":false, "properties":{ "id": { "type":"string", "id": "id", "required":true }, "network": { "type":"object", "id": "network", "required":true, "properties":{ "gateway": { "type":"string", "id": "gateway", "required":false }, "id": { "type":"string", "id": "id", "required":true }, "name": { "type":"string", "id": "name", "required":false }, "shared": { "type":"boolean", "id": "shared", "required":false }, "state": { "type":"string", "id": "state", "required":false }, "subnets": { "type":"array", "id": "subnets", "required":true, "items": { "type":"object", "id": "0", "required":false, "properties":{ "allocation_pools": { "type":"array", "id": "allocation_pools", "required":false, "items": { "type":"object", "id": "0", "required":false, "properties":{ "end": { "type":"string", "id": "end", "required":false }, "start": { "type":"string", "id": "start", "required":false } } } }, "cidr": { "type":"string", "id": "cidr", "required":true }, "dns_nameservers": { "type":"array", "id": "dns_nameservers", "required":false }, "enable_dhcp": { "type":"boolean", "id": "enable_dhcp", "required":false }, "gateway_ip": { "type":"string", "id": "gateway_ip", "required":false }, "host_routes": { "type":"array", "id": "host_routes", "required":false }, "id": { "type":"string", "id": "id", "required":true }, "ip_version": { "type":"number", "id": "ip_version", "required":false }, "name": { "type":"string", "id": "name", "required":false }, "network_id": { "type":"string", "id": "network_id", "required":true }, "shared": { "type":"boolean", "id": "shared", "required":false }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } } }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } }, "subnet": { "type":"object", "id": "subnet", "required":true, "properties":{ "allocation_pools": { "type":"array", "id": "allocation_pools", "required":false, "items": { "type":"object", "id": "0", "required":false, "properties":{ "end": { "type":"string", "id": "end", "required":false }, "start": { "type":"string", "id": "start", "required":false } } } }, "cidr": { "type":"string", "id": "cidr", "required":true }, "dns_nameservers": { "type":"array", "id": "dns_nameservers", "required":false }, "enable_dhcp": { "type":"boolean", "id": "enable_dhcp", "required":false }, "gateway_ip": { "type":"string", "id": "gateway_ip", "required":false }, "host_routes": { "type":"array", "id": "host_routes", "required":false }, "id": { "type":"string", "id": "id", "required":true }, "ip_version": { "type":"number", "id": "ip_version", "required":false }, "name": { "type":"string", "id": "name", "required":false }, "network_id": { "type":"string", "id": "network_id", "required":true }, "shared": { "type":"boolean", "id": "shared", "required":false }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } } } } }, "name": { "type":"string", "id": "name", "required":false }, "state": { "type":"string", "id": "state", "required":false }, "tenant_id": { "type":"string", "id": "tenant_id", "required":true } } } } }}

        body_dict = json.loads(body)
        self._validator.validate(body_dict, schema)
        return

    def getresponse(self):
        return HTTPResponseMock(None)

    def close(self):
        pass


class L3TestExtensionManager(object):

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class RouterDBTestCase(test_l3_plugin.L3NatDBTestCase):

    def _create_network(self, fmt, name, admin_status_up,
                        arg_list=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_status_up,
                            'tenant_id': self._tenant_id}}
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['quantum.context'] = context.Context(
                '', kwargs['tenant_id'])

        return network_req.get_response(self.api)

    def setUp(self):

        self.httpPatch = patch('httplib.HTTPConnection', create=True,
                               new=HTTPConnectionMock)
        MockHTTPConnection = self.httpPatch.start()
        super(RouterDBTestCase, self).setUp()

        db._ENGINE = None
        db._MAKER = None
        QuantumManager._instance = None
        PluginAwareExtensionManager._instance = None
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

    def tearDown(self):
        super(RouterDBTestCase, self).tearDown()
        self.httpPatch.stop()

    def test_router_add_interface_overlapped_cidr(self):
        self.skipTest("Plugin does not support external gateway for router")

    def test_create_router_with_gwinfo(self):
        self.skipTest("Plugin does not support external gateway for router")

    def test_router_add_gateway(self):
        self.skipTest("Plugin does not support external gateway for router")

    def test_router_update_gateway(self):
        self.skipTest("Plugin does not support external gateway for router")

    def test_router_add_gateway_invalid_network(self):
        self.skipTest("Plugin does not support external gateway for router")

    def test_router_add_gateway_net_not_external(self):
        self.skipTest("Plugin does not support external gateway for router")

    def test_router_add_gateway_no_subnet(self):
        self.skipTest("Plugin does not support external gateway for router")

    def floatingip_with_assoc(self, port_id=None, fmt='json'):
        self.skipTest("Plugin does not support floating IPs")

    def floatingip_no_assoc(self, private_sub, fmt='json'):
        self.skipTest("Plugin does not support floating IPs")

    def test_floatingip_crd_ops(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_floatingip_with_assoc_fails(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_router_delete_with_floatingip(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_floatingip_update(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_floatingip_with_assoc(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_floatingip_port_delete(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_two_fips_one_port_invalid_return_409(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_floating_ip_direct_port_delete_returns_409(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_create_floatingip_no_ext_gateway_return_404(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_create_floating_non_ext_network_returns_400(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_create_floatingip_no_public_subnet_returns_400(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_create_floatingip_invalid_floating_network_id_returns_400(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_create_floatingip_invalid_floating_port_id_returns_400(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_create_floatingip_invalid_fixed_ip_address_returns_400(self):
        self.skipTest("Plugin does not support floating IPs")

    def test_list_nets_external(self):
        self.skipTest("Plugin does not support external networks")

    def test_create_port_external_network_non_admin_fails(self):
        self.skipTest("Plugin does not support external networks")

    def test_create_port_external_network_admin_suceeds(self):
        self.skipTest("Plugin does not support external networks")

    def test_create_external_network_non_admin_fails(self):
        self.skipTest("Plugin does not support external networks")

    def test_create_external_network_admin_suceeds(self):
        self.skipTest("Plugin does not support external networks")

    def test_send_data(self):
        plugin_obj = QuantumManager.get_plugin()
        with self.router() as r:
            with self.subnet() as s:
                with self.router() as r1:
                    with self.subnet(cidr='10.0.10.0/24') as s1:
                        body = self._router_interface_action('add',
                                                         r1['router']['id'],
                                                         s1['subnet']['id'],
                                                         None)
                        body = self._router_interface_action('add',
                                                         r['router']['id'],
                                                         s['subnet']['id'],
                                                         None)
                        self.assertTrue('port_id' in body)

                        # fetch port and confirm device_id
                        r_port_id = body['port_id']
                        body = self._show('ports', r_port_id)
                        self.assertEquals(body['port']['device_id'],
                                          r['router']['id'])

                        result = plugin_obj._send_all_data()
                        self.assertEquals(result[0], 200)

                        body = self._router_interface_action('remove',
                                                             r['router']['id'],
                                                             s['subnet']['id'],
                                                             None)
                        body = self._show('ports', r_port_id,
                                          expected_code=exc.HTTPNotFound.code)
                        body = self._router_interface_action('remove',
                                                             r1['router']['id'],
                                                             s1['subnet']['id'],
                                                             None)
