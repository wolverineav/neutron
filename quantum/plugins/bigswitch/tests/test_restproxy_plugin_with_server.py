# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Big Switch Networks, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import multiprocessing
import os


from mock import patch

import quantum.common.test_lib as test_lib
from quantum.manager import QuantumManager
import quantum.tests.unit.test_db_plugin as test_plugin
import quantum.plugins.bigswitch.tests.test_server as server


RESTPROXY_PKG_PATH = 'quantum.plugins.bigswitch.plugin'


class V2TestCaseWithServer(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('%s.QuantumRestProxyV2' % RESTPROXY_PKG_PATH)
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
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        test_lib.test_config['config_files'] = [os.path.join(etc_path,
                                                'restproxy.ini.test')]

        super(V2TestCaseWithServer,
              self).setUp(self._plugin_name)

    def tearDown(self):
        super(V2TestCaseWithServer, self).tearDown()


class TestBigSwitchProxyBasicGetWithServer(test_plugin.TestBasicGet,
                                           V2TestCaseWithServer):

    pass


class TestBigSwitchProxyV2HTTPResponseWServer(test_plugin.TestV2HTTPResponse,
                                              V2TestCaseWithServer):

    pass


class TestBigSwitchProxyPortsV2WithServer(test_plugin.TestPortsV2,
                                          V2TestCaseWithServer):

    def test_create_ports_bulk_emulated_plugin_failure(self):
        self.skipTest("Plugin does not support")


class TestBigSwitchProxyNetworksV2WithServer(test_plugin.TestNetworksV2,
                                             V2TestCaseWithServer):

    def test_create_networks_bulk_emulated_plugin_failure(self):
        self.skipTest("Plugin does not support")


class TestBigSwitchProxySubnetsV2WithServer(test_plugin.TestSubnetsV2,
                                            V2TestCaseWithServer):

    pass


class TestBigSwitchProxySyncWithServer(V2TestCaseWithServer):

    def test_send_data(self):
        plugin_obj = QuantumManager.get_plugin()
        result = plugin_obj._send_all_data()
        self.assertEquals(result[0], 200)
