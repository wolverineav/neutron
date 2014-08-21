# Copyright (c) 2014 OpenStack Foundation.
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

from neutron import context
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import service_instance_info_db
from neutron.tests.unit import testlib_api


class FakePlugin(base_plugin.NeutronDbPluginV2,
                 service_instance_info_db.ServiceInstanceInfoDbMixin):
    """A fake plugin class containing all DB methods."""
    pass


test_service_instance_info = {'service_instance_info': {
    'id': '981797982872',
    'service_name': 'vpnservice'}}


class TestDbServiceInstanceInfo(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestDbServiceInstanceInfo, self).setUp()
        self.plugin = FakePlugin()
        self.context = context.get_admin_context()

    def test_create_service_instance_info(self):
        self.plugin.register_service_instance(self.context,
                                              test_service_instance_info)
        srv_instances = self.plugin.get_service_instance_infos(self.context)
        self.assertEqual(1, len(srv_instances))
        self.assertEqual('vpnservice', srv_instances[0]['service_name'])
        one_ins = self.plugin.get_service_instance_info(self.context,
                                                       srv_instances[0]['id'])
        self.assertEqual(one_ins, srv_instances[0])

    def test_delete_service_instance_info(self):
        self.plugin.register_service_instance(self.context,
                                              test_service_instance_info)
        srv_instances = self.plugin.get_service_instance_infos(self.context)
        self.assertEqual(1, len(srv_instances))
        self.plugin.unregister_service_instance(self.context,
                                                srv_instances[0]['id'])
        instances = self.plugin.get_service_instance_infos(self.context)
        self.assertFalse(instances)
