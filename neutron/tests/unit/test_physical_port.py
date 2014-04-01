# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
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

import os

import mock
from oslo.config import cfg

from neutron import context
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import physicalport_db
from neutron import manager
from neutron.tests import base


class PhysicalPortTestCase(base.BaseTestCase):
    def setUp(self):
        super(PhysicalPortTestCase, self).setUp()
        plugin = 'neutron.neutron_plugin_base_v2.NeutronPluginBaseV2'

        #just stubbing core plugin with LoadBalancer plugin
        self.setup_coreplugin(plugin)

        self.plugin = manager.NeutronManager().get_instance().get_plugin()
        db.configure_db()
