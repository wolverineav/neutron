# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.
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
#
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

import inspect

from oslo.config import cfg

from neutron.openstack.common import log
from neutron.plugins.bigswitch.plugin import NeutronRestProxyV2Base
from neutron.plugins.bigswitch.plugin import ServerPool
from neutron.plugins.ml2 import driver_api as api


LOG = log.getLogger(__name__)


class BigSwitchMechanismDriver(NeutronRestProxyV2Base,
                               api.MechanismDriver):

    """Mechanism Driver for Big Switch Networks Controller.

    This driver relays the network create, update, delete
    operations to the Big Switch Controller.
    """

    def initialize(self, server_timeout=None):
        LOG.debug(_('Initializing driver'))
        stack = inspect.stack()
        parentframe = stack[2][0]
        class_ref = parentframe.f_locals['self'].__class__
        class_ref._Ml2Plugin__native_bulk_support = False

        # init network ctrl connections
        self.servers = ServerPool(server_timeout)
        self.segmentation_type = ', '.join(cfg.CONF.ml2.type_drivers)
        LOG.debug(_("Initialization done"))

    def create_network_postcommit(self, context):
        # create network on the network controller
        self._send_create_network(context.current)

    def update_network_postcommit(self, context):
        # update network on the network controller
        self._send_update_network(context.current)

    def delete_network_postcommit(self, context):
        # delete network on the network controller
        self._send_delete_network(context.current)
