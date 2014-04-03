# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation.
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

import abc

from oslo.config import cfg
import six

from neutron import manager
from neutron import quota
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as qexception
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)

# PhysicalPort Exceptions
class PhysicalPortNotFound(qexception.NotFound):
    message = _("Physical port %(id)s does not exist")


class PhysicalPortExists(qexception.InUse):
    message = _("Physical port with the same attachment already exists, %(id)s")


class PhysicalPortInUse(qexception.InUse):
    message = _("Physical port %(id) is already assign to network %(net_id)")


RESOURCE_ATTRIBUTE_MAP = {
    'physical_ports': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': True,
                      'required_by_policy': True,
                      'is_visible': True},
        'port_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid_or_none': None},
                    'is_visible': True, 'default': None},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'mac_address': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:mac_address': None},
                        'required_by_policy': True,
                        'is_visible': True},
        'attachment': {'allow_post': True, 'allow_put': True,
                   'default': False, 'validate': {'type:string': None},
                   'is_visible': True,
                   'required_by_policy': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
    }
}

physicalport_quota_opts = [
    cfg.IntOpt('quota_physical_port',
               default=10,
               help=_('Number of physical ports allowed per tenant. '
                      'A negative value means unlimited.'))
]
cfg.CONF.register_opts(physicalport_quota_opts, 'QUOTAS')


class Physicalport(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron Physical Port"

    @classmethod
    def get_alias(cls):
        return "physical_port"

    @classmethod
    def get_description(cls):
        return "Neutron Physical Port configuration"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/physicalport/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2014-03-25:00:00-00:00"

    def update_attributes_map(self, attributes):
        super(Physicalport, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        resource_name = "physical_port"
        collection_name = resource_name.replace('_', '-') + "s"
        exts = []
        attr.PLURALS.update(plural_mappings)
        plugin = manager.NeutronManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict()) 
        quota.QUOTAS.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params, allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)

        ext = extensions.ResourceExtension(collection_name,
                                              controller,
                                              attr_map=params)
        exts.append(ext)
        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class PhysicalPortPluginBase(object):

    @abc.abstractmethod
    def get_physical_ports(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_physical_port(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_physical_port(self, context, physicalport):
        pass

    @abc.abstractmethod
    def update_physical_port(self, context, id, physicalport):
        pass

    @abc.abstractmethod
    def delete_physical_port(self, context, id):
        pass
