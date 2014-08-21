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
import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as qexception
from neutron import manager
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


# ServiceInstanceInfo Exceptions
class ServiceInstanceNotFound(qexception.NotFound):
    message = _("Service Instance %(id)s does not exist")


RESOURCE_ATTRIBUTE_MAP = {
    'service_instance_infos': {
        'id': {'allow_post': False, 'allow_put': False,
               'enforce_policy': True,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True},
        'service_name': {'allow_post': True, 'allow_put': True,
                         'enforce_policy': True,
                         'validate': {'type:string': None},
                         'is_visible': True, 'default': ''},
    }
}


class ServiceInstanceInfo(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron Service Instance Info"

    @classmethod
    def get_alias(cls):
        return "service_instance_info"

    @classmethod
    def get_description(cls):
        return "Neutron Service Instance Information"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/serviceinstanceinfo/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2014-08-20:00:00-00:00"

    def update_attributes_map(self, attributes):
        super(ServiceInstanceInfo, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        resource_name = "service_instance_info"
        collection_name = resource_name.replace('_', '-') + "s"
        exts = []
        attr.PLURALS.update(plural_mappings)
        plugin = manager.NeutronManager.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
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
class ServiceInstanceInfoPluginBase(object):

    @abc.abstractmethod
    def get_service_instance_infos(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_service_instance_info(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def register_service_instance(self, context, service_instance_info):
        pass

    @abc.abstractmethod
    def unregister_service_instance(self, context, id):
        pass
