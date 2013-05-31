# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013, Big Switch Networks, Inc.
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


from quantum.api.v2 import attributes as attr
from quantum.common import exceptions as qexception


# Router Rules Exceptions
class InvalidRouterRules(qexception.InvalidInput):
    message = _("Invalid format for router rules: %(rule)s, %(reason)s")


# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'router_rules': {'allow_post': False, 'allow_put': True,
                   'validate': {'type:routerrules': None},
                   'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED},
    }
}


class Routerrule():

    @classmethod
    def get_name(cls):
        return "Quantum Router Rule"

    @classmethod
    def get_alias(cls):
        return "router_rules"

    @classmethod
    def get_description(cls):
        return "Router rule configuration for L3 router"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/quantum/routerrules/api/v1.0" #TODO: replace this

    @classmethod
    def get_updated(cls):
        return "2013-05-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
