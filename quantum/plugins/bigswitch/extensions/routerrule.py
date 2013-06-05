# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Big Switch Networks, Inc.
# All Rights Reserved
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
# @author: Kevin Benton, Big Switch Networks, Inc.

from quantum.api.v2 import attributes as attr
from quantum.common import exceptions as qexception
from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)


# Router Rules Exceptions
class InvalidRouterRules(qexception.InvalidInput):
    message = _("Invalid format for router rules: %(rule)s, %(reason)s")


# Validates and converts router rules to the appropriate data structure
def convert_to_valid_router_rules(data):
    if not isinstance(data, list):
        msg = _("Invalid data format for router rule: '%s'") % data
        LOG.debug(msg)
        raise qexception.InvalidInput(error_message=msg)
    rules = []
    expected_keys = ['source', 'destination', 'action']
    for rule in data:
        msg = attr._verify_dict_keys(expected_keys, rule)
        if msg:
            msg =attr._verify_dict_keys(expected_keys+['nexthops'],rule)
        if msg:
            LOG.debug(msg)
            raise qexception.InvalidInput(error_message=msg)
        msg = attr._validate_subnet(rule['destination'])
        if msg and not rule['destination']=='any':
            LOG.debug(msg)
            raise qexception.InvalidInput(error_message=msg)
        msg = attr._validate_subnet(rule['source'])
        if msg and not rule['source']=='any':
            LOG.debug(msg)
            raise qexception.InvalidInput(error_message=msg)
        try:
           rule['nexthops']=rule['nexthops'].split('+')
        except KeyError:
           rule['nexthops']=[]
        for ip in rule['nexthops']:
            msg = attr._validate_ip_address(ip)
            if msg:
                LOG.debug(msg)
                raise qexception.InvalidInput(error_message=msg)
        if (not rule['action']=='permit' and not rule['action']=='deny'):
            msg = _("Action must be either permit or deny. '%s' was provided") % rule['action']
            LOG.debug(msg)
            raise qexception.InvalidInput(error_message=msg)
        if rule in rules:
            msg = _("Duplicate router rule '%s'") % rule
            LOG.debug(msg)
            raise qexception.InvalidInput(error_message=msg)
        rules.append(rule)
    return rules



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
        return "http://docs.openstack.org/ext/quantum/routerrules/api/v1.0" 

    @classmethod
    def get_updated(cls):
        return "2013-05-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

# Attribute Map
EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        'router_rules': {'allow_post': False, 'allow_put': True,
                   'convert_to': convert_to_valid_router_rules,
                   'is_visible': True, 'default': attr.ATTR_NOT_SPECIFIED},
    }
}
