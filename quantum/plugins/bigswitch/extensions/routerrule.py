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


class RulesExhausted(qexception.BadRequest):
    message = _("Unable to complete rules update for %(router_id)s. "
                "The number of rules exceeds the maximum %(quota)s.")


def convert_to_valid_router_rules(data):
    """
    Validates and converts router rules to the appropriate data structure
    """
    V4ANY = '0.0.0.0/0'
    CIDRALL = ['any', 'external']
    if not isinstance(data, list):
        emsg = _("Invalid data format for router rule: '%s'") % data
        LOG.debug(emsg)
        raise qexception.InvalidInput(error_message=emsg)
    _validate_uniquerules(data)
    rules = []
    expected_keys = ['source', 'destination', 'action']
    for rule in data:
        try:
            if not isinstance(rule['nexthops'], list):
                rule['nexthops'] = rule['nexthops'].split('+')
        except KeyError:
            rule['nexthops'] = []
        src = V4ANY if rule['source'] in CIDRALL else rule['source']
        dst = V4ANY if rule['destination'] in CIDRALL else rule['destination']
        errors = [msg for msg in
                  [attr._verify_dict_keys(expected_keys, rule, False),
                   attr._validate_subnet(dst),
                   attr._validate_subnet(src),
                   _validate_nexthops(rule['nexthops']),
                   _validate_action(rule['action'])] if msg]
        if errors:
            LOG.debug(errors)
            raise qexception.InvalidInput(error_message=errors)
        rules.append(rule)
    return rules


def _validate_nexthops(nexthops):
    for ip in nexthops:
        msg = attr._validate_ip_address(ip)
        if msg:
            return msg


def _validate_action(action):
    if action not in ['permit', 'deny']:
        return _("Action must be either permit or deny."
                 " '%s' was provided") % action


def _validate_uniquerules(rules):
    pairs = []
    for r in rules:
        if 'source' not in r or 'destination' not in r:
            continue
        pairs.append((r['source'], r['destination']))
    pairs.sort(key=lambda x: (x[0], x[1]))
    for i, p in enumerate(pairs):
        if i == 0:
            continue
        if p == pairs[i - 1]:
            error = _("Duplicate router rule (src,dst) '%s'") % str(p)
            LOG.debug(error)
            raise qexception.InvalidInput(error_message=error)


class Routerrule(object):

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
                         'is_visible': True,
                         'default': attr.ATTR_NOT_SPECIFIED},
    }
}
