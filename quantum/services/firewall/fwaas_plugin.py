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

from sqlalchemy.orm import exc

from oslo.config import cfg

from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import api as qdbapi
from quantum.db.firewall import firewall_db
from quantum.extensions import firewall
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.common import constants as const

LOG = logging.getLogger(__name__)


class FirewallCallbacks(object):
    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])

    def set_firewall_status(self, context, firewall_id, status,
                            **kwargs):
        """Agent uses this to set a firewall's status."""
        with context.session.begin(subtransactions=True):
            qry = context.session.query(firewall_db.Firewall)
            qry = qry.filter_by(id=firewall_id)
            try:
                fw = qry.one()
            except exc.NoResultFound:
                raise firewall.FirewallNotFound(firewall_id=firewall_id)

            if status in (const.ACTIVE, const.INACTIVE):
                fw.status = status
            else:
                fw.status = const.ERROR
        return True

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        with context.session.begin(subtransactions=True):
            qry = context.session.query(firewall_db.Firewall)
            qry = qry.filter_by(id=firewall_id)
            try:
                fw = qry.one()
            except exc.NoResultFound:
                raise firewall.FirewallNotFound(firewall_id=firewall_id)
            if fw['status'] == const.PENDING_DELETE:
                self.plugin.delete_firewall(context, firewall_id)
                return True
            else:
                fw.status = const.ERROR
                return False


class FirewallAgentApi(proxy.RpcProxy):
    """Plugin side of plugin to agent RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(FirewallAgentApi, self).__init__(topic, self.API_VERSION)
        self.host = host

    def create_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('create_firewall', firewall=firewall,
                          host=self.host),
            topic=self.topic
        )

    def update_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('update_firewall', firewall=firewall,
                          host=self.host),
            topic=self.topic
        )

    def delete_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('delete_firewall', firewall=firewall,
                          host=self.host),
            topic=self.topic
        )


class FirewallPlugin(firewall_db.Firewall_db_mixin):

    """Implementation of the Quantum Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        qdbapi.register_models()

        self.callbacks = FirewallCallbacks(self)

        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN,
            self.callbacks.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()

        self.agent_rpc = FirewallAgentApi(
            topics.L3_AGENT,
            cfg.CONF.host
        )

    def get_plugin_type(self):
        return const.FIREWALL

    def get_plugin_description(self):
        return "Quantum Firewall Service Plugin"

    def _make_firewall_dict_with_rules(self, context, firewall_id):
        firewall = super(FirewallPlugin, self).get_firewall(context,
                                                            firewall_id)
        fw_policy_id = firewall['firewall_policy_id']
        if fw_policy_id:
            fw_policy = super(FirewallPlugin,
                              self).get_firewall_policy(context,
                                                        fw_policy_id)
            fw_rules_list = []
            for rule_id in fw_policy['firewall_rules_list']:
                fw_rule = super(FirewallPlugin,
                                self).get_firewall_policy(context,
                                                          rule_id)
                fw_rules_list.append(fw_rule)
        # TODO(Sumit): This is an inefficient implementation since for any
        # change to the firewall, policy or rule, we send all the rules.
        # We also need to verify what is the largest message size supported
        # by rabbit/qpid since the with a large number of rules this firewall
        # dict can be potentially be a large number of bytes.
        firewall['firewall_rules_list'] = fw_rules_list
        return firewall

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        fw = super(FirewallPlugin, self).update_firewall(context, firewall_id,
                                                         status_update)
        if fw:
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context,
                                                    firewall_id))
            self.agent_rpc.update_firewall(context, fw_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = super(FirewallPlugin,
                                self).get_firewall_policy(context,
                                                          firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewalls_list']:
                self._rpc_update_firewall(context, firewall_id)

    def create_firewall(self, context, firewall):
        firewall['firewall']['status'] = const.PENDING_CREATE
        fw = super(FirewallPlugin, self).create_firewall(context, firewall)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        self.agent_rpc.create_firewall(context, fw_with_rules)
        return fw

    def update_firewall(self, context, id, firewall):
        firewall['firewall']['status'] = const.PENDING_UPDATE
        fw = super(FirewallPlugin, self).update_firewall(context, id, firewall)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        self.agent_rpc.update_firewall(context, fw_with_rules)
        return fw

    def delete_firewall(self, context, id):
        firewall = super(FirewallPlugin, self).get_firewall(context, id)
        if firewall['status'] in [const.PENDING_DELETE]:
            firewall = super(FirewallPlugin, self).delete_firewall(context, id)
        else:
            status_update = {"firewall": {"status": const.PENDING_DELETE}}
            fw = super(FirewallPlugin, self).update_firewall(context, id,
                                                             status_update)
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context, fw['id']))
            self.agent_rpc.delete_firewall(context, fw_with_rules)

    def update_firewall_policy(self, context, id, firewall_policy):
        fwp = super(FirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def update_firewall_rule(self, context, id, firewall_rule):
        fwr = super(FirewallPlugin,
                    self).update_firewall_rule(context, id, firewall_rule)
        firewall_policy_id = fwr['firewall_policy_id']
        if firewall_policy_id:
            self._rpc_update_firewall_policy(context, id)
        return fwr

    def delete_firewall_rule(self, context, id):
        fwr = super(FirewallPlugin, self).get_firewall_rule(context, id)
        firewall_policy_id = fwr['firewall_policy_id']
        super(FirewallPlugin, self).delete_firewall_rule(context, id)
        # At this point we have already deleted the rule in the DB,
        # however it's still not deleted on the backend firewall.
        # Until it gets deleted on the backend we will be setting
        # the firewall in PENDING_UPDATE state. The backend firewall
        # implementation is responsible for setting the appropriate
        # configuration (e.g. do not allow any traffic) until the rule
        # is deleted. Once the rule is deleted, the backend should put
        # the firewall back in ACTIVE state. While the firewall is in
        # PENDING_UPDATE state, the firewall behavior might differ based
        # on the backend implementation.
        if firewall_policy_id:
            self._rpc_update_firewall_policy(context, firewall_policy_id)
