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

import sqlalchemy as sa
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy import orm
from sqlalchemy.orm import exc

from quantum.db import db_base_plugin_v2 as base_db
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import firewall
from quantum import manager
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


class FirewallRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall rule."""
    __tablename__ = 'firewall_rules'
    name = sa.Column(sa.String(64))
    description = sa.Column(sa.String(1024))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)
    shared = sa.Column(sa.Boolean)
    protocol = sa.Column(sa.String(24))
    source_ip_address = sa.Column(sa.String(46))
    destination_ip_address = sa.Column(sa.String(46))
    source_port = sa.Column(sa.Integer)
    destination_port = sa.Column(sa.Integer)
    action = sa.Column(sa.Enum('allow', 'deny', name='firewallrules_action'))
    enabled = sa.Column(sa.Boolean)
    position = sa.Column(sa.Integer)


class Firewall(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall resource."""
    __tablename__ = 'firewalls'
    name = sa.Column(sa.String(64))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    admin_state_up = sa.Column(sa.Boolean)
    status = sa.Column(sa.String(16))
    firewall_policy_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('firewall_policies.id'),
                                   nullable=True)


class FirewallPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a Firewall Policy resource."""
    __tablename__ = 'firewall_policies'
    name = sa.Column(sa.String(64))
    description = sa.Column(sa.String(1024))
    shared = sa.Column(sa.Boolean)
    firewall_rules = orm.relationship(FirewallRule,
                                      backref=orm.backref('firewall_policies',
                                                          cascade=
                                                          'all, delete'),
                                      order_by='FirewallRule.position',
                                      collection_class=
                                      ordering_list('position', count_from=1))
    audited = sa.Column(sa.Boolean)
    firewalls = orm.relationship(Firewall, backref='firewall_policies')


class Firewall_db_mixin(firewall.FirewallPluginBase, base_db.CommonDbMixin):
    """Mixin class to for Firewall DB implementation."""

    @property
    def _core_plugin(self):
        return manager.QuantumManager.get_plugin()

    def _get_firewall(self, context, id):
        try:
            fw = self._get_by_id(context, Firewall, id)
        except exc.NoResultFound:
            raise firewall.FirewallNotFound(firewall_id=id)
        return fw

    def _get_firewall_policy(self, context, id):
        try:
            firewall_policy = self._get_by_id(context, FirewallPolicy, id)
        except exc.NoResultFound:
            raise firewall.FirewallPolicyNotFound(firewall_policy_id=id)
        return firewall_policy

    def _get_firewall_rule(self, context, id):
        try:
            firewall_rule = self._get_by_id(context, FirewallRule, id)
        except exc.NoResultFound:
            raise firewall.FirewallRuleNotFound(firewall_rule_id=id)
        return firewall_rule

    def _make_firewall_dict(self, fw, fields=None):
        res = {'id': fw['id'],
               'tenant_id': fw['tenant_id'],
               'name': fw['name'],
               'description': fw['description'],
               'shared': fw['shared'],
               'admin_state_up': fw['admin_state_up'],
               'status': fw['status'],
               'firewall_policy_id': fw['firewall_policy_id']}
        return self._fields(res, fields)

    def _make_firewall_policy_dict(self, firewall_policy, fields=None):
        fw_rules = [rule['id'] for rule in firewall_policy['firewall_rules']]
        firewalls = [fw['id'] for fw in firewall_policy['firewalls']]
        res = {'id': firewall_policy['id'],
               'tenant_id': firewall_policy['tenant_id'],
               'name': firewall_policy['name'],
               'description': firewall_policy['description'],
               'shared': firewall_policy['shared'],
               'audited': firewall_policy['audited'],
               'firewall_rules_list': fw_rules,
               'firewalls_list': firewalls}
        return self._fields(res, fields)

    def _make_firewall_rule_dict(self, firewall_rule, fields=None):
        res = {'id': firewall_rule['id'],
               'tenant_id': firewall_rule['tenant_id'],
               'name': firewall_rule['name'],
               'description': firewall_rule['description'],
               'firewall_policy_id': firewall_rule['firewall_policy_id'],
               'shared': firewall_rule['shared'],
               'protocol': firewall_rule['protocol'],
               'source_ip_address': firewall_rule['source_ip_address'],
               'destination_ip_address':
               firewall_rule['destination_ip_address'],
               'source_port': firewall_rule['source_port'],
               'destination_port': firewall_rule['destination_port'],
               'action': firewall_rule['action'],
               'enabled': firewall_rule['enabled']}
        return self._fields(res, fields)

    def _add_rules_to_policy(self, context, firewall_policy_id, rules_list):
        fwp_db = self._get_firewall_policy(context, firewall_policy_id)
        with context.session.begin(subtransactions=True):
            # We will first check if the new list of rules is valid
            for fwrule_id in rules_list:
                try:
                    qry = context.session.query(FirewallRule)
                    # TODO(sumit): As pointed out by enikanorov
                    # the following implementation is inefficient
                    # because it makes one DB fetch for every rule
                    # in the system
                    qry.filter_by(id=fwrule_id).one()
                except exc.NoResultFound:
                    raise firewall.FirewallRuleNotFound(firewall_rule_id=
                                                        fwrule_id)

            # New list of rules is valid so we will add each rule
            # in order
            for fwrule_id in rules_list:
                qry = context.session.query(FirewallRule)
                fwrule_db = qry.filter_by(id=fwrule_id).one()
                fwp_db.firewall_rules.append(fwrule_db)

    def create_firewall(self, context, firewall):
        fw = firewall['firewall']
        tenant_id = self._get_tenant_id_for_create(context, fw)
        with context.session.begin(subtransactions=True):
            firewall_db = Firewall(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=fw['name'],
                                   description=fw['description'],
                                   firewall_policy_id=
                                   fw['firewall_policy_id'],
                                   admin_state_up=fw['admin_state_up'],
                                   status='PENDING_CREATE')
            context.session.add(firewall_db)
        return self._make_firewall_dict(firewall_db)

    def update_firewall(self, context, id, firewall):
        fw = firewall['firewall']
        with context.session.begin(subtransactions=True):
            firewall_db = self._get_firewall(context, id)
            firewall_db.update(fw)
        return self._make_firewall_dict(firewall_db)

    def delete_firewall(self, context, id):
        with context.session.begin(subtransactions=True):
            fw = self._get_firewall(context, id)
            # TODO(Sumit): Ensure that the firewall is not active
            context.session.delete(fw)

    def get_firewall(self, context, id, fields=None):
        fw = self._get_firewall(context, id)
        return self._make_firewall_dict(fw, fields)

    def get_firewalls(self, context, filters=None, fields=None):
        return self._get_collection(context, Firewall,
                                    self._make_firewall_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_count(self, context, filters=None):
        return self._get_collection_count(context, Firewall,
                                          filters=filters)

    def create_firewall_policy(self, context, firewall_policy):
        fwp = firewall_policy['firewall_policy']
        tenant_id = self._get_tenant_id_for_create(context, fwp)
        with context.session.begin(subtransactions=True):
            fwp_db = FirewallPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=fwp['name'],
                                    description=fwp['description'],
                                    shared=fwp['shared'],
                                    audited=fwp['audited'])
            context.session.add(fwp_db)
            self._add_rules_to_policy(context, fwp_db['id'],
                                      fwp['firewall_rules_list'])
        return self._make_firewall_policy_dict(fwp_db)

    def update_firewall_policy(self, context, id, firewall_policy):
        fwp = firewall_policy['firewall_policy']
        with context.session.begin(subtransactions=True):
            fwp_db = self._get_firewall_policy(context, id)
            if 'firewall_rules_list' in fwp.keys():
                # We will first check if the new list of rules is valid
                self._add_rules_to_policy(context, id,
                                          fwp['firewall_rules_list'])
                del fwp['firewall_rules_list']
            fwp_db.update(fwp)
        return self._make_firewall_policy_dict(fwp_db)

    def delete_firewall_policy(self, context, id):
        with context.session.begin(subtransactions=True):
            fwp = self._get_firewall_policy(context, id)
            # Ensure that the firewall_policy  is not
            # being used
            qry = context.session.query(Firewall)
            if qry.filter_by(firewall_policy_id=id).all():
                raise firewall.FirewallPolicyInUse(firewall_policy_id=id)
            else:
                context.session.delete(fwp)

    def get_firewall_policy(self, context, id, fields=None):
        fwp = self._get_firewall_policy(context, id)
        return self._make_firewall_policy_dict(fwp, fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        return self._get_collection(context, FirewallPolicy,
                                    self._make_firewall_policy_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_policies_count(self, context, filters=None):
        return self._get_collection_count(context, FirewallPolicy,
                                          filters=filters)

    def create_firewall_rule(self, context, firewall_rule):
        fwr = firewall_rule['firewall_rule']
        tenant_id = self._get_tenant_id_for_create(context, fwr)
        with context.session.begin(subtransactions=True):
            fwr_db = FirewallRule(id=uuidutils.generate_uuid(),
                                  tenant_id=tenant_id,
                                  name=fwr['name'],
                                  description=fwr['description'],
                                  shared=fwr['shared'],
                                  protocol=fwr['protocol'],
                                  source_ip_address=fwr['source_ip_address'],
                                  destination_ip_address=
                                  fwr['destination_ip_address'],
                                  source_port=fwr['source_port'],
                                  destination_port=fwr['destination_port'],
                                  action=fwr['action'],
                                  enabled=fwr['enabled'])
            context.session.add(fwr_db)
        return self._make_firewall_rule_dict(fwr_db)

    def update_firewall_rule(self, context, id, firewall_rule):
        fwr = firewall_rule['firewall_rule']
        with context.session.begin(subtransactions=True):
            fwr_db = self._get_firewall_rule(context, id)
            fwr_db.update(fwr)
        return self._make_firewall_rule_dict(fwr_db)

    def delete_firewall_rule(self, context, id):
        with context.session.begin(subtransactions=True):
            fwr = self._get_firewall_rule(context, id)
            context.session.delete(fwr)

    def get_firewall_rule(self, context, id, fields=None):
        fwr = self._get_firewall_rule(context, id)
        return self._make_firewall_rule_dict(fwr, fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        return self._get_collection(context, FirewallRule,
                                    self._make_firewall_rule_dict,
                                    filters=filters, fields=fields)

    def get_firewalls_rules_count(self, context, filters=None):
        return self._get_collection_count(context, FirewallRule,
                                          filters=filters)
