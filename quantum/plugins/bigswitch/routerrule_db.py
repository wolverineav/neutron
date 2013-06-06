# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013, Big Switch Networks
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
import pprint
import json
import netaddr
from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy import orm

from quantum.common import utils
from quantum.db import l3_db
from quantum.db import model_base
from quantum.openstack.common import log as logging
from quantum.plugins.bigswitch.extensions import routerrule


LOG = logging.getLogger(__name__)

extra_route_opts = [
    cfg.IntOpt('max_rules', default=100,
               help=_("Maximum number of router rules")),
]

cfg.CONF.register_opts(extra_route_opts)


class RouterRule(model_base.BASEV2):
            id = sa.Column(sa.Integer, primary_key=True)
            source = sa.Column(sa.String(64), nullable=False)
            destination = sa.Column(sa.String(64), nullable=False)
            nexthops = orm.relationship('NextHop', cascade='all,delete')
            action = sa.Column(sa.String(10), nullable=False)
	    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"))

class NextHop(model_base.BASEV2):
           rule_id = sa.Column(sa.Integer,
                               sa.ForeignKey('routerrules.id',
                                             ondelete="CASCADE"),primary_key=True)
           nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


class RouterRule_db_mixin(l3_db.L3_NAT_db_mixin):
    """ Mixin class to support route rule configuration on a router"""
    def update_router(self, context, id, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, id)
            if 'router_rules' in r:
                self._update_router_rules(context,
                                          router_db,
                                          r['router_rules'])
            router_updated = super(RouterRule_db_mixin, self).update_router(
                context, id, router)
            router_updated['router_rules'] = self._get_router_rules_by_router_id(
                context, id)

        return router_updated

    def create_router(self, context, router):
        r = router['router']
        with context.session.begin(subtransactions=True):
            router_db = super(RouterRule_db_mixin, self).create_router(
                context, router)
            if 'router_rules' in r:
                self._update_router_rules(context,
                                          router_db,
                                          r['router_rules'])
            else:
                LOG.debug('No rules in router')
            router_db['router_rules'] = self._get_router_rules_by_router_id(
                context, router_db['id'])

        return router_db


    def _validate_rules(self, context,
                         router_id, rules):
        if len(routes) > cfg.CONF.max_routes:
            raise routerrule.RoutesExhausted(
                router_id=router_id,
                quota=cfg.CONF.max_rules)

    def _update_router_rules(self, context, router, rules):
        query = context.session.query(RouterRule)
        router_rules = query.filter(RouterRule.router_id == router['id']).all()
        for rule in router_rules:
            nh_del_context = context.session.query(NextHop)
            nh_del_context.filter_by(rule_id=rule['id']).delete()
        del_context = context.session.query(RouterRule)
        del_context.filter_by(router_id=router['id']).delete()        
        context.session.flush()
        LOG.debug('Rules are %s' % rules)
        for rule in rules:
            router_rule = RouterRule(
                router_id=router['id'],
                destination=rule['destination'],
                source=rule['source'],
                action=rule['action'])
            context.session.add(router_rule)
            context.session.flush()
            nexthops=[NextHop(rule_id=router_rule.id,nexthop=hop) for hop in rule['nexthops']]
            for hop in nexthops:
                context.session.add(hop)


    def _diff_list_of_dict_with_list(self,old_list,new_list): #TODO: remove
       new_set = set([json.dumps(l) for l in new_list])
       old_set = set([json.dumps(l) for l in old_list])
       added = new_set - old_set
       removed = old_set - new_set
       return [json.loads(a) for a in added], [json.loads(r) for r in removed]

    def _make_router_rule_list(self, router_rules):
        ruleslist = []
        for rule in router_rules:
             hops = [hop['nexthop'] for hop in rule['nexthops']]
             ruleslist.append({'id': rule['id'],
                               'destination': rule['destination'],
                               'source': rule['source'],
                               'action': rule['action'],
                               'nexthops': hops})
        return ruleslist

    def _get_router_rules_by_router_id(self, context, id):
        query = context.session.query(RouterRule)
        router_rules = query.filter(RouterRule.router_id == id).all()
        return self._make_router_rule_list(router_rules)

    def get_router(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            router = super(RouterRule_db_mixin, self).get_router(
                context, id, fields)
            router['router_rules'] = self._get_router_rules_by_router_id(
                context, id)
            return router

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with context.session.begin(subtransactions=True):
            routers = super(RouterRule_db_mixin, self).get_routers(
                context, filters, fields, sorts=sorts, limit=limit,
                marker=marker, page_reverse=page_reverse)
            for router in routers:
                router['router_rules'] = self._get_router_rules_by_router_id(
                    context, router['id'])
            return routers

    def get_sync_data(self, context, router_ids=None, active=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            routers = super(RouterRule_db_mixin,
                            self).get_sync_data(context, router_ids,
                                                active=active)
            for router in routers:
                router['router_rules'] = self._get_router_rules_by_router_id(
                    context, router['id'])
        return routers

