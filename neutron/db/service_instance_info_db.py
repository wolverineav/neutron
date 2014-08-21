# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013 OpenStack Foundation.
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

import sqlalchemy as sa
from sqlalchemy.orm import exc as sa_exc

from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.extensions import serviceinstanceinfo
from neutron import manager
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class ServiceInstanceInfo(model_base.BASEV2):
    """ Represents a neutron service instance info. """

    __tablename__ = 'service_instance_info'
    id = sa.Column(sa.String(36), primary_key=True)
    service_name = sa.Column(sa.String(255), nullable=False)


class ServiceInstanceInfoDbMixin(
    serviceinstanceinfo.ServiceInstanceInfoPluginBase,
    base_db.CommonDbMixin):
    """Mixin class for ServiceInstanceInfo DB implementation."""

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_service_instance_info(self, context, id):
        try:
            return self._get_by_id(context, ServiceInstanceInfo, id)
        except sa_exc.NoResultFound:
            raise serviceinstanceinfo.ServiceInstanceNotFound(id=id)

    def _make_service_instance_info_dict(self, serviceinstanceinfo,
                                         fields=None):
        res = {'id': serviceinstanceinfo['id'],
               'service_name': serviceinstanceinfo['service_name']}
        return self._fields(res, fields)

    def get_service_instance_infos(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        LOG.debug(_("get_service_instance_infos() called"))
        return self._get_collection(context, ServiceInstanceInfo,
                                    self._make_service_instance_info_dict,
                                    filters=filters, fields=fields)

    def get_service_instance_info(self, context, id, fields=None):
        LOG.debug(_("get_service_instance_info() called"))
        serviceinstanceinfo = self._get_service_instance_info(context, id)
        return self._make_service_instance_info_dict(serviceinstanceinfo,
                                                     fields)

    def register_service_instance(self, context, service_instance_info):
        LOG.debug(_("create_service_instance_info() called"))
        service_instance_info = service_instance_info['service_instance_info']
        with context.session.begin(subtransactions=True):
            serviceinstanceinfo_db = ServiceInstanceInfo(
                id=service_instance_info['id'],
                service_name=service_instance_info['service_name'])
            context.session.add(serviceinstanceinfo_db)
        return self._make_service_instance_info_dict(serviceinstanceinfo_db)

    def unregister_service_instance(self, context, id):
        LOG.debug(_("delete_service_instance_info() called"))
        with context.session.begin(subtransactions=True):
            try:
                serviceinstanceinfo_db = (context.session.
                    query(ServiceInstanceInfo).
                    enable_eagerloads(False).
                    filter_by(id=id).with_lockmode('update').one())
            except sa_exc.NoResultFound:
                LOG.error(_("The service instance info '%s' doesn't exist"),
                          id)
                return

            serviceinstanceinfo_query = context.session.query(
                ServiceInstanceInfo).with_lockmode('update')
            serviceinstanceinfo_db = (serviceinstanceinfo_query.
                                      filter_by(id=id).one())
            context.session.delete(serviceinstanceinfo_db)
