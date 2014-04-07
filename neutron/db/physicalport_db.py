# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 IBM Corp.
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
#    @author: Kanzhe Jiang, Big Switch Networks

import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import physicalport
from neutron.extensions.physicalport import PhysicalPortPluginBase
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)

class PhysicalPort(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """ Represents a neutron physical port. """

    __tablename__ = 'physical_ports'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='SET NULL'),
                        nullable=True)
    name = sa.Column(sa.String(255))
    mac_address = sa.Column(sa.String(32), nullable=False)
    attachment = sa.Column(sa.String(255), nullable=False)
    admin_state_up = sa.Column(sa.Boolean)

    def __init__(self, id=None, tenant_id=None, port_id=None, name=None,
                 mac_address=None, attachment=None, admin_state_up=None):
        self.id = id
        self.tenant_id = tenant_id
        self.port_id = port_id 
        self.name = name 
        self.mac_address = mac_address 
        self.attachment = attachment 
        self.admin_state_up = admin_state_up

 
class PhysicalPortDbMixin(PhysicalPortPluginBase, base_db.CommonDbMixin):
    """Mixin class for PhysicalPort DB implementation."""

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_physical_port(self, context, id):
        try:
            return self._get_by_id(context, PhysicalPort, id)
        except exc.NoResultFound:
            raise physicalport.PhysicalPortNotFound(id=id)

    def _make_physical_port_dict(self, physicalport, fields=None):
        res = {'id': physicalport['id'],
               'tenant_id': physicalport['tenant_id'],
               'name': physicalport['name'],
               'mac_address': physicalport['mac_address'],
               'attachment': physicalport['attachment'],
               'admin_state_up': physicalport['admin_state_up'],
               'port_id': physicalport['port_id']}
        return self._fields(res, fields)

    def get_physical_ports(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        LOG.debug(_("get_physical_ports() called"))
        return self._get_collection(context, PhysicalPort,
                                    self._make_physical_port_dict,
                                    filters=filters, fields=fields)

    def get_physical_port(self, context, id, fields=None):
        LOG.debug(_("get_physical_port() called"))
        physicalport = self._get_physical_port(context, id)
        return self._make_physical_port_dict(physicalport, fields)

    def create_physical_port(self, context, physical_port):
        LOG.debug(_("create_physical_port() called"))
        physical_port = physical_port['physical_port']
        tenant_id = self._get_tenant_id_for_create(context, physical_port)
        with context.session.begin(subtransactions=True):
            physicalport_db = PhysicalPort(id=uuidutils.generate_uuid(),
                                   tenant_id=tenant_id,
                                   name=physical_port['name'],
                                   mac_address=physical_port['mac_address'],
                                   attachment=physical_port['attachment'],
                                   port_id=physical_port['port_id'],
                                   admin_state_up=physical_port['admin_state_up'])
            context.session.add(physicalport_db)
        return self._make_physical_port_dict(physicalport_db)

    def update_physical_port(self, context, id, physical_port):
        LOG.debug(_("update_physical_port() called"))
        physical_port = physical_port['physical_port']
        with context.session.begin(subtransactions=True):
            physicalport_query = context.session.query(
                PhysicalPort).with_lockmode('update')
            physicalport_db = physicalport_query.filter_by(id=id).one()
            physicalport_db.update(physical_port)
        return self._make_physical_port_dict(physicalport_db)

    def delete_physical_port(self, context, id):
        LOG.debug(_("delete_physical_port() called"))
        with context.session.begin(subtransactions=True):
            try:
                pport_db = (session.query(physicalport_db.PhysicalPort).
                           enable_eagerloads(False).
                           filter_by(id=id).with_lockmode('update').one())
            except sa_exc.NoResultFound:
                LOG.error(_("The phyiscal port '%s' doesn't exist"), id)
                return

            port_id = pport_db.get('port_id')
            if port_id:
                self.delete_port(context, port_id)

            physicalport_query = context.session.query(
                PhysicalPort).with_lockmode('update')
            physicalport_db = physicalport_query.filter_by(id=id).one()
            # Note: Plugin should ensure that it's okay to delete if the
            # physicalport is in use
            context.session.delete(physicalport_db)
