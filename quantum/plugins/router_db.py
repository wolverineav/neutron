# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Big Switch Networks, Inc.  All rights reserved.
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
# Adapted from l3_db.py
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com
#

import netaddr
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr
import webob.exc as w_exc

from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum.db import db_base_plugin_v2
from quantum.db import l3_db
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import l3
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils
from quantum import policy


LOG = logging.getLogger(__name__)


class Router_db_mixin(l3_db.L3_NAT_db_mixin):

    def create_router(self, context, router):
        LOG.error("Router_db_mixin.create_router() called")
        r = router['router']

        if 'external_gateway_info' in r and r['external_gateway_info']:
            msg = "Setting of external gateway not supported in this version"
            raise q_exc.BadRequest(resource='router', msg=msg)

        return super(Router_db_mixin, self).create_router(context, router)

    """
    def create_floatingip(self, context, floatingip):
        return super(Router_db_mixin, self).creating_floatingip(context,
                                                                floatingip)

    def update_floatingip(self, context, id, floatingip):
        return super(Router_db_mixin, self).update_floatingip(context, id,
                                                              floatingip)

    def delete_floatingip(self, context, id):
        return super(Router_db_mixin, self).delete_floatingip(context, id)

    def get_floatingip(self, context, id, fields=None):
        return super(Router_db_mixin, self).get_floatingip(context, id,
                                                           fields)

    def get_floatingips(self, context, filters=None, fields=None):
        return super(Router_db_mixin, self).get_floatingips(context, filters,
                                                            fields)

    def get_floatingips_count(self, context, filters=None):
        return super(Router_db_mixin, self).get_floatingips_count(context,
                                                                  filters)
    """
