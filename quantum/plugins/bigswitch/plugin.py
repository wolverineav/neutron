# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2012 Big Switch Networks, Inc.
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
# @author: Mandeep Dhami, Big Switch Networks, Inc.
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

"""
Quantum REST Proxy Plug-in for Big Switch and FloodLight Controllers

QuantumRestProxy provides a generic quantum plugin that translates all plugin
function calls to equivalent authenticated REST calls to a set of redundant
external network controllers. It also keeps persistent store for all quantum
state to allow for re-sync of the external controller(s), if required.

The local state on the plugin also allows for local response and fast-fail
semantics where it can be determined based on the local persistent store.

Network controller specific code is decoupled from this plugin and expected
to reside on the controller itself (via the REST interface).

This allows for:
 - independent authentication and redundancy schemes between quantum and the
   network controller
 - independent upgrade/development cycles between quantum and the controller
   as it limits the proxy code upgrade requirement to quantum release cycle
   and the controller specific code upgrade requirement to controller code
 - ability to sync the controller with quantum for independent recovery/reset

External REST API used by proxy is the same API as defined for quantum (JSON
subset) with some additional parameters (gateway on network-create and macaddr
on port-attach) on an additional PUT to do a bulk dump of all persistent data.
"""

import base64
import copy
import httplib
import json
import socket

from quantum.common import constants as const
from quantum.common import exceptions
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum import context as qcontext
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.plugins.bigswitch import router_db
from quantum.plugins.bigswitch.version import version_string_with_vcs


LOG = logging.getLogger(__name__)


database_opts = [
    cfg.StrOpt('sql_connection', default='sqlite://'),
    cfg.IntOpt('sql_max_retries', default=-1),
    cfg.IntOpt('reconnect_interval', default=2),
]


restproxy_opts = [
    cfg.StrOpt('servers', default='localhost:8800'),
    cfg.StrOpt('serverauth', default='username:password'),
    cfg.BoolOpt('serverssl', default=False),
    cfg.BoolOpt('syncdata', default=False),
    cfg.IntOpt('servertimeout', default=10),
    cfg.StrOpt('quantumid', default='Quantum'),
]


cfg.CONF.register_opts(database_opts, "DATABASE")
cfg.CONF.register_opts(restproxy_opts, "RESTPROXY")


# The following are used to invoke the API on the external controller
NET_RESOURCE_PATH = "/tenants/%s/networks"
PORT_RESOURCE_PATH = "/tenants/%s/networks/%s/ports"
ROUTER_RESOURCE_PATH = "/tenants/%s/routers"
ROUTER_INTF_OP_PATH = "/tenants/%s/routers/%s/interfaces"
NETWORKS_PATH = "/tenants/%s/networks/%s"
PORTS_PATH = "/tenants/%s/networks/%s/ports/%s"
ATTACHMENT_PATH = "/tenants/%s/networks/%s/ports/%s/attachment"
ROUTERS_PATH = "/tenants/%s/routers/%s"
ROUTER_INTF_PATH = "/tenants/%s/routers/%s/interfaces/%s"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]
SYNTAX_ERROR_MESSAGE = 'Syntax error in server config file, aborting plugin'
BASE_URI = '/quantum/v1.1'


class RemoteRestError(exceptions.QuantumException):
    def __init__(self, message):
        if message is None:
            message = "None"
        self.message = _("Error in REST call to remote network "
                         "controller") + ": " + message
        super(RemoteRestError, self).__init__()


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, quantumid, timeout,
                 base_uri, name):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = SUCCESS_CODES
        self.auth = None
        self.quantum_id = quantumid
        if auth:
            self.auth = 'Basic ' + base64.encodestring(auth).strip()

    def rest_call(self, action, resource, data, headers):
        uri = self.base_uri + resource
        body = json.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['QuantumProxy-Agent'] = self.name
        headers['Instance-ID'] = self.quantum_id
        if self.auth:
            headers['Authorization'] = self.auth

        LOG.debug('ServerProxy: server=%s, port=%d, ssl=%r, action=%s' %
                  (self.server, self.port, self.ssl, action))
        LOG.debug('ServerProxy: resource=%s, data=%r, headers=%r' %
                  (resource, data, headers))

        conn = None
        if self.ssl:
            conn = httplib.HTTPSConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error('ServerProxy: Could not establish HTTPS connection')
                return 0, None, None, None
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error('ServerProxy: Could not establish HTTP connection')
                return 0, None, None, None

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except (socket.timeout, socket.error) as e:
            LOG.error('ServerProxy: %s failure, %r' % (action, e))
            ret = 0, None, None, None
        conn.close()
        LOG.debug('ServerProxy: status=%d, reason=%r, ret=%s, data=%r' % ret)
        return ret


class ServerPool(object):
    def __init__(self, servers, ssl, auth, quantumid, timeout=10,
                 base_uri='/quantum/v1.0', name='QuantumRestProxy'):
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.auth = auth
        self.quantum_id = quantumid
        self.ssl = ssl
        self.servers = []
        for server_port in servers:
            self.servers.append(self.server_proxy_for(*server_port))

    def server_proxy_for(self, server, port):
        return ServerProxy(server, port, self.ssl, self.auth, self.quantum_id,
                           self.timeout, self.base_uri, self.name)

    def server_failure(self, resp):
        """Define failure codes as required.
        Note: We assume 301-303 is a failure, and try the next server in
        the server pool.
        """
        return resp[0] in FAILURE_CODES

    def action_success(self, resp):
        """Defining success codes as required.
        Note: We assume any valid 2xx as being successful response.
        """
        return resp[0] in SUCCESS_CODES

    def rest_call(self, action, resource, data, headers):
        failed_servers = []
        while self.servers:
            active_server = self.servers[0]
            ret = active_server.rest_call(action, resource, data, headers)
            if not self.server_failure(ret):
                self.servers.extend(failed_servers)
                return ret
            else:
                LOG.error('ServerProxy: %s failure for servers: %r' % (
                    action, (active_server.server, active_server.port)))
                failed_servers.append(self.servers.pop(0))

        # All servers failed, reset server list and try again next time
        LOG.error('ServerProxy: %s failure for all servers: %r' % (
            action, tuple((s.server, s.port) for s in failed_servers)))
        self.servers.extend(failed_servers)
        return (0, None, None, None)

    def get(self, resource, data='', headers=None):
        return self.rest_call('GET', resource, data, headers)

    def put(self, resource, data, headers=None):
        return self.rest_call('PUT', resource, data, headers)

    def post(self, resource, data, headers=None):
        return self.rest_call('POST', resource, data, headers)

    def delete(self, resource, data='', headers=None):
        return self.rest_call('DELETE', resource, data, headers)


class RpcProxy(dhcp_rpc_base.DhcpRpcCallbackMixin):

    RPC_API_VERSION = '1.0'

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])


class QuantumRestProxyV2(db_base_plugin_v2.QuantumDbPluginV2,
                         router_db.Router_db_mixin):

    supported_extension_aliases = ["router"]

    def __init__(self):
        LOG.info('QuantumRestProxy: Starting plugin. Version=%s' %
                 version_string_with_vcs())

        # init DB, proxy's persistent store defaults to in-memory sql-lite DB
        options = {"sql_connection": "%s" % cfg.CONF.DATABASE.sql_connection,
                   "sql_max_retries": cfg.CONF.DATABASE.sql_max_retries,
                   "reconnect_interval": cfg.CONF.DATABASE.reconnect_interval,
                   "base": models_v2.model_base.BASEV2}
        db.configure_db(options)

        # 'servers' is the list of network controller REST end-points
        # (used in order specified till one suceeds, and it is sticky
        # till next failure). Use 'serverauth' to encode api-key
        servers = cfg.CONF.RESTPROXY.servers
        serverauth = cfg.CONF.RESTPROXY.serverauth
        serverssl = cfg.CONF.RESTPROXY.serverssl
        syncdata = cfg.CONF.RESTPROXY.syncdata
        timeout = cfg.CONF.RESTPROXY.servertimeout
        quantumid = cfg.CONF.RESTPROXY.quantumid

        # validate config
        assert servers is not None, 'Servers not defined. Aborting plugin'
        servers = tuple(s.rsplit(':', 1) for s in servers.split(','))
        servers = tuple((server, int(port)) for server, port in servers)
        assert all(len(s) == 2 for s in servers), SYNTAX_ERROR_MESSAGE

        # init network ctrl connections
        self.servers = ServerPool(servers, serverssl, serverauth, quantumid,
                                  timeout, BASE_URI)

        # init dhcp support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.callbacks = RpcProxy()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        if syncdata:
            self._send_all_data()

        LOG.debug("QuantumRestProxyV2: initialization done")

    def create_network(self, context, network):
        """Create a network, which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        :param context: quantum api request context
        :param network: dictionary describing the network

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can specify
                         a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxyV2: create_network() called")

        self._warn_on_state_status(network['network'])

        # Validate args
        tenant_id = self._get_tenant_id_for_create(context, network["network"])

        session = context.session
        with session.begin(subtransactions=True):
            # create network in DB
            new_net = super(QuantumRestProxyV2, self).create_network(context,
                                                                     network)
            self._process_l3_create(context, network['network'], new_net['id'])
            self._extend_network_dict_l3(context, new_net)

        # create network on the network controller
        try:
            resource = NET_RESOURCE_PATH % tenant_id
            mapped_network = self._get_mapped_network_with_subnets(new_net)
            data = {
                "network": mapped_network
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to create remote network:%s" %
                      e.message)
            super(QuantumRestProxyV2, self).delete_network(context,
                                                           new_net['id'])
            raise

        # return created network
        return new_net

    def update_network(self, context, net_id, network):
        """Updates the properties of a particular Virtual Network.
        :param context: quantum api request context
        :param net_id: uuid of the network to update
        :param network: dictionary describing the updates

        :returns: a sequence of mappings with the following signature:
        {
            "id": UUID representing the network.
            "name": Human-readable name identifying the network.
            "tenant_id": Owner of network. NOTE: only admin user can
                         specify a tenant_id other than its own.
            "admin_state_up": Sets admin state of network.
                              if down, network does not forward packets.
            "status": Indicates whether network is currently operational
                      (values are "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "subnets": Subnets associated with this network.
        }

        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxyV2.update_network() called")

        self._warn_on_state_status(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                                   net_id)
            tenant_id = orig_net["tenant_id"]
            new_net = super(QuantumRestProxyV2, self).update_network(context,
                                                                     net_id,
                                                                     network)
            self._process_l3_update(context, network['network'], net_id)
            self._extend_network_dict_l3(context, new_net)

        # update network on network controller
        try:
            self._send_update_network(new_net)
        except RemoteRestError as e:
            # reset network to original state
            super(QuantumRestProxyV2, self).update_network(context, id,
                                                           orig_net)
            raise

        # return updated network
        return new_net

    def delete_network(self, context, net_id):
        """Delete a network.
        :param context: quantum api request context
        :param id: UUID representing the network to delete.

        :returns: None

        :raises: exceptions.NetworkInUse
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: delete_network() called")

        # Validate args
        orig_net = super(QuantumRestProxyV2, self).get_network(context, net_id)
        tenant_id = orig_net["tenant_id"]

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = NETWORKS_PATH % (tenant_id, net_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            ret_val = super(QuantumRestProxyV2, self).delete_network(context,
                                                                     net_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote network: %s" %
                e.message)
            raise

    def create_port(self, context, port):
        """Create a port, which is a connection point of a device
        (e.g., a VM NIC) to attach to a L2 Quantum network.
        :param context: quantum api request context
        :param port: dictionary describing the port

        :returns:
        {
            "id": uuid represeting the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": Sets admin state of port. if down, port
                              does not forward packets.
            "status": dicates whether port is currently operational
                      (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet ID"s and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.StateInvalid
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: create_port() called")

        # Update DB
        port["port"]["admin_state_up"] = False
        new_port = super(QuantumRestProxyV2, self).create_port(context, port)
        net = super(QuantumRestProxyV2,
                    self).get_network(context, new_port["network_id"])

        # create on networl ctrl
        try:
            resource = PORT_RESOURCE_PATH % (net["tenant_id"], net["id"])
            mapped_port = self._map_state_and_status(new_port)
            data = {
                "port": mapped_port
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            # connect device to network, if present
            if port["port"].get("device_id"):
                self._plug_interface(context,
                                     net["tenant_id"], net["id"],
                                     new_port["id"], new_port["id"] + "00")
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2: Unable to create remote port: %s" %
                      e.message)
            super(QuantumRestProxyV2, self).delete_port(context,
                                                        new_port["id"])
            raise

        # Set port state up and return that port
        port_update = {"port": {"admin_state_up": True}}
        return super(QuantumRestProxyV2, self).update_port(context,
                                                           new_port["id"],
                                                           port_update)

    def update_port(self, context, port_id, port):
        """Update values of a port.
        :param context: quantum api request context
        :param id: UUID representing the port to update.
        :param port: dictionary with keys indicating fields to update.

        :returns: a mapping sequence with the following signature:
        {
            "id": uuid represeting the port.
            "network_id": uuid of network.
            "tenant_id": tenant_id
            "mac_address": mac address to use on this port.
            "admin_state_up": sets admin state of port. if down, port
                               does not forward packets.
            "status": dicates whether port is currently operational
                       (limit values to "ACTIVE", "DOWN", "BUILD", and "ERROR")
            "fixed_ips": list of subnet ID's and IP addresses to be used on
                         this port
            "device_id": identifies the device (e.g., virtual server) using
                         this port.
        }

        :raises: exceptions.StateInvalid
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: update_port() called")

        self._warn_on_state_status(port['port'])

        # Validate Args
        orig_port = super(QuantumRestProxyV2, self).get_port(context, port_id)

        # Update DB
        new_port = super(QuantumRestProxyV2, self).update_port(context,
                                                               port_id, port)

        # update on networl ctrl
        try:
            resource = PORTS_PATH % (orig_port["tenant_id"],
                                     orig_port["network_id"], port_id)
            mapped_port = self._map_state_and_status(new_port)
            data = {"port": mapped_port}
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            if new_port.get("device_id") != orig_port.get("device_id"):
                if orig_port.get("device_id"):
                    self._unplug_interface(context, orig_port["tenant_id"],
                                           orig_port["network_id"],
                                           orig_port["id"])
                if new_port.get("device_id"):
                    self._plug_interface(context, new_port["tenant_id"],
                                         new_port["network_id"],
                                         new_port["id"], new_port["id"] + "00")

        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to create remote port: %s" %
                e.message)
            # reset port to original state
            super(QuantumRestProxyV2, self).update_port(context, port_id,
                                                        orig_port)
            raise

        # return new_port
        return new_port

    def delete_port(self, context, port_id, l3_port_check=True):
        """Delete a port.
        :param context: quantum api request context
        :param id: UUID representing the port to delete.

        :raises: exceptions.PortInUse
        :raises: exceptions.PortNotFound
        :raises: exceptions.NetworkNotFound
        :raises: RemoteRestError
        """

        LOG.debug("QuantumRestProxyV2: delete_port() called")

        # Delete from DB
        port = super(QuantumRestProxyV2, self).get_port(context, port_id)

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = PORTS_PATH % (port["tenant_id"], port["network_id"],
                                     port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])

            # if needed, check to see if this is a port owned by
            # and l3-router.  If so, we should prevent deletion.
            if l3_port_check:
                self.prevent_l3_port_deletion(context, port_id)

            if port.get("device_id"):
                self._unplug_interface(context, port["tenant_id"],
                                       port["network_id"], port["id"])
            ret_val = super(QuantumRestProxyV2, self).delete_port(context,
                                                                  port_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote port: %s" %
                e.message)
            raise

    def _plug_interface(self, context, tenant_id, net_id, port_id,
                        remote_interface_id):
        """Attaches a remote interface to the specified port on the
        specified Virtual Network.

        :returns: None

        :raises: exceptions.NetworkNotFound
        :raises: exceptions.PortNotFound
        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: _plug_interface() called")

        # update attachment on network controller
        try:
            port = super(QuantumRestProxyV2, self).get_port(context, port_id)
            mac = port["mac_address"]

            for ip in port["fixed_ips"]:
                if ip.get("subnet_id") is not None:
                    subnet = super(QuantumRestProxyV2, self).get_subnet(
                        context, ip["subnet_id"])
                    gateway = subnet.get("gateway_ip")
                    if gateway is not None:
                        resource = NETWORKS_PATH % (tenant_id, net_id)
                        orig_net = super(QuantumRestProxyV2,
                                         self).get_network(context, net_id)
                        mapped_network = self._map_state_and_status(orig_net)
                        mapped_network['gateway'] = gateway
                        data = {"network": mapped_network}
                        ret = self.servers.put(resource, data)
                        if not self.servers.action_success(ret):
                            raise RemoteRestError(ret[2])

            if mac is not None:
                resource = ATTACHMENT_PATH % (tenant_id, net_id, port_id)
                data = {"attachment":
                        {"id": remote_interface_id,
                         "mac": mac,
                         }
                        }
                ret = self.servers.put(resource, data)
                if not self.servers.action_success(ret):
                    raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to update remote network:%s" %
                      e.message)
            raise

    def _unplug_interface(self, context, tenant_id, net_id, port_id):
        """Detaches a remote interface from the specified port on the
        network controller

        :returns: None

        :raises: RemoteRestError
        """
        LOG.debug("QuantumRestProxyV2: _unplug_interface() called")

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = ATTACHMENT_PATH % (tenant_id, net_id, port_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote port: %s" %
                e.message)

    def create_subnet(self, context, subnet):
        LOG.debug("QuantumRestProxyV2: create_subnet() called")

        self._warn_on_state_status(subnet['subnet'])

        # create subnet in DB
        new_subnet = super(QuantumRestProxyV2, self).create_subnet(context,
                                                                   subnet)
        net_id = new_subnet['network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            # rollback creation of subnet
            super(QuantumRestProxyV2, self).delete_subnet(context,
                                                          subnet['id'])
            raise
        return new_subnet

    def update_subnet(self, context, id, subnet):
        LOG.debug("QuantumRestProxyV2: update_subnet() called")

        self._warn_on_state_status(subnet['subnet'])

        orig_subnet = super(QuantumRestProxyV2, self).get_subnet(context, id)

        # update subnet in DB
        new_subnet = super(QuantumRestProxyV2, self).update_subnet(context, id,
                                                                   subnet)
        net_id = new_subnet['network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            # rollback updation of subnet
            super(QuantumRestProxyV2, self).update_subnet(context, id,
                                                          orig_subnet)
            raise
        return new_subnet

    def delete_subnet(self, context, id):
        LOG.debug("QuantumRestProxyV2: delete_subnet() called")
        orig_subnet = super(QuantumRestProxyV2, self).get_subnet(context, id)
        net_id = orig_subnet['network_id']
        # delete subnet in DB
        super(QuantumRestProxyV2, self).delete_subnet(context, id)
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            # TODO (Sumit): rollback deletion of subnet
            raise

    def create_router(self, context, router):
        LOG.debug("QuantumRestProxyV2: create_router() called")

        self._warn_on_state_status(router['router'])

        tenant_id = self._get_tenant_id_for_create(context, router["router"])

        # create router in DB
        new_router = super(QuantumRestProxyV2, self).create_router(context,
                                                                   router)

        # create router on the network controller
        try:
            resource = ROUTER_RESOURCE_PATH % tenant_id
            mapped_router = self._map_state_and_status(new_router)
            data = {
                "router": mapped_router
            }
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to create remote router:%s" %
                      e.message)
            super(QuantumRestProxyV2, self).delete_router(context,
                                                          new_router['id'])
            raise

        # return created router
        return new_router

    def update_router(self, context, router_id, router):

        LOG.debug("QuantumRestProxyV2.update_router() called")

        self._warn_on_state_status(router['router'])

        orig_router = super(QuantumRestProxyV2, self).get_router(context,
                                                                 router_id)
        tenant_id = orig_router["tenant_id"]
        new_router = super(QuantumRestProxyV2, self).update_router(context,
                                                                   router_id,
                                                                   router)

        # update router on network controller
        try:
            resource = ROUTERS_PATH % (tenant_id, router_id)
            mapped_router = self._map_state_and_status(new_router)
            data = {
                "router": mapped_router
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote router: %s" %
                e.message)
            # reset router to original state
            super(QuantumRestProxyV2, self).update_router(context,
                                                          router_id,
                                                          orig_router)
            raise

        # return updated router
        return new_router

    def delete_router(self, context, router_id):
        LOG.debug("QuantumRestProxyV2: delete_router() called")

        # Validate args
        orig_router = super(QuantumRestProxyV2, self).get_router(context,
                                                                 router_id)
        tenant_id = orig_router["tenant_id"]

        # delete from network ctrl. Remote error on delete is ignored
        try:
            resource = ROUTERS_PATH % (tenant_id, router_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            ret_val = super(QuantumRestProxyV2, self).delete_router(context,
                                                                    router_id)
            return ret_val
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to delete remote router: %s" %
                e.message)
            raise

    def add_router_interface(self, context, router_id, interface_info):

        LOG.debug("QuantumRestProxyV2: add_router_interface() called")

        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # create interface in DB
        new_interface_info = super(QuantumRestProxyV2,
                                   self).add_router_interface(context,
                                                              router_id,
                                                              interface_info)
        port = self._get_port(context, new_interface_info['port_id'])
        net_id = port['network_id']
        subnet_id = new_interface_info['subnet_id']
        # we will use the port's network id as interface's id
        interface_id = net_id
        intf_details = self._get_router_intf_details(context,
                                                     router_id,
                                                     interface_id,
                                                     subnet_id)

        # create interface on the network controller
        try:
            resource = ROUTER_INTF_OP_PATH % (tenant_id, router_id)
            data = {"interface": intf_details}
            ret = self.servers.post(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to create interface :%s" %
                      e.message)
            super(QuantumRestProxyV2,
                  self).remove_router_interface(context, router_id,
                                                interface_info)
            raise

        return new_interface_info

    def remove_router_interface(self, context, router_id, interface_info):

        LOG.debug("QuantumRestProxyV2: remove_router_interface() called")

        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # we will first get the interface identifier before deleting in the DB
        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port = self._get_port(context, interface_info['port_id'])
            interface_id = port['network_id']
        elif 'subnet_id' in interface_info:
            subnet = self._get_subnet(context, interface_info['subnet_id'])
            interface_id = subnet['network_id']
        else:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)

        # remove router in DB
        del_intf_info = super(QuantumRestProxyV2,
                              self).remove_router_interface(context,
                                                            router_id,
                                                            interface_info)

        # create router on the network controller
        try:
            resource = ROUTER_INTF_PATH % (tenant_id, router_id, interface_id)
            ret = self.servers.delete(resource)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to delete remote intf :%s" %
                      e.message)
            raise

        # return new interface
        return del_intf_info

    def create_floatingip(self, context, floatingip):
        LOG.debug("QuantumRestProxyV2: create_floatingip() called")

        # create floatingip in DB
        new_fl_ip = super(QuantumRestProxyV2,
                          self).create_floatingip(context, floatingip)

        net_id = new_fl_ip['floating_network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # create floatingip on the network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            LOG.error("QuantumRestProxyV2:Unable to create remote floatingip: "
                      "%s" % e.message)
            super(QuantumRestProxyV2, self).delete_floatingip(context,
                                                              floatingip)
            raise

        # return created floating IP
        return new_fl_ip

    def update_floatingip(self, context, id, floatingip):
        LOG.debug("QuantumRestProxyV2: update_floatingip() called")

        orig_fl_ip = super(QuantumRestProxyV2, self).get_floatingip(context,
                                                                    id)

        # update floatingip in DB
        new_fl_ip = super(QuantumRestProxyV2,
                          self).update_floatingip(context, id, floatingip)

        net_id = new_fl_ip['floating_network_id']
        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            # rollback updation of subnet
            super(QuantumRestProxyV2, self).update_floatingip(context, id,
                                                              floatingip)
            raise
        return new_fl_ip

    def delete_floatingip(self, context, id):
        LOG.debug("QuantumRestProxyV2: delete_floatingip() called")

        orig_fl_ip = super(QuantumRestProxyV2, self).get_floatingip(context,
                                                                    id)
        # delete floating IP in DB
        net_id = orig_fl_ip['floating_network_id']
        super(QuantumRestProxyV2, self).delete_floatingip(context, id)

        orig_net = super(QuantumRestProxyV2, self).get_network(context,
                                                               net_id)
        # update network on network controller
        try:
            self._send_update_network(orig_net)
        except RemoteRestError as e:
            # TODO(Sumit): rollback deletion of floating IP
            raise

    def _send_all_data(self):
        """Pushes all data to network ctrl (networks/ports, ports/attachments)
        to give the controller an option to re-sync it's persistent store
        with quantum's current view of that data.
        """
        admin_context = qcontext.get_admin_context()
        networks = []
        routers = []

        all_networks = super(QuantumRestProxyV2,
                             self).get_networks(admin_context) or []
        for net in all_networks:
            mapped_network = self._get_mapped_network_with_subnets(net)

            ports = []
            net_filter = {'network_id': [net.get('id')]}
            net_ports = super(QuantumRestProxyV2,
                              self).get_ports(admin_context,
                                              filters=net_filter) or []
            for port in net_ports:
                mapped_port = self._map_state_and_status(port)
                mapped_port['attachment'] = {
                    'id': port.get('id') + '00',
                    'mac': port.get('mac_address'),
                }
                ports.append(mapped_port)
            mapped_network['ports'] = ports

            networks.append(mapped_network)

        all_routers = super(QuantumRestProxyV2,
                            self).get_routers(admin_context) or []
        for router in all_routers:
            interfaces = []
            mapped_router = self._map_state_and_status(router)
            router_filter = {
                'device_owner': ["network:router_interface"],
                'device_id': [router.get('id')]
            }
            router_ports = super(QuantumRestProxyV2,
                                 self).get_ports(admin_context,
                                                 filters=router_filter) or []
            #LOG.error("Sumit: ports %s" % router_ports)
            for port in router_ports:
                net_id = port.get('network_id')
                subnet_id = port['fixed_ips'][0]['subnet_id']
                intf_details = self._get_router_intf_details(admin_context,
                                                             router.get('id'),
                                                             net_id,
                                                             subnet_id)
                interfaces.append(intf_details)
            mapped_router['interfaces'] = interfaces

            routers.append(mapped_router)

        try:
            resource = '/topology'
            data = {
                'networks': networks,
                'routers': routers,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
            return ret
        except RemoteRestError as e:
            LOG.error(
                'QuantumRestProxy: Unable to update remote topology: %s' %
                e.message)
            raise

    def _get_network_with_floatingips(self, network):
        admin_context = qcontext.get_admin_context()

        if 'router:external' in network:
            if network['router:external']:
                net_id = network['id']
                net_filter = {'floating_network_id': [net_id]}
                fl_ips = super(QuantumRestProxyV2,
                               self).get_floatingips(admin_context,
                                                     filters=net_filter) or []
                network['floatingips'] = fl_ips

        return network

    def _get_all_subnets_json_for_network(self, net_id):
        admin_context = qcontext.get_admin_context()
        subnets = self._get_subnets_by_network(admin_context,
                                               net_id)
        subnets_details = []
        if subnets:
            for subnet in subnets:
                subnet_dict = self._make_subnet_dict(subnet)
                mapped_subnet = self._map_state_and_status(subnet_dict)
                subnets_details.append(mapped_subnet)

        return subnets_details

    def _get_mapped_network_with_subnets(self, network):
        network = self._map_state_and_status(network)
        subnets = self._get_all_subnets_json_for_network(network['id'])
        network['subnets'] = subnets
        gateway_ip = None

        if subnets:
            for subnet in subnets:
                gateway_ip = subnet['gateway_ip']
                if gateway_ip:
                    # FIX: For backward compatibility with wire protocol
                    network['gateway'] = gateway_ip
                    break
        if not gateway_ip:
            network['gateway'] = ""

        return network

    def _send_update_network(self, network):
        net_id = network['id']
        tenant_id = network['tenant_id']
        # update network on network controller
        try:
            resource = NETWORKS_PATH % (tenant_id, net_id)
            mapped_network = self._get_mapped_network_with_subnets(network)
            net_with_fl_ips = self._get_network_with_floatingips(network)
            data = {
                "network": net_with_fl_ips,
            }
            ret = self.servers.put(resource, data)
            if not self.servers.action_success(ret):
                raise RemoteRestError(ret[2])
        except RemoteRestError as e:
            LOG.error(
                "QuantumRestProxyV2: Unable to update remote network: %s" %
                e.message)
            raise

    def _map_state_and_status(self, resource):
        resource = copy.copy(resource)
        if 'admin_state_up' in resource:
            if resource['admin_state_up']:
                resource['state'] = 'UP'
            else:
                resource['state'] = 'DOWN'
            del resource['admin_state_up']
        else:
            resource['state'] = 'UP'

        if 'status' in resource:
            del resource['status']

        return resource

    def _warn_on_state_status(self, resource):
        if 'admin_state_up' in resource:
            if resource['admin_state_up'] is False:
                LOG.warning("Setting admin_state_up=False is not supported"
                            " in this plugin version. Ignoring setting.")

        if 'status' in resource:
            if resource['status'] is not const.NET_STATUS_ACTIVE:
                LOG.warning("Operational status is internally set by the"
                            " plugin. Ignoring setting status=%s." %
                            resource['status'])

    def _get_router_intf_details(self, context, router_id, intf_id, subnet_id):

        router = self._get_router(context, router_id)
        # we will use the network id as interface's id
        net_id = intf_id
        network = super(QuantumRestProxyV2, self).get_network(context,
                                                              net_id)
        subnet = super(QuantumRestProxyV2, self).get_subnet(context,
                                                            subnet_id)
        mapped_network = self._get_mapped_network_with_subnets(network)
        mapped_subnet = self._map_state_and_status(subnet)

        data = {
            'id': intf_id,
            "network": mapped_network,
            "subnet": mapped_subnet
        }

        return data
