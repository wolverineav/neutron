# Copyright 2014, Big Switch Networks
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
import random
import re
import string
import time

from oslo.config import cfg
import sqlalchemy as sa

from neutron.db import model_base
from neutron.openstack.common.db import exception as db_exc
from neutron.openstack.common.db.sqlalchemy import session
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)
# Maximum time in seconds to wait for a single record lock to be released
# NOTE: The total time waiting may exceed this if there are multiple servers
# waiting for the same lock
MAX_LOCK_WAIT_TIME = 60


def clear_db():
    '''Helper to unregister models and clear engine in unit tests.'''
    if not HashHandler._ENGINE:
        return
    ConsistencyHash.metadata.drop_all(HashHandler._ENGINE)
    HashHandler._ENGINE = None


class ConsistencyHash(model_base.BASEV2):
    '''
    A simple table to store the latest consistency hash
    received from a server.
    For now we only support one global state so the
    hash_id will always be '1'
    '''
    __tablename__ = 'consistencyhashes'
    hash_id = sa.Column(sa.String(255),
                        primary_key=True)
    hash = sa.Column(sa.String(255), nullable=False)


class HashHandler(object):
    '''
    A wrapper object to keep track of the session between the read
    and the update operations.

    This class needs an SQL engine completely independent of the main
    neutron connection so rollbacks from consistency hash operations don't
    affect the parent sessions.
    '''
    _ENGINE = None

    def __init__(self, hash_id='1'):
        if HashHandler._ENGINE is None:
            HashHandler._ENGINE = session.create_engine(
                cfg.CONF.database.connection,
                sqlite_fk=False,
                mysql_traditional_mode=False)
            ConsistencyHash.metadata.create_all(HashHandler._ENGINE)
        self.hash_id = hash_id
        self.session = session.get_maker(HashHandler._ENGINE)()
        self.random_lock_id = ''.join(random.choice(string.ascii_uppercase
                                                    + string.digits)
                                      for _ in range(10))
        self.lock_marker = 'LOCKED_BY[%s]' % self.random_lock_id

    def read_for_update(self):
        # an optimistic locking strategy with a timeout to avoid using a
        # consistency hash while another server is using it.
        lock_wait_start = None
        last_lock_owner = None
        while True:
            try:
                update = False
                with self.session.begin(subtransactions=True):
                    res = (self.session.query(ConsistencyHash).
                           filter_by(hash_id=self.hash_id).first())
                    if not res:
                        res = ConsistencyHash(hash_id=self.hash_id,
                                              hash=self.lock_marker)
                        self.session.add(res)
                        break
                self.session.refresh(res)  # make sure latest is loaded from db
                LOG.debug("My lock ID is %(mine)s. Current hash is %(cur)s" % {
                          'mine': self.random_lock_id, 'cur': res.hash})
                matches = re.findall("^LOCKED_BY\[(\w+)\]", res.hash)
                if matches:
                    current_lock_owner = matches[0]
                    if current_lock_owner == self.random_lock_id:
                        # no change needed, we already have the table lock
                        break
                    if current_lock_owner != last_lock_owner:
                        # the owner changed, but it wasn't to us.
                        # reset the counter and log if not first time.
                        if lock_wait_start:
                            LOG.debug(
                                "Lock owner changed from %(last)s to "
                                "%(current)s while waiting to acquire it.",
                                {'last': last_lock_owner,
                                 'current': current_lock_owner})
                        lock_wait_start = time.time()
                        last_lock_owner = current_lock_owner
                    if time.time() - lock_wait_start > MAX_LOCK_WAIT_TIME:
                        # the lock has been held too long, steal it
                        LOG.warning(_("Gave up waiting for consistency DB "
                                      "lock, taking it from current holder. "
                                      "Current hash is: %s"), res.hash)
                        update = res.hash.replace(current_lock_owner,
                                                  self.random_lock_id)
                else:
                    # no current lock
                    update = self.lock_marker + res.hash

                if update:
                    # need to check update row count in case another server is
                    # doing this at the same time. Only one can succeed.
                    query = sa.update(ConsistencyHash.__table__).values(
                        hash=update)
                    query = query.where(ConsistencyHash.hash_id == res.hash_id)
                    query = query.where(ConsistencyHash.hash == res.hash)
                    with self._ENGINE.begin() as conn:
                        result = conn.execute(query)
                    if result.rowcount == 1:
                        # we successfully updated the table with our lock
                        break
                    # someone else beat us to it. timers will be reset on next
                    # iteration due to lock ID change
                    LOG.debug("Failed to acquire lock. Restarting lock wait. "
                              "Previous hash: %(prev)s. Update: %(update)s" %
                              {'prev': res.hash, 'update': update})
                time.sleep(0.25)
            except db_exc.DBDuplicateEntry:
                # another server created a new record at the same time
                # retry process after waiting
                LOG.debug("Concurrent record inserted. Retrying.")
                time.sleep(0.25)

        ret = (update.replace(self.lock_marker, '')
               if update else res.hash.replace(self.lock_marker, ''))
        LOG.debug("Returning hash header %s", ret)
        return ret

    def clear_lock(self):
        LOG.debug("Clearing hash record lock of id %s" % self.random_lock_id)
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if not res:
                LOG.warning(_("Hash record already gone, no lock to clear."))
                return
            if not res.hash.startswith(self.lock_marker):
                # if these are frequent the server is too slow
                LOG.warning(_("Another server has already taken the lock. %s"),
                            res.hash)
                return
            res.hash = res.hash.replace(self.lock_marker, '')

    def put_hash(self, hash):
        hash = hash or ''
        with self.session.begin(subtransactions=True):
            res = (self.session.query(ConsistencyHash).
                   filter_by(hash_id=self.hash_id).first())
            if res:
                res.hash = hash
            else:
                conhash = ConsistencyHash(hash_id=self.hash_id, hash=hash)
                self.session.merge(conhash)
        LOG.debug(_("Consistency hash for group %(hash_id)s updated "
                    "to %(hash)s"), {'hash_id': self.hash_id, 'hash': hash})
