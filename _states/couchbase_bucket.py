# -*- coding: utf-8 -*-
"""
Manage Couchbase Buckets
=============================

Example:

.. code-block:: yaml

    add_my_new_bucket_name:
      couchbase_bucket.present:
        - name: my_new_bucket_name
        - host: localhost
        - port: 8091
        - username: Administrator
        - password: 'password'
        - bucket_replica=1
        - bucket_type: couchbase
        - bucket_port: 11211
        - bucket_priority: low
        - bucket_password: 'password'
        - bucket_eviction_policy: valueOnly
        - bucket_ramsize: 256
        - enable_flush: True
        - enable_index_replica: True
        - wait: 2


    remove_my_new_bucket_name:
      couchbase_bucket.absent:
        - name: my_new_bucket_name
        - host: localhost
        - port: 8091
        - username: Administrator
        - password: 'password'


    change_my_new_bucket_name:
      couchbase_bucket.change:
        - name: my_new_bucket_name
        - host: localhost
        - port: 8091
        - username: Administrator
        - password: 'password'
        - bucket_port: 11222
        - bucket_ramsize: 512
        - bucket_replica: 2,
        - bucket_priority: high
        - bucket_password: 'new_password'
        - bucket_eviction_policy: fullEviction
        - enable_flush: True
"""

# Import python libs
from __future__ import absolute_import
import logging
import json

# Import salt libs
import salt.utils
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def __virtual__(couchbase_path='/opt/couchbase'):
    """
    Only load if Couchbase Server is installed.
    """
    couchbase_bin_path = '{0}/bin'.format(couchbase_path)
    couchbase_cli_bin_path = '{0}/couchbase-cli'.format(couchbase_bin_path)
    couchbase_cli = salt.utils.which(couchbase_cli_bin_path) is not None
    return couchbase_cli


def present(name,
            host='localhost',
            port=8091,
            username='Administrator',
            password='password',
            bucket_replica=None,
            bucket_type='couchbase',
            bucket_port=11211,
            bucket_priority='low',
            bucket_password='password',
            bucket_eviction_policy='valueOnly',
            bucket_ramsize=256,
            enable_flush=False,
            enable_index_replica=False,
            wait=False):
    """
    Ensure the Couchbase Cluster exists.

    Name
        Bucket name

    Host
        Hostname of the cluster
        Defaults to localhost

    Port
        Cluster management REST/HTTP port.
        Defaults to 8091

    Username
        Administrative username.
        Defaults to Administrator

    Password
        Administrator's password.
        Defaults to password

    Bucket_replica
        Replication count.

    Bucket_type
        Bucket type, either memcached or Couchbase.
        [memcached|couchbase]
        Defaults to couchbase

    Bucket_port
        Access Control on TCP port (Needs SASL Auth.)
        Defaults to 11211

    Bucket_priority
        Bucket priority compared to other buckets.
        [low|high]
        Defaults to low

    Bucket_password
        Password of the bucket (SASL Auth)
        Depends on the selected port.*
        Defaults to password

    Bucket_eviction_policy
        Define the eviction policy: full eviction or value-only eviction.
        [valueOnly|fullEviction]
        Defaults to valueOnly

    Bucket_ramsize
        Bucket RAM quota in MB.
        Defaults to 256

    Enable_flush
        Enables or disables flush
        Defaults to False

    Enable_index_replica
        Enables a defined number of replicas
        Defaults to False

    Wait
        Wait for the creation of the bucket to be completed before returning.
        Defaults to False
    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    bucket_exists = __salt__['couchbase_cli.bucket_exists'](name, host, port, username, password)
    if bucket_exists:
        ret['comment'] = 'Bucket \'{0}\' already exists on cluster \'{1}:{2}\'.'.format(name, host, port)
        return ret

    if not __opts__['test']:
        result = __salt__['couchbase_cli.create_bucket'](name, host, port, username, password, bucket_replica,
                                                         bucket_type, bucket_port, bucket_priority,
                                                         bucket_password, bucket_eviction_policy, bucket_ramsize,
                                                         enable_flush, enable_index_replica, wait)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Added' in result:
            ret['comment'] = result['Added']

    # If we've reached this far before returning, we have changes.
    ret['changes'] = {'old': '', 'new': name}

    if __opts__['test']:
        ret['comment'] = 'Bucket \'{0}\' on cluster \'{1}:{2}\' will be created.'.format(name, host, port)

    return ret


def change(name,
           host='localhost',
           port=8091,
           username='Administrator',
           password='password',
           bucket_port=None,
           bucket_ramsize=None,
           bucket_replica=None,
           bucket_priority=None,
           bucket_password=None,
           bucket_eviction_policy=None,
           enable_flush=None):
    """
    Modify an existing bucket

    Name
        Bucket name

    Host
        Hostname of the cluster
        Defaults to localhost

    Port
        Cluster management REST/HTTP port.
        Defaults to 8091

    Username
        Administrative username.
        Defaults to Administrator

    Password
        Administrator's password.
        Defaults to password

    Bucket_port
        Access Control on TCP port (Needs SASL Auth.)

    Bucket_ramsize
        Bucket RAM quota in MB.

    Bucket_replica
        Replication count.

    Bucket_priority
        Bucket priority compared to other buckets [low|high]

    Bucket_password
        Password of the bucket (SASL Auth)
        Depends on the selected port.*

    Bucket_eviction_policy
        Define the eviction policy: full eviction or value-only eviction [valueOnly|fullEviction]

    Enable_flush
        Enables or disables flush
    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    bucket_exists = __salt__['couchbase_cli.bucket_exists'](name, host, port, username, password)
    if not bucket_exists:
        ret['comment'] = 'Bucket \'{0}\' to modify does not exist on cluster \'{1}:{2}\'.'.format(name, host, port)
        ret['result'] = False
        return ret

    try:
        bucket_info_json = __salt__['couchbase_cli.list_buckets'](host, port, username, password)
        bucket_info = json.loads(bucket_info_json)
    except StandardError as err:
        log.error('Error: {0}'.format(err))
        return False

    if isinstance(bucket_info, list):
        bucket_port_cur = None
        bucket_ramsize_cur = None
        bucket_replica_cur = None
        bucket_priority_cur = None
        bucket_password_cur = None
        bucket_eviction_policy_cur = None
        enable_flush_cur = None

        # iterate all buckets
        for bucket in bucket_info:
            if bucket['name'] == name:
                for node in bucket['nodes']:
                    if 'thisNode' in node:
                        bucket_port_cur = node['ports']['proxy']
                bucket_ramsize_cur = bucket['quota']['rawRAM']
                bucket_replica_cur = bucket['replicaNumber']
                bucket_priority_cur = ('low' if bucket['threadsNumber'] == 3 else 'high')
                bucket_password_cur = bucket['saslPassword']
                bucket_eviction_policy_cur = bucket['evictionPolicy']
                enable_flush_cur = 'flush' in bucket['controllers']

        if bucket_port is not None:
            if bucket_port_cur == bucket_port:
                bucket_port = None
            else:
                ret['changes'].update({'bucket_port': {'old': bucket_port_cur, 'new': bucket_port}})
        if bucket_ramsize is not None:
            if bucket_ramsize_cur == bucket_ramsize*1024*1024:
                bucket_ramsize = None
            else:
                ret['changes'].update({'bucket_ramsize':
                                           {'old': (bucket_ramsize_cur/(1024*1024)), 'new': bucket_ramsize}})
        if bucket_replica is not None:
            if bucket_replica_cur == bucket_replica:
                bucket_replica = None
            else:
                ret['changes'].update({'bucket_replica': {'old': bucket_replica_cur, 'new': bucket_replica}})
        if bucket_priority is not None:
            if bucket_priority_cur == bucket_priority:
                bucket_priority = None
            else:
                ret['changes'].update({'bucket_priority': {'old': bucket_priority_cur, 'new': bucket_priority}})
        if bucket_password is not None:
            if bucket_password_cur == bucket_password:
                bucket_password = None
            else:
                ret['changes'].update({'bucket_password': {'old': 'XXX-REDACTED-XXX', 'new': 'XXX-REDACTED-XXX'}})
        if bucket_eviction_policy is not None:
            if bucket_eviction_policy_cur == bucket_eviction_policy:
                bucket_eviction_policy = None
            else:
                ret['changes'].update({'bucket_eviction_policy':
                                           {'old': bucket_eviction_policy_cur, 'new': bucket_eviction_policy}})
        if enable_flush is not None:
            if enable_flush_cur == enable_flush:
                enable_flush = None
            else:
                ret['changes'].update({'enable_flush': {'old': enable_flush_cur, 'new': enable_flush}})

    if not __opts__['test']:
        result = __salt__['couchbase_cli.edit_bucket'](name, host, port, username, password, bucket_port,
                                                       bucket_ramsize, bucket_replica, bucket_priority, bucket_password,
                                                       bucket_eviction_policy, enable_flush)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Changed' in result:
            ret['comment'] = result['Changed']

    if __opts__['test']:
        if ret['changes']:
            ret['comment'] = 'Bucket \'{0}\' on cluster \'{1}:{2}\' will be modified.'.format(name, host, port)
        else:
            ret['comment'] = 'Bucket values are already set with the correct values'

    return ret


def absent(name,
           host='localhost',
           port=8091,
           username='Administrator',
           password='password'):
    """
    Ensure the bucket is absent

    Name
        Bucket name

    Host
        Hostname of the cluster
        Defaults to localhost

    Port
        Cluster management REST/HTTP port.
        Defaults to 8091

    Username
        Administrative username.
        Defaults to Administrator

    Password
        Administrator's password.
        Defaults to password
    """

    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    bucket_exists = __salt__['couchbase_cli.bucket_exists'](name, host, port, username, password)
    if not bucket_exists:
        ret['comment'] = 'Bucket \'{0}\' not exists on cluster \'{1}:{2}\'.'.format(name, host, port)
        return ret

    if not __opts__['test']:
        result = __salt__['couchbase_cli.delete_bucket'](name, host, port, username, password)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Deleted' in result:
            ret['comment'] = result['Deleted']

    # If we've reached this far before returning, we have changes.
    ret['changes'] = {'new': '', 'old': name}

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Bucket \'{0}\' will be removed from cluster \'{1}:{2}\'.'.format(name, host, port)

    return ret

