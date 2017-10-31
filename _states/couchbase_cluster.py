# -*- coding: utf-8 -*-
"""
Manage Couchbase Cluster
=============================

Example:

.. code-block:: yaml

    new_cluster_my-new-cluster-host.local:
      couchbase_cluster.present:
        - name: my-new-cluster-host.local
        - port: 8091
        - cluster_username: Administrator
        - cluster_password: 'password'
        - cluster_ramsize: 1000
        - cluster_index_ramsize: 256
        - cluster_fts_ramsize: 256
        - cluster_port: 8091
        - services:
          - data
          - index
          - query
          - fts

    change_cluster_my-new-cluster-host.local:
      couchbase_cluster.change:
        - name: my-new-cluster-host.local
        - port: 8091
        - username: Administrator
        - password: 'password'
        - cluster_username: Administrator
        - cluster_password: 'password'
        - cluster_port: 8091
        - cluster_ramsize: 256
        - cluster_index_ramsize: 256
        - cluster_fts_ramsize: 256

    add_node_couchbase-node-02.local:
      couchbase_cluster.node_present:
        - name: couchbase-node-02.local
        - new_port: 8091
        - new_username: Administrator
        - new_password: 'password'
        - cluster_host: my-new-cluster-host.local
        - cluster_port: 8091
        - cluster_username: Administrator
        - cluster_password: 'password'
        - rebalance: True

    remove_node_couchbase-node-02.local:
      couchbase_cluster.node_absent:
        - name: couchbase-node-02.local
        - node_port: 8091
        - cluster_host: my-new-cluster-host.local
        - cluster_port: 8091
        - cluster_username: Administrator
        - cluster_password: 'password'

    my_cluster_name:
      couchbase_cluster.set_name:
        - name: my_cluster_name
        - host: my-new-cluster-host.local
        - port: 8091
        - username: Administrator
        - password: 'password'
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
            port=8091,
            cluster_username='Administrator',
            cluster_password='password',
            cluster_port=8091,
            cluster_ramsize=256,
            cluster_index_ramsize=512,
            cluster_fts_ramsize=256,
            index_storage_setting=None,
            services=['data']):
    """
    Ensure the Couchbase Cluster exists.

    name
        Cluster hostname where the cluster should be created on.

    Port
        Cluster management port where the cluster should be created on.
        Defaults to 8091

    cluster_username
        New administrative user name.
        Defaults to Administrator

    cluster_password
        New administrator's password.
        Defaults to password

    cluster_port
        New cluster REST/HTTP port.
        Defaults to 8091.

    cluster_ramsize
        Per node RAM quota in megabytes for the Data service. This is a required parameter.
        Defaults to 256

    cluster_index_ramsize
        Per node RAM quota in megabytes for the Index service.
        Defaults to 512

    cluster_fts_ramsize
        Per node RAM quota in megabytes for the Search service.
        Defaults to 256

    index_storage_setting
        Index storage type (requires couchbase enterprise)
        Defaults to memopt

    services
        A list of services that first node in the cluster runs
        Defaults to data

    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    cluster_exists = __salt__['couchbase_cli.cluster_exists'](name, port, cluster_username, cluster_password)
    if cluster_exists:
        ret['comment'] = 'Cluster \'{0}:{1}\' already exists.'.format(name, port)
        return ret

    if not __opts__['test']:
        result = __salt__['couchbase_cli.init_cluster'](name, port, cluster_username, cluster_password, cluster_port,
                                                        cluster_ramsize, cluster_index_ramsize, cluster_fts_ramsize,
                                                        services, index_storage_setting)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Added' in result:
            ret['comment'] = result['Added']

    # If we've reached this far before returning, we have changes.
    ret['changes'] = {'old': '', 'new': name}

    if __opts__['test']:
        ret['comment'] = 'Cluster \'{0}:{1}\' will be created.'.format(name, port)

    return ret


def node_present(name, new_port=8091, new_username='Administrator', new_password='password',
                 cluster_host='localhost', cluster_port=8091,
                 cluster_username='Administrator', cluster_password='password', rebalance=False):
    """
    Adds an existing node to a cluster

    Name
        Hostname of the node to add

    New_port
        New port of the node (should be same as cluster node)
        Defaults to 8091

    New_username
        Creates a new User on the node
        Defaults to Administrator

    New_password
        Creates a new password on the node

    Cluster_host
        Hostname of the cluster
        Defaults to localhost

    Cluster_port
        Port of the cluster
        Defaults to 8091

    Cluster_username
        Username of the cluster for authentication
        Defaults to Administrator

    Cluster_password
        Password of the cluster for authentication
        Defaults to password

    Rebalance
        Start add node and start rebalance process
        Defaults to False
    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    node_exists = __salt__['couchbase_cli.node_exists'](name, new_port,
                                                        cluster_host, cluster_port, cluster_username, cluster_password)

    if node_exists:
        ret['comment'] = 'Node \'{0}:{1}\' exist in the cluster already.'.format(name, new_port)
        return ret

    if not __opts__['test']:
        result = __salt__['couchbase_cli.add_node'](name, new_port, new_username,
                                                    new_password, cluster_host, cluster_port,
                                                    cluster_username, cluster_password, rebalance)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Added' in result:
            ret['comment'] = result['Added']

    # If we've reached this far before returning, we have changes.
    ret['changes'] = {'old': '', 'new': name}

    if __opts__['test']:
        ret['comment'] = 'Node \'{0}:{1}\' will be added.'.format(name, new_port)
    return ret


def node_absent(name, node_port=8091, cluster_host='localhost', cluster_port=8091,
                cluster_username='Administrator', cluster_password='password'):
    """
    Adds an existing node to a cluster

    Name
        Hostname of the node to add

    Node_port
        Port of the node (should be same as cluster node)
        Defaults to 8091

    Cluster_host
        Hostname of the cluster
        Defaults to localhost

    Cluster_port
        Port of the cluster
        Defaults to 8091

    Cluster_username
        Username of the cluster for authentication
        Defaults to Administrator

    Cluster_password
        Password of the cluster for authentication
        Defaults to password

    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    node_exists = __salt__['couchbase_cli.node_exists'](name, node_port,
                                                        cluster_host, cluster_port, cluster_username, cluster_password)

    if not node_exists:
        ret['comment'] = 'Node \'{0}:{1}\' doesn\'t already not exists in the cluster.'.format(name, node_port)
        return ret

    if not __opts__['test']:
        result = __salt__['couchbase_cli.remove_node'](name, node_port, cluster_host, cluster_port,
                                                       cluster_username, cluster_password)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Removed' in result:
            ret['comment'] = result['Removed']

    # If we've reached this far before returning, we have changes.
    ret['changes'] = {'new': '', 'old': name}

    if __opts__['test']:
        ret['comment'] = 'Node \'{0}:{1}\' will be removed.'.format(name, node_port)

    return ret


def set_name(name, host='localhost', port=8091, username='Administrator', password='password'):
    """
    Sets the name of the cluster
    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    cluster_exists = __salt__['couchbase_cli.cluster_exists'](host, port, username, password)
    if not cluster_exists:
        ret['comment'] = 'Cluster to modify \'{0}:{1}\' does not exist.'.format(host, port)
        ret['result'] = False
        return ret

    cluster_name = __salt__['couchbase_cli.get_cluster_name'](host, port, username, password)
    if cluster_name is not None:
        if cluster_name == name:
            ret['comment'] = 'Name of Cluster \'{0}\' is already set with correct values.'.format(name)
            return ret
        else:
            ret['changes'].update({'cluster_name': {'old': cluster_name, 'new': name}})

    if not __opts__['test']:
        result = __salt__['couchbase_cli.set_cluster_name'](name, host, port, username, password)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Changed' in result:
            ret['comment'] = result['Changed']

    if __opts__['test']:
        if ret['changes']:
            ret['comment'] = 'Cluster \'{0}:{1}\' will be modified.'.format(name, port)

    return ret


def change(name,
           port=8091,
           username='Administrator',
           password='password',
           cluster_username=None,
           cluster_password=None,
           cluster_port=None,
           cluster_ramsize=None,
           cluster_index_ramsize=None,
           cluster_fts_ramsize=None,
           index_storage_setting=None,
           services=None):
    """
    Modify cluster settings

    name
        Cluster hostname where the cluster should be created on.

    Port
        Cluster management port where the cluster should be created on.

    cluster_username
        New administrative user name.
        Defaults to Administrator

    cluster_password
        New administrator's password.
        Defaults to password

    cluster_port
        New cluster REST/HTTP port

    cluster_ramsize
        Per node RAM quota in megabytes for the Data service.

    cluster_index_ramsize
        Per node RAM quota in megabytes for the Index service.

    cluster_fts_ramsize
        Per node RAM quota in megabytes for the Search service.

    index_storage_setting
        Index storage type (requires couchbase enterprise)

    services
        A list of services that first node in the cluster runs

    """

    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    cluster_exists = __salt__['couchbase_cli.cluster_exists'](name, port, username, password)

    if not cluster_exists:
        ret['comment'] = 'Cluster to modify \'{0}:{1}\' does not exist.'.format(name, port)
        ret['result'] = False
        return ret

    server_info = None
    try:
        server_info = __salt__['couchbase_cli.server_info'](name, port, username, password)
    except CommandExecutionError as err:
        log.error('Error: {0}'.format(err))
        return False

    if server_info is not None:
        if cluster_username is not None:
            ret['changes'].update({'username': {'old': username, 'new': cluster_username}})

        if cluster_username is not None:
            ret['changes'].update({'password': {'old': 'XXX-REDACTED-XXX', 'new': 'XXX-REDACTED-XXX'}})

        if cluster_ramsize is not None:
            if server_info['memoryQuota'] == cluster_ramsize:
                cluster_ramsize = None
            else:
                ret['changes'].update({'memoryQuota':
                                           {'old': server_info['memoryQuota'], 'new': cluster_ramsize}})

        if cluster_index_ramsize is not None:
            if server_info['indexMemoryQuota'] == cluster_index_ramsize:
                cluster_index_ramsize = None
            else:
                ret['changes'].update({'indexMemoryQuota':
                                           {'old': server_info['indexMemoryQuota'], 'new': cluster_index_ramsize}})
        if cluster_fts_ramsize is not None:
            if server_info['ftsMemoryQuota'] == cluster_fts_ramsize:
                cluster_fts_ramsize = None
            else:
                ret['changes'].update({'ftsMemoryQuota':
                                           {'old': server_info['ftsMemoryQuota'], 'new': cluster_fts_ramsize}})

        # always include the cluster-port
        if cluster_port is not None:
            port = int(server_info['hostname'].split(':')[1])
            if port != cluster_port:
                ret['changes'].update({'port': {'old': port, 'new': cluster_port}})
        else:
            cluster_port = port

    if not __opts__['test']:
        result = __salt__['couchbase_cli.edit_cluster'](name, port, username, password,
                                                        cluster_username, cluster_password,
                                                        cluster_port, cluster_ramsize,
                                                        cluster_index_ramsize, cluster_fts_ramsize,
                                                        services, index_storage_setting)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Changed' in result:
            ret['comment'] = result['Changed']

    if __opts__['test']:
        if ret['changes']:
            ret['comment'] = 'Cluster \'{0}:{1}\' will be modified.'.format(name, port)
        else:
            ret['comment'] = 'Cluster values are already set with the correct values'

    return ret
