# -*- coding: utf-8 -*-
"""
Module to provide Couchbase compatibility to Salt.
Todo: A lot, need to add cluster support, logging, and minion configuration
data.
"""
from __future__ import absolute_import

# Import python libs
import json
import logging
import re
import urllib

# Import salt libs
import salt.utils
import salt.utils.itertools
import salt.ext.six as six
from salt.exceptions import SaltInvocationError
from salt.ext.six.moves import range
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def __virtual__(couchbase_path='/opt/couchbase'):
    """
    Verify couchbase-cli and curl is installed.
    """
    couchbase_bin_path = '{0}/bin'.format(couchbase_path)
    couchbase_cli_bin_path = '{0}/couchbase-cli'.format(couchbase_bin_path)
    couchbase_cli = salt.utils.which(couchbase_cli_bin_path) is not None
    curl = salt.utils.which('curl') is not None

    return couchbase_cli and curl


def _format_response(response, msg):
    error = 'couchbase-cli command failed: {0}'.format(response)
    if isinstance(response, dict):
        if response['retcode'] != 0:
            raise CommandExecutionError(error)
        else:
            msg = response['stdout']
    else:
        if 'Error' in response:
            raise CommandExecutionError(error)
    return {
        msg: response
    }


def _safe_output(line):
    """
    Looks for couchbase-cli warning, or general formatting, strings that aren't
    intended to be parsed as output.
    Returns a boolean whether the line can be parsed as couchbase-cli output.
    """
    return not any([
        line.startswith('Listing') and line.endswith('...'),
        '...done' in line,
        line.startswith('WARNING:')
    ])


def _strip_listing_to_done(output_list):
    """
    Conditionally remove non-relevant first and last line,
    "Listing ..." - "...done".
    outputlist: couchbase-cli command output split by newline
    return value: list, conditionally modified, may be empty.
    """
    return [line for line in output_list if _safe_output(line)]


def _output_to_dict(cmdoutput, values_mapper=None):
    """
    Convert couchbase-cli output to a dict of data
    cmdoutput: string output of couchbase-cli commands
    values_mapper: function object to process the values part of each line
    """
    ret = {}
    if values_mapper is None:
        values_mapper = lambda string: string.split('\t')

    # remove first and last line: Listing ... - ...done
    data_rows = _strip_listing_to_done(cmdoutput.splitlines())

    for row in data_rows:
        try:
            key, values = row.split('\t', 1)
        except ValueError:
            log.debug('Could not find any values for key \'{0}\'. '
                      'Setting to \'{0}\' to an empty string.'.format(row))
            ret[row] = ''
            continue
        ret[key] = values_mapper(values)
    return ret


def cluster_exists(name, port=8091, user='Administrator', passwd='password', runas=None):
    """
    Return whether the cluster exists based on server-list exit code

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.cluster_exists cluster_host cluster_port user passwd
    """
    if runas is None:
        runas = salt.utils.get_user()
    res = __salt__['cmd.run_all'](
        ['couchbase-cli', 'server-list', '-c', '{0}:{1}'.format(name, port),
         '-u', user, '-p', passwd, '--output=standard'], python_shell=False, runas=runas)
    ret = False
    if isinstance(res, dict):
        if res['retcode'] == 0:
            ret = True
        elif res['retcode'] == 1:
            ret = False
        else:
            error = 'couchbase-cli server-list command failed with: {0}'.format(res['stdout'])
            raise CommandExecutionError(error)
    else:
        error = 'couchbase-cli server-list command failed with: {0}'.format(res)
        if 'Error' in res:
            raise CommandExecutionError(error)
    return ret


def node_list(name, port=8091, user='Administrator', passwd='password', runas=None):
    """
    Return a list of available nodes in a cluster

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.node_list cluster_host cluster_port user passwd
    """
    if runas is None:
        runas = salt.utils.get_user()

    cmd_args = ['couchbase-cli', 'server-list', '-c', '{0}:{1}'.format(name, port),
                '-u', user, '-p', passwd, '--output=json']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    ret = None
    if isinstance(res, dict):
        if res['retcode'] == 0:
            try:
                ret = res['stdout']
                json.loads(ret)
            except ValueError as err:
                error = 'couchbase-cli server-list command failed to deserialize json string: {0}'.format(res['stdout'])
                raise CommandExecutionError(error)
        else:
            error = 'couchbase-cli server-list command failed with: {0}'.format(res['stdout'])
            raise CommandExecutionError(error)
    else:
        error = 'couchbase-cli server-list command failed with: {0}'.format(res)
        if 'Error' in res:
            raise CommandExecutionError(error)
    return ret


def node_exists(name, port=8091,
                cluster_host='localhost', cluster_port=8091,
                cluster_username='Administrator', cluster_password='password', runas=None):
    """
    Return true if the node exists in a cluster based on couchbase_cli.node_list

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.node_exists node_name node_port cluster_host cluster_port cluster_user cluster_passwd
    """

    nodes = json.loads(node_list(cluster_host, cluster_port, cluster_username, cluster_password, runas))
    ret = False
    node_host = '{0}:{1}'.format(name, port)
    for item in nodes['nodes']:
        if item['hostname'] == node_host:
            ret = True
            break

    return ret


def add_node(name, new_port=8091, new_username='Administrator', new_password='password',
             cluster_host='localhost', cluster_port=8091, cluster_username='Administrator', cluster_password='password',
             rebalance=False, runas=None):
    """
    Adds a node to a cluster based on couchbase-cli server-add

    Wrong Warning message in Couchbase 4.5:
    https://issues.couchbase.com/browse/MB-19847

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.add_node node_name node_port node_username node_password
                                        cluster_host cluster_port cluster_user cluster_passwd rebalance
    """

    if runas is None:
        runas = salt.utils.get_user()

    if rebalance:
        cmd_args = ['couchbase-cli', 'rebalance', '-c', '{0}:{1}'.format(cluster_host, cluster_port),
                    '-u', cluster_username, '-p', cluster_password, '--server-add={0}:{1}'.format(name, new_port),
                    '--server-add-username={0}'.format(cluster_username),
                    '--server-add-password={0}'.format(cluster_password), '--output=json']
    else:
        cmd_args = ['couchbase-cli', 'server-add', '-c', '{0}:{1}'.format(cluster_host, cluster_port),
                    '-u', cluster_username, '-p', cluster_password, '--server-add={0}:{1}'.format(name, new_port),
                    '--server-add-username={0}'.format(cluster_username),
                    '--server-add-password={0}'.format(cluster_password), '--output=json']

    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)

    msg = 'Added'
    return _format_response(res, msg)


def remove_node(name, node_port=8091,
                cluster_host='localhost', cluster_port=8091,
                cluster_username='Administrator', cluster_password='password', runas=None):
    """
    Removes a node from a cluster based on couchbase-cli rebalance

    CLI Example:

    .. code-block:: bash

    salt '*' couchbase_cli.remove_node node_name node_port cluster_host cluster_port cluster_user cluster_passwd
    """

    if runas is None:
        runas = salt.utils.get_user()

    cmd_args = ['couchbase-cli', 'rebalance', '-c', '{0}:{1}'.format(cluster_host, cluster_port),
                '-u', cluster_username, '-p', cluster_password, '--server-remove={0}:{1}'.format(name, node_port),
                '--output=json']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)

    msg = 'Removed'
    return _format_response(res, msg)


def list_buckets(host='localhost', port=8091, user='Administrator', passwd='password', runas=None):
    """
    Return a list of buckets based on couchbase-cli bucket-list

    CLI Example:

    .. code-block:: bash

    salt '*' couchbase_cli.list_buckets host port username passwd
    """
    if runas is None:
        runas = salt.utils.get_user()

    cmd_args = ['couchbase-cli', 'bucket-list', '-c', '{0}:{1}'.format(host, port),
                '-u', user, '-p', passwd, '--output=json']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    ret = None
    if isinstance(res, dict):
        if res['retcode'] == 0:
            ret = res['stdout']
        else:
            error = 'couchbase-cli server-list command failed with: {0}'.format(res['stdout'])
            raise CommandExecutionError(error)
    else:
        error = 'couchbase-cli server-list command failed with: {0}'.format(res)
        if 'Error' in res:
            raise CommandExecutionError(error)
    return ret


def get_alert_settings(host='localhost', port=8091, username='Administrator', password='password', runas=None):
    """
    Returns the configured alert

    CLI Example:

    .. code-block:: bash

    salt '*' couchbase_cli.get_alert host port username passwd
    """
    if runas is None:
        runas = salt.utils.get_user()

    cmd_args = ['curl', '-s', '-f', '-H', 'content-type:application/json',
                '-u', '{0}:{1}'.format(urllib.quote(username), urllib.quote(password)),
                'http://{0}:{1}/settings/alerts'.format(host, port)]
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    ret = None
    if isinstance(res, dict):
        if res['retcode'] == 0:
            # verify json output
            json.loads(res['stdout'])
            ret = res['stdout']
        else:
            msg = ((res['stdout']) if not res['stderr'] else res['stderr'])
            error = 'curl command failed with: {0}'.format(msg)
            raise CommandExecutionError(error)
    else:
        error = 'curl command failed with: {0}'.format(res)
        if 'Error' in res:
            raise CommandExecutionError(error)

    return ret




def bucket_exists(name, host='localhost', port=8091, user='Administrator', passwd='password', runas=None):
    """
    Return whether the cluster exists based on list_buckets

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.bucket_exists bucket_name host port user passwd
    """
    if runas is None:
        runas = salt.utils.get_user()

    buckets_json = list_buckets(host, port, user, passwd, runas)
    ret = False
    for item in json.loads(buckets_json):
        if item['name'] == name:
            ret = True
            break
    return ret


def create_bucket(bucket_name,
                  host='localhost', port=8091, username='Administrator', password='password',
                  bucket_replica=None, bucket_type='couchbase',
                  bucket_port=11211, bucket_priority='low',
                  bucket_password='password', bucket_eviction_policy='valueOnly',
                  bucket_ramsize=256, enable_flush=False,
                  enable_index_replica=False, wait=False, runas=None):
    """
    Creates a new bucket on a cluster

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.create_bucket bucket_name host port user passwd bucket_replica bucket_type
                                             bucket_port bucket_priority bucket_password bucket_eviction_policy
                                             bucket_ramsize enable_flush enable_index_replica wait
    """
    if runas is None:
        runas = salt.utils.get_user()

    # sanitize input
    if re.match(r'^(couchbase|memcached)$', bucket_type) is not None:
        bucket_type_opt = '--bucket-type={0}'.format(bucket_type)
    else:
        raise SaltInvocationError("Wrong parameter for bucket_type {0} expected "
                                  "[couchbase|memcached].".format(bucket_type))

    if re.match(r'^(low|high)$', bucket_priority) is not None:
        bucket_priority_opt = '--bucket-priority={0}'.format(bucket_priority)
    else:
        raise SaltInvocationError("Wrong parameter for bucket_priority {0} expected "
                                  "[low|high].".format(bucket_type))

    if re.match(r'^(valueOnly|fullEviction)$', bucket_eviction_policy) is not None:
        bucket_eviction_policy_opt = '--bucket-eviction-policy={0}'.format(bucket_eviction_policy)
    else:
        raise SaltInvocationError("Wrong parameter for bucket_eviction_policy {0} expected "
                                  "[valueOnly|fullEviction].".format(bucket_eviction_policy))

    bucket_replica_opt = ('--bucket-replica={0}'.format(bucket_replica) if bucket_replica is not None else '')
    # 1=yes and 0=no
    enable_flush_opt = ('--enable-flush=1' if enable_flush else '--enable-flush=0')
    enable_index_replica_opt = ('--enable-index-replica=1' if enable_index_replica else '--enable-index-replica=0')
    wait_opt = ('--wait' if wait else '')

    cmd_args = ['couchbase-cli', 'bucket-create', '-c', '{0}:{1}'.format(host, port),
                '-u', username, '-p', password, '--bucket={0}'.format(bucket_name), bucket_replica_opt, bucket_type_opt,
                '--bucket-port={0}'.format(bucket_port), bucket_priority_opt,
                '--bucket-password={0}'.format(bucket_password), '--bucket-ramsize={0}'.format(bucket_ramsize),
                bucket_eviction_policy_opt, enable_flush_opt, enable_index_replica_opt, wait_opt, '--output=json']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    msg = 'Added'
    return _format_response(res, msg)


def delete_bucket(bucket_name,
                  host='localhost', port=8091,
                  username='Administrator', password='password', runas=None):
    """
    Deletes a bucket from a cluster

    CLI Example:

    .. code-block:: bash

       salt '*' couchbase_cli.delete_bucket bucket_name host port user passwd
    """
    if runas is None:
        runas = salt.utils.get_user()

    cmd_args = ['couchbase-cli', 'bucket-delete', '-c', '{0}:{1}'.format(host, port),
                '-u', username, '-p', password, '--bucket={0}'.format(bucket_name), '--output=json']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    msg = 'Deleted'
    return _format_response(res, msg)


def edit_bucket(bucket_name,
                host='localhost', port=8091,
                username='Administrator', password='password',
                bucket_port=None, bucket_ramsize=None, bucket_replica=None,
                bucket_priority=None, bucket_password=None,
                bucket_eviction_policy=None, enable_flush=None, runas=None):
    """
    Modifies the parameter of a bucket
    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.edit_bucket bucket_name host port user passwd bucket_port bucket_ramsize bucket_replica
                                           bucket_priority bucket_password bucket_eviction_policy enable_flush
    """
    if runas is None:
        runas = salt.utils.get_user()

    # sanitize input
    bucket_port_opt = ('--bucket-port={0}'.format(bucket_port) if bucket_port is not None else '')
    bucket_ramsize_opt = ('--bucket-ramsize={0}'.format(bucket_ramsize) if bucket_ramsize is not None else '')
    bucket_replica_opt = ('--bucket-replica={0}'.format(bucket_replica) if bucket_replica is not None else '')
    bucket_priority_opt = ('--bucket-priority={0}'.format(bucket_priority) if bucket_priority is not None else '')
    bucket_password_opt = ('--bucket-password={0}'.format(bucket_password) if bucket_password is not None else '')
    bucket_eviction_policy_opt = ('--bucket-eviction-policy={0}'.format(bucket_eviction_policy)
                                  if bucket_eviction_policy is not None else '')
    # 1=yes and 0=no
    if enable_flush is not None:
        enable_flush_opt = ('--enable-flush=1' if enable_flush else '--enable-flush=0')
    else:
        enable_flush_opt = ''

    cmd_args = ['couchbase-cli', 'bucket-edit', '-c', '{0}:{1}'.format(host, port),
                '-u', username, '-p', password, '--bucket={0}'.format(bucket_name), bucket_port_opt,
                bucket_ramsize_opt, bucket_replica_opt, bucket_priority_opt, bucket_password_opt,
                bucket_eviction_policy_opt, enable_flush_opt, '--output=json']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    msg = 'Changed'
    return _format_response(res, msg)


def init_cluster(name, port=8091, cluster_username='Administrator', cluster_password='password',
                 cluster_port=8091, cluster_ramsize=256, cluster_index_ramsize=512, cluster_fts_ramsize=256,
                 services=['data'], index_storage_setting=None, runas=None):
    """
    Return whether the cluster exists based on couchbase-cli .

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.init_cluster host port user passwd hostname_to_add 256 'data'  512 256 memopt
    """
    if runas is None:
        runas = salt.utils.get_user()

    service_opt = '--services={0}'.format(','.join(services))
    index_storage_setting_opt = ('--index-storage-setting={0}'.format(index_storage_setting)
                                 if index_storage_setting is not None else '')

    cmd_args = ['couchbase-cli', 'cluster-init', '-c', '{0}:{1}'.format(name, port),
                '--cluster-username={0}'.format(cluster_username), '--cluster-password={0}'.format(cluster_password),
                '--cluster-ramsize={0}'.format(cluster_ramsize), '--cluster-port={0}'.format(cluster_port),
                '--cluster-index-ramsize={0}'.format(cluster_index_ramsize),
                '--cluster-fts-ramsize={0}'.format(cluster_fts_ramsize), service_opt, index_storage_setting_opt,
                '--output=standard']

    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    msg = 'Added'
    return _format_response(res, msg)


def edit_cluster(name, port=8091, username='Administrator', password='password',
                 cluster_username=None, cluster_password=None,
                 cluster_port=None, cluster_ramsize=None, cluster_index_ramsize=None, cluster_fts_ramsize=None,
                 services=None, index_storage_setting=None, runas=None):
    """
    Modifies a cluster via couchbase-cli

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.edit_cluster host port username password new_cluster_user new_cluster_password
    """
    if runas is None:
        runas = salt.utils.get_user()

    # sanitize input
    cluster_username_opt = ('--cluster-username={0}'.format(cluster_username) if cluster_username is not None else '')
    cluster_password_opt = ('--cluster-password={0}'.format(cluster_password) if cluster_password is not None else '')
    cluster_ramsize_opt = ('--cluster-ramsize={0}'.format(cluster_ramsize) if cluster_ramsize is not None else '')
    cluster_port_opt = ('--cluster-port={0}'.format(cluster_port) if cluster_port is not None else '')
    cluster_index_ramsize_opt = ('--cluster-index-ramsize={0}'.format(cluster_index_ramsize)
                                 if cluster_index_ramsize is not None else '')
    cluster_fts_ramsize_opt = ('--cluster-fts-ramsize={0}'.format(cluster_fts_ramsize)
                               if cluster_fts_ramsize is not None else '')
    service_opt = ('--services={0}'.format(','.join(services)) if services is not None else '')
    index_storage_setting_opt = ('--index-storage-setting={0}'.format(index_storage_setting)
                                 if index_storage_setting is not None else '')

    cmd_args = ['couchbase-cli', 'cluster-edit', '-c', '{0}:{1}'.format(name, port),
                '-u', username, '-p', password, cluster_username_opt, cluster_password_opt,
                cluster_ramsize_opt, cluster_port_opt, cluster_index_ramsize_opt, cluster_fts_ramsize_opt,
                service_opt, index_storage_setting_opt, '--output=standard']

    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    msg = 'Changed'
    return _format_response(res, msg)


def server_info(host, port=8091, username='Administrator', password='password', runas=None):
    """
    Returns the details on one server

    CLI Example:

    .. code-block:: bash

        salt '*' couchbase_cli.server_info host port username password
    """
    if runas is None:
        runas = salt.utils.get_user()

    res = __salt__['cmd.run_all'](
        ['couchbase-cli', 'server-info', '-c', '{0}:{1}'.format(host, port), '-u', username, '-p', password,
         '--output=json'], python_shell=False, runas=runas)
    ret = None
    if isinstance(res, dict):
        if res['retcode'] == 0:
            try:
                ret = json.loads(res['stdout'])
            except ValueError as err:
                return None
        else:
            msg = ((res['stdout']) if not res['stderr'] else res['stderr'])
            error = 'couchbase-cli server-list command failed with: {0}'.format(msg)
            raise CommandExecutionError(error)
    else:
        error = 'couchbase-cli server-list command failed with: {0}'.format(res)
        if 'Error' in res:
            raise CommandExecutionError(error)
    return ret


def get_cluster_name(host, port=8091, username='Administrator', password='password', runas=None):
    """
    Returns the name of the cluster
    """
    if runas is None:
        runas = salt.utils.get_user()
    cmd_args = ['curl', '-s', '-f', '-H', 'content-type:application/json',
                '-u', '{0}:{1}'.format(urllib.quote(username), urllib.quote(password)),
                'http://{0}:{1}/pools/default?waitChange=0'.format(host, port)]
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    ret = None
    if isinstance(res, dict):
        if res['retcode'] == 0:
            try:
                response = json.loads(res['stdout'])
                if 'clusterName' in response:
                    ret = response['clusterName']
            except ValueError as err:
                return None
        else:
            msg = ((res['stdout']) if not res['stderr'] else res['stderr'])
            error = 'curl command failed with: {0}'.format(msg)
            raise CommandExecutionError(error)
    else:
        error = 'curl command failed with: {0}'.format(res)
        if 'Error' in res:
            raise CommandExecutionError(error)
    return ret


def set_cluster_name(cluster_name, host, port=8091,
                     username='Administrator', password='password',
                     runas=None):
    """
    Set the name of the cluster
    """
    if runas is None:
        runas = salt.utils.get_user()

    cmd_args = ['couchbase-cli', 'setting-cluster', '-c', '{0}:{1}'.format(host, port),
                '-u', username, '-p', password, '--cluster-name={0}'.format(cluster_name), '--output=standard']
    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)
    msg = 'Changed'
    return _format_response(res, msg)


def set_alerts(host='localhost', port=8091, username='Administrator', password='password',
               enable_email_alert=False, email_sender='couchbase@localhost',
               email_user='couchbase', email_password='', email_host='localhost',
               email_port=25, enable_email_encrypt=True, email_recipients=(), alerts=(), runas=None):
    """
    Set alerts for cluster
    """
    if runas is None:
        runas = salt.utils.get_user()

    # sanitize input
    enable_email_alert_opt = ('--enable-email-alert=1' if enable_email_alert else '--enable-email-alert=0')
    email_sender_opt = '--email-sender={0}'.format(email_sender)
    email_user_opt = '--email-user={0}'.format(email_user)
    email_password_opt = '--email-password={0}'.format(email_password)
    email_host_opt = '--email-host={0}'.format(email_host)
    email_port_opt = '--email-port={0}'.format(email_port)
    enable_email_encrypt_opt = ('--enable-email-encrypt=1' if enable_email_encrypt else '--enable-email-encrypt=0')
    alert_auto_failover_node_opt = ('--alert-auto-failover-node' if 'alert_auto_failover_node' in alerts else '')
    alert_auto_failover_max_reached_opt = ('--alert-auto-failover-max-reached'
                                           if 'alert_auto_failover_max_reached' in alerts else '')
    alert_auto_failover_node_dow_opt = ('--alert-auto-failover-node-down'
                                        if 'alert_auto_failover_node_dow' in alerts else '')
    alert_auto_failover_cluster_small_opt = ('--alert-auto-failover-cluster-small'
                                             if 'alert_auto_failover_cluster_small' in alerts else '')
    alert_auto_failover_disabled_opt = ('--alert-auto-failover-disabled'
                                        if 'alert_auto_failover_disabled' in alerts else '')
    alert_ip_changed_opt = ('--alert-ip-changed' if 'alert_ip_changed' in alerts else '')
    alert_disk_space_opt = ('--alert-disk-space' if 'alert_disk_space' in alerts else '')
    alert_meta_overhead_opt = ('--alert-meta-overhead' if 'alert_meta_overhead' in alerts else '')
    alert_meta_oom_opt = ('--alert-meta-oom' if 'alert_meta_oom' in alerts else '')
    alert_write_failed_opt = ('--alert-write-failed' if 'alert_write_failed' in alerts else '')
    alert_audit_msg_dropped_opt = ('--alert-audit-msg-dropped' if 'alert_audit_msg_dropped' in alerts else '')
    email_recipients_opt = ('--email-recipients={0}'.format(','.join(email_recipients))
                            if len(email_recipients) > 0 else '')

    cmd_args = ['couchbase-cli', 'setting-alert', '-c', '{0}:{1}'.format(host, port),
                '-u', username, '-p', password, enable_email_alert_opt, email_sender_opt, email_user_opt,
                email_password_opt, email_host_opt, email_port_opt, enable_email_encrypt_opt, email_recipients_opt,
                alert_auto_failover_node_opt, alert_auto_failover_max_reached_opt, alert_auto_failover_node_dow_opt,
                alert_auto_failover_cluster_small_opt, alert_auto_failover_disabled_opt, alert_ip_changed_opt,
                alert_disk_space_opt, alert_meta_overhead_opt, alert_meta_oom_opt, alert_write_failed_opt,
                alert_audit_msg_dropped_opt, '--output=standard']

    res = __salt__['cmd.run_all'](filter(None, cmd_args), python_shell=False, runas=runas)

    msg = 'Changed'
    return _format_response(res, msg)

