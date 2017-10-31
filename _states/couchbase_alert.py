# -*- coding: utf-8 -*-
"""
Manage Couchbase Alert
=============================

Example:

.. code-block:: yaml

    add_alert:
      couchbase_alert.present:
        - name: add_alert
        - host: localhost
        - port: 8091
        - username: Administrator
        - password: 'password'
        - enable_email_alert: True
        - email_recipients:
          - john.doe@example.com
          - max.power@example.com
        - email_sender: couchbase@localhost
        - email_user: couchbase
        - email_password: 'password'
        - email_host: smtp.example.com
        - email_port: 587
        - enable_email_encrypt: True
        - alerts:
          - alert_auto_failover_node
          - alert_auto_failover_max_reached
          - alert_auto_failover_node_dow
          - alert_auto_failover_cluster_small
          - alert_auto_failover_disabled
          - alert_ip_changed
          - alert_disk_space
          - alert_meta_overhead
          - alert_meta_oom
          - alert_write_failed
          - alert_audit_msg_dropped

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
            enable_email_alert=False,
            email_recipients=(),
            email_sender='couchbase@localhost',
            email_user='',
            email_password='',
            email_host='localhost',
            email_port=25,
            enable_email_encrypt=False,
            alerts=()):
    """
    Ensure the Couchbase Cluster exists.

    Name
        Meaningless

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

    Enable_email_alert
        Enables Email alerts
        Defaults to False

    Email_recipients
        List of recipients to send alerts to

    Email_sender
        Sender email address
        Defaults to couchbase@localhost

    Email_user
        Email server username

    Email_password
        Email server password

    Email_host
        email smtp server host
        Defaults to localhost

    Email_port
        Email smtp server port
        Defaults to 25

    Enable_email_encrypt
        Email encryption
        Defaults to False

    Alerts
        List of alerts

        alert_auto_failover_node
            Enables or Disables node was auto failover alerts

        alert_auto_failover_max_reached
            Enables or Disables maximum number of auto failover nodes was reached alerts

        alert_auto_failover_node_down
            Enables or Disables node wasn't auto failover as other nodes are down at the same time alerts

        alert_auto_failover_cluster_small
            Enables or Disables node wasn't auto fail over as cluster was too small alerts

        alert_auto_failover_disabled
            Enables or Disables node was not auto-failed-over as auto-failover for one or more services running on the
            node is disabled alerts

        alert_ip_changed
            Enables or Disables node ip address has changed unexpectedly alerts

        alert_disk_space
            Enables or Disables disk space used for persistent storgage has reached at least 90% capacity alerts

        alert_meta_overhead
            Enables or Disables metadata overhead is more than 50% alerts

        alert_meta_oom
            Enables or Disables bucket memory on a node is entirely used for metadata alerts

        alert_write_failed
            Enables or Disables writing data to disk for a specific bucket has failed alerts

        alert_audit_msg_dropped
            Enables or Disables writing event to audit log has failed alerts
    """
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}

    cluster_exists = __salt__['couchbase_cli.cluster_exists'](host, port, username, password)

    if not cluster_exists:
        ret['comment'] = 'Cluster to modify \'{0}:{1}\' does not exist.'.format(name, port)
        ret['result'] = False
        return ret

    try:
        alert_info_json = __salt__['couchbase_cli.get_alert_settings'](host, port, username, password)
        alert_info = json.loads(alert_info_json)

        if isinstance(alert_info, dict):
            enable_email_alert_cur = alert_info['enabled']
            email_sender_cur = alert_info['sender']
            enable_email_encrypt_cur = alert_info['emailServer']['encrypt']
            email_host_cur = alert_info['emailServer']['host']
            # email_pass_cur = alert_info['emailServer']['pass']
            email_port_cur = alert_info['emailServer']['port']
            email_user_cur = alert_info['emailServer']['user']
            email_recipients_cur = alert_info['recipients']
            alerts_cur = []
            for alert in alert_info['alerts']:
                alerts_cur.append('alert_auto_failover_node') if alert == 'auto_failover_node' else None
                alerts_cur.append('alert_auto_failover_max_reached') \
                    if alert == 'auto_failover_maximum_reached' else None
                alerts_cur.append('alert_auto_failover_node_dow') \
                    if alert == 'auto_failover_other_nodes_down' else None
                alerts_cur.append('alert_auto_failover_cluster_small') \
                    if alert == 'auto_failover_cluster_too_small' else None
                alerts_cur.append('alert_auto_failover_disabled') \
                    if alert == 'auto_failover_disabled' else None
                alerts_cur.append('alert_ip_changed') if alert == 'ip' else None
                alerts_cur.append('alert_disk_space') if alert == 'disk' else None
                alerts_cur.append('alert_meta_overhead') if alert == 'overhead' else None
                alerts_cur.append('alert_meta_oom') if alert == 'ep_oom_errors' else None
                alerts_cur.append('alert_write_failed') if alert == 'ep_item_commit_failed' else None
                alerts_cur.append('alert_audit_msg_dropped') if alert == 'audit_dropped_events' else None

            if enable_email_alert_cur != enable_email_alert:
                ret['changes'].update({'enable_email_alert':
                                           {'old': enable_email_alert_cur, 'new': enable_email_alert}})
            if set(email_recipients_cur) != set(email_recipients):
                # email_recipients_diff = set(email_recipients_cur).symmetric_difference(set(email_recipients))
                ret['changes'].update(
                    {'email_recipients': {'old': format(','.join(email_recipients_cur)),
                                          'new': format(','.join(email_recipients))}})
            if email_sender_cur != email_sender:
                ret['changes'].update({'email_sender': {'old': email_sender_cur, 'new': email_sender}})
            if email_user_cur != email_user:
                ret['changes'].update({'email_user': {'old': email_user_cur, 'new': email_user}})
            # if email_pass_cur != email_password:
            #    ret['changes'].update({'email_password': {'old': 'XXX-REDACTED-XXX', 'new': 'XXX-REDACTED-XXX'}})
            if email_host_cur != email_host:
                ret['changes'].update({'email_host': {'old': email_host_cur, 'new': email_host}})
            if email_port_cur != email_port:
                ret['changes'].update({'email_port': {'old': email_port_cur, 'new': email_port}})
            if enable_email_encrypt_cur != enable_email_encrypt:
                ret['changes'].update({'enable_email_encrypt':
                                           {'old': enable_email_encrypt_cur, 'new': enable_email_encrypt}})
            if set(alerts_cur) != set(alerts):
                # alert_diff = set(alerts_cur).symmetric_difference(set(alerts))
                ret['changes'].update({'alerts': {'old': format(','.join(alerts_cur)),
                                                  'new': format(','.join(alerts))}})
    except StandardError as err:
        log.error('Error: {0}'.format(err))
        return False

    if not __opts__['test']:
        result = __salt__['couchbase_cli.set_alerts'](host, port, username, password, enable_email_alert, email_sender,
                                                      email_user, email_password, email_host, email_port,
                                                      enable_email_encrypt, email_recipients, alerts)
        if 'Error' in result:
            ret['result'] = False
            ret['comment'] = result['Error']
            return ret
        elif 'Changed' in result:
            ret['comment'] = result['Changed']

    if __opts__['test']:
        ret['comment'] = 'Alerts on cluster \'{1}:{2}\' will be configured.'.format(host, port)

    return ret


