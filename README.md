# saltstack_couchbase

# Missing saltstack modules for couchbase

How to use the state modules?


```yaml
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
```

