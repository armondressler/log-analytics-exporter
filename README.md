# log-analytics-exporter
- Query azure log-analytics workspaces
- Transform and return query results as prometheus metrics

Purpose: Upon receiving http POST request to the /api/config endpoint, read the configuration (see below) from the body, validate and write it to /data/config.json. The config file is located in a mounted fileshare which was added by using: "az webapp config storage-account update -g my-resource-group-name -n log-analytics-exporter  --custom-id justsomeuniquestring --storage-type AzureFiles  --account-name somestorageaccountname  --share-name log-analytics-exporter-config --access-key 'STORAGE ACCOUNT ACCESS KEY 1' --mount-path /data" .

Upon receiving http GET request to the /api/metrics endpoint, read configuration containing information about Azure Log Analytics workspaces and queries to be performed. 
Perform queries and use results to form a response with valid prometheus metrics. The Managed Identity (see "Identities" blade in Azure Functions) is system assigned and requires the Log Analytics Workspace Reader Role to perform the queries. The actual metric value to exposed will be fetched from a column called "metric" in the LAW query response.

Any 'label' mentioned in the config section will be used to add a label to the exposed prometheus metric. The label key will be the name used in the config section and 
value will be the value from the corresponding column in the query response. 

Any static_label and its value found in the config section will be applied to the resulting prometheus metric as is. 

The type and help options are used to expose TYPE and HELP sections for the resulting prometheus metric. The type options has to be one of "counter", "gauge", "histogram", "summary" or "untyped". The configuration is a JSON dictionary with the keys being the LAW IDs and their values being a list of dictionaries with each dict being a config for one metric to be exposed. Every config must contain at least the keys "metric" (the name of the metric) and query (the LAW query to perform).

Example config for a log analytics workspace with the id 7965aec3-7c67-48b5-a4a4-348dd932e123 as follows:
```
{
  "7965aec3-7c67-48b5-a4a4-348dd932e123":
    [
      {"metric": "kubernetes_billable_logdata_mb",
       "type": "counter",
       "help": "Logdata ingested in LAW measured in megabytes of billable data",
       "labels": ["namespace"],
       "static_labels": {"product": "curamed"}
       "query": "let billableTimeView = 1d; ContainerLog | join(KubePodInventory | where TimeGenerated > startofday(ago(billableTimeView))) on ContainerID | where TimeGenerated > startofday(ago(billableTimeView)) | summarize (metric)=sum(_BilledSize) / 1000 / 1000 by (bu)=bin(TimeGenerated, 1d), (namespace)=Namespace  | order by metric | limit 5"
      },
      {"metric": "kubernetes_nodes_ready_count",
       "type": "gauge",
       "labels": ["cluster","nodepool"],
       "query":  "let endDateTime = now(); let startDateTime = ago(1h); let trendBinSize = 1m; KubeNodeInventory | where TimeGenerated < endDateTime | where TimeGenerated >= startDateTime | distinct ClusterName, Computer, _ResourceId,TimeGenerated | summarize ClusterSnapshotCount = count() by bin(TimeGenerated, trendBinSize), ClusterName, Computer, _ResourceId | join hint.strategy=broadcast kind=inner ( KubeNodeInventory | where TimeGenerated < endDateTime | where TimeGenerated >= startDateTime | summarize TotalCount = count(), ReadyCount = sumif(1, Status contains ('Ready')) by ClusterName, Computer,  bin(TimeGenerated, trendBinSize), _ResourceId  | extend NotReadyCount = TotalCount - ReadyCount ) on ClusterName, Computer, _ResourceId, TimeGenerated | project   TimeGenerated, ClusterName, Computer, ReadyCount = todouble(ReadyCount) / ClusterSnapshotCount,  NotReadyCount = todouble(NotReadyCount) / ClusterSnapshotCount, _ResourceId | order by ClusterName asc, Computer asc, TimeGenerated desc, _ResourceId | distinct Computer, ClusterName, ReadyCount | summarize metric=sum(ReadyCount) by cluster=ClusterName"
    }
  ]
}
```

