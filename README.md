# Auth Policy Controller

Auth Policy Controller (APC) is an open-source simple to configure, high-performance authorization service focused on working with HTTP requests. Integrates into the infrastructure layer of your project and does not require changes to your applications. Configured in YAML format (without new declarative languages) so that your team can easily get started with it.

## Getting started 

See example of [nginx integration](./examples/nginx).

### Run as a container:

```docker run -v ./policy.yaml:/policy.yaml -v ./data.json:/data.json -p 8080:8080 ghcr.io/auth-policy-controller/agent:latest run /policy.yaml /data.json```

You can see the detailed flags of the `run` command [bellow](#run-options).

### Static binaries 

Download from [releases on GitHub (expand "Assets")](https://github.com/auth-policy-controller/apc/releases) archive for you OS and ARCH (supported linux and macos)

```sh
curl -L https://github.com/auth-policy-controller/apc/releases/download/v{version}/agent_{os}_{arch}.tar.gz > agent.tar.gz 
tar -xvf agent.tar.gz
mv agent_{os}_{arch} /usr/local/bin/apcagent
```

## Configuring policies

Configuration is a definition of an unlimited number of access rules (policies) for URI. Each policy consists of:

- one or more URIs (regular expressions can be used), to which the policy should be applied
- [HTTP methods](https://developer.mozilla.org/ru/docs/Web/HTTP/Methods) (applicable to any of the specified URIs)
- client names that are allowed access, while all others will be denied

The default client name is extracted from the HTTP header `x-source`, see below how to override it. Empty clients list means access will be denied to everyone, since no client will match the rule. To allow everyone, you can use a wildcard (`*`).

Example:

```yaml
policies:
  - uri: ["/users", "/order/[0-9]+/info"]
    method: ["get"]
    allow: ["admin"]
  - uri: ["/order"]
    method: ["post"]
    allow: ["*"] # wildcard means - access is allowed for all clients
```

The same URI can only be used once. Otherwise, it will not be clear which rule should take effect first. Special attention should be paid to the use of regular expressions, as the likelihood of pattern crossmatching there is higher.

### Policy check order

The parser checks policies from top to bottom until the first match with the URI template is found and immediately returns the result without checking the remaining policies. Please note that in each policy, first the match with non-regular expression patterns is checked, and then with regular expressions.

### Multiple client name sources

By default, the client name is determined from the HTTP header `x-source`, but this behavior can be changed and even use multiple sources with prefixes.

Example:

```yaml
cn:
  - header: "x-source" # without prefix
  - header: "admin-name"
    prefix: "admin:"
policies:
  - uri: ["/users", "/order/[0-9]+/info"]
    method: ["get"]
    allow: ["admin:jhon", "admin:jessica"]
  - uri: ["/order"]
    method: ["post"]
    allow: ["user", "admin:*"] # you can use wildcard with prefixes
```

You can configure only one source without a prefix in one configuration file. In the near future, the ability to use JWT tokens to extract the client name will also be added.

### Dynamic data

There are often situations where data changes dynamically, and we need to make authorization decisions based on actual data. For example, when a user's group changes, and we want to give access specifically for the group. You can load data in json format to agent, and search with [JSONPath](https://kubernetes.io/docs/reference/kubectl/jsonpath/), and update [within a time interval](#updating-policy-and-data).

Example:

data:

```json
{
    "admins": [
        {
            "name": "jhon",
        },
        {
            "name": "jessica",
        }
    ],
    "manager": [
        {
            "name": "torin"
        }
    ]
}
```

policies:

```yaml
policies:
  - uri: ["/user"]
    allow: ["{.admins[*].name}", "jared"]
  - uri: ["/order"]
    allow: ["prefix:{.manager[*].name}"]
```

Query `{.team1[*].name}` returns `["jhon", "jessica"]`. This result that will be used for access checking. At the same time, the list is merged with the other listed clients. That is, the final policy configuration can be represented in this way.

```yaml
policies:
  - uri: ["/user"]
    allow: ["jhon", "jessica", "jared"]
  - uri: ["/order"]
    allow: ["torin"]
```

You don't need to update the policies, but only update the data.

### Variables 

Variables allow to combine clients into groups (including dynamic data) to use them several times. For example:

```yaml
cn:
  - header: "x-source"
  - header: "admin"
    prefix: "admin:"
vars:
  super_admins: ["admin:jhon", "admin:jessica"]
  admins: ["admin:*"]
  managers: ["prefix:{.manager[*].name}"]
policies:
  - uri: ["/user"]
    allow: ["$admins", "jared"]
  - uri: ["/order"]
    allow: ["$managers"]
```

## Run options 

Agent run command signature

```bash
Usage:
  main run [flags] [policy-file.yaml] [data-file.json (optional)]

Flags:
      --addr string                set listening address of the http server (e.g., [ip]:<port>) (default ":8080")
      --log-check-results          log info about check requests results (default false)
      --log-level string           set log level (default "info")
      --monitoring-addr string     set listening address for the /health and /metrics (e.g., [ip]:<port>) (default ":9191")
      --update-files-seconds int   set policy/data file updating period (seconds) (default 0 - do not update)
```

- `policy-file.yaml` [authorization policies](#configuring-policies)
- `data-file.json` [dynamic data](#dynamic-data) (optional)

The order of files doesn't matter. Policies are always expected in `yaml`, and dynamic data in `json`. Using the `--update-files-seconds` flag, you can specify the number of seconds after which the agent will reload the files again, thereby updating them.

## Metrics

APC agent exposes HTTP endpoint that responds metrics in the [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format). By default metrics endpoint is available at `"http://localhost:9191/stats/prometheus"`, but you can configure host and port with `--monitoring-addr` [option](#run-options).

To configure Prometheus to scrape from APC you'll need a YAML configuration file similar to this:

```yaml
global:
  scrape_interval: 10s

scrape_configs:
  - job_name: apc 
    metrics_path: "/stats/prometheus"
    static_configs:
      - targets: ['localhost:9191']
```

APC agent exposes these metrics

| metric name | metric type | description |
|-------------|-------------|-------------|
| check_rq_total | Counter | A counter of check requests |
| check_rq_failed | Counter | A counter of failed check requests (500 response code) |
| check_rq_duration | Histogram | A histogram of duration for check requests |

Also agent exposes runtime metrics provided automatically by the [Prometheus Go Client](https://github.com/prometheus/client_golang). They are prefixed with `go_*` and `process_*` (only for linux).

- go_memstats_alloc_bytes
- go_memstats_alloc_bytes_total
- go_memstats_sys_bytes
- go_memstats_mallocs_total
- go_memstats_frees_total
- go_memstats_heap_alloc_bytes
- go_memstats_heap_sys_bytes
- go_memstats_heap_idle_bytes
- go_memstats_heap_inuse_bytes
- go_memstats_heap_released_bytes
- go_memstats_heap_objects
- go_memstats_stack_inuse_bytes
- go_memstats_stack_sys_bytes
- go_memstats_mspan_inuse_bytes
- go_memstats_mspan_sys_bytes
- go_memstats_mcache_inuse_bytes
- go_memstats_mcache_sys_bytes
- go_memstats_buck_hash_sys_bytes
- go_memstats_gc_sys_bytes
- go_memstats_other_sys_bytes
- go_memstats_next_gc_bytes

## Logging

There are situations when your policies behave in a way that is not what you expect. Logging the results of policy checking may help you understand faster which specific policy from the set of policies was matched by the request condition (this is not always obvious, especially if using regular expression templates). You can also see which client name the agent has determined.

The APC agent has a logging feature for checking result. By default it is disabled. To enable it, you can use a parameter `--log-check-results`. Then all checking requests will be logged similar to this:

```
time= level=INFO msg="check result: false, uri: test, method: POST, headers: map[accept:*/* user-agent:curl/8.6.0 x-method:POST x-path:test], policy endpoint: /order/[0-9]+/info, parsed client: "
time= level=INFO msg="check result: false, uri: user, method: GET, headers: map[accept:*/* user-agent:curl/8.6.0 x-method:GET x-path:user x-source:client2], policy endpoint: default, parsed client: client2"
```

Arguments desctiption:

- `uri` - original request URI
- `method` - original request method
- `headers` - original request headers (used for client names)
- `policy endpoint` - mathched endpoint from policy (ex. `/order/[0-9]+/info`)
- `parsed client` - client name with prefix

## How to contribute

- make a pull request to the latest release branch (release-*)
- [create issue](https://github.com/auth-policy-controller/apc/issues/new)