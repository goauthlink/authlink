# Overview 

AuthLink adds the ability for Envoy to authorize HTTP requests based on access policies before proxying to the target service. There is no need to change the code of your service. Authorization works at the infrastructure level and does not depend on the programming languages used.

# How it works

Agent works as a daemon, while envoy communicates with it via gRPC. The agent loads policies (policy.yaml) and data (data.json, if necessary) and stores them in memory. Using the the [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) filter, envoy check authorization policies through the agent. Based on the loaded policies, the agent responds whether the given client is allowed to rich the service. Envoy, based on the response received from the agent, either proxies the request to the service or returns an access error 403. To improve response speed, the agent should be placed as close to envoy as possible. If necessary, the agent can update policies and data at a specified interval.

![img-desc](./envoy-arch.svg)

# Quick start 

In this directory you can find a working example.

The target service used is [jmalloc/echo](https://github.com/jmalloc/echo-server), which returns a simple response to any handle.

In the [authorization rules](./agent/policy.yaml), we allow requests to endpoints `GET /user` and `PUT /user` only for users named `client2` and `client3`, respectively. 
The client name `cn` is obtained from the original header `x-source`.

```yaml
cn:
  - header: "x-source"
policies:
  - uri: ["/user"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["/user"]
    method: ["put"]
    allow: ["client3"]
```

Next, run the command `docker compose up -d` in the `examples/envoy` directory, to get a working example with Envoy as a proxy. Now, we can try send HTTP requests to envoy and verify that the rules are working as expected.

**Example 1**

Request:

```curl
curl -XPUT -i localhost:80/user -H "x-source:client3"
```

Response:

```bash
HTTP/1.1 200 OK
content-type: text/plain
content-length: 234
date: Wed, 01 Jan 2025 18:44:42 GMT
x-envoy-upstream-service-time: 0
server: envoy

Request served by c391ab9e3ea5

PUT /user HTTP/2.0

Host: localhost
Accept: */*
User-Agent: curl/8.7.1
X-Envoy-Expected-Rq-Timeout-Ms: 15000
X-Forwarded-Proto: http
X-Request-Id: 4cc5947a-5051-4c9c-84bc-127accc8da4a
X-Source: client3

```

Envoy authorized the request and proxied it to the backend, which returned a 200 response.

**Example 2**

Request:

```curl
curl -XPUT -i localhost:80/user -H "x-source:client2"
```

Response:

```bash
HTTP/1.1 403 Forbidden
date: Wed, 01 Jan 2025 18:44:58 GMT
server: envoy
content-length: 0
```

Envoy received a response from the agent that the original request was not authorized. Envoy returned a 403.

# Envoy configuration

Envoy authorizes requests using the filter [ext_authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) filter (included in standard envoy builds). 

Example:

```yaml
http_filters:
  - name: envoy.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      failure_mode_allow: false
      grpc_service:
        envoy_grpc:
          cluster_name: ext-authz
```

See full example in `examples/envoy/proxy/envoy.yaml`

# AuthLink envoy extension

To integrate with Envoy AuthLink uses [extensions](https://github.com/goauthlink/authlink/tree/master/envoy) since the implementation of the gRPC method is required.