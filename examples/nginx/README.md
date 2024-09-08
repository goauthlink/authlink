# Overview 

AuthRequestAgent adds the ability for Nginx to authorize HTTP requests based on access policies before proxying to the target service. There is no need to change the code of your service. Authorization works at the infrastructure level and does not depend on the programming languages used.

# How it works

Agent works as a daemon, while nginx communicates with it via HTTP. The agent loads policies (policy.yaml) and data (data.json, if necessary) and stores them in memory. Using the the [ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html), nginx check authorization policies through the agent. Based on the loaded policies, the agent responds whether the given client is allowed to rich the service. Nginx, based on the response received from the agent, either proxies the request to the service or returns an access error 403. To improve response speed, the agent should be placed as close to nginx as possible. If necessary, the agent can update policies and data at a specified interval.

![img-desc](./nginx-arch.svg)

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

Next, run the command `docker compose up -d` in the `examples/nginx` directory, to get a working example with Nginx as a proxy. Now, we can try send HTTP requests to nginx and verify that the rules are working as expected.

**Example 1**

Request:

```curl
curl -XPUT -i localhost:80/user -H "x-source:client3"
```

Response:

```bash
HTTP/1.1 200 OK
Server: nginx/1.27.1
Date: Wed, 21 Aug 2024 19:36:50 GMT
Content-Type: text/plain
Content-Length: 142
Connection: keep-alive

Request served by 359a35388a96

PUT /user HTTP/1.0

Host: backend:8080
Accept: */*
Connection: close
User-Agent: curl/8.6.0
X-Source: client3
```

Nginx authorized the request and proxied it to the backend, which returned a 200 response.

**Example 2**

Request:

```curl
curl -XPUT -i localhost:80/user -H "x-source:client2"
```

Response:

```bash
HTTP/1.1 403 Forbidden
Server: nginx/1.27.1
Date: Wed, 21 Aug 2024 19:39:54 GMT
Content-Type: text/html
Content-Length: 153
Connection: keep-alive

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.27.1</center>
</body>
</html>
```

Nginx received a response from the agent that the original request was not authorized. Nginx returned a 403.

# Nginx configuration

Nginx authorizes requests using the module [ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html) (usually included in most nginx builds). It's enough to use the directive `auth_request` so that nginx makes a request to the specified URL where the agent is running.

It is also necessary to additionally pass the following arguments in the headers of the authorization request (so that these data can be used in the rules):

- `X-Path` original request URI
- `X-Method` original request HTTP method


A working Nginx configuration may look like this:

```nginx
location / {
    auth_request /auth;
    proxy_pass http://backend:8080; # target service
}

location = /auth {
    proxy_pass http://agent:8090/check;
    proxy_method POST;
    proxy_pass_request_body off;
    proxy_set_header X-Path $request_uri; # original request URI
    proxy_set_header X-Method $request_method; # original request HTTP method
}
```

Based on the agent's response, Nginx will either proxy the request to `backend:8080` or return 403.