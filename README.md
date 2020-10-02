# Webhook Sentry [![Actions Status](https://github.com/juggernaut/egress-proxy/workflows/Go/badge.svg)](https://github.com/juggernaut/egress-proxy/actions) [![release](https://img.shields.io/github/v/release/juggernaut/webhook-sentry?sort=semver)]
Webhook Sentry is a proxy that helps you send [webhooks](https://en.wikipedia.org/wiki/Webhook) to your customers securely.

## Why?
### Security
Sending webhooks appears simple on the surface -- they're just HTTP requests after all. But sending them _securely_ is hard. If your application sends webhooks, does your implementation
1. Prevent SSRF attacks?
2. Protect against DNS rebind attacks?
3. Support mutual TLS?
4. Validate SSL certificate chains correctly?
5. Use an updated CA certificate bundle?
6. Specify reasonable idle socket and connection timeouts?

By proxying webhooks through Webhook Sentry, you get all of these for free.

### Auditability
Sending webhooks involves making connections to untrusted and possibly malicious servers on the public internet. Maintaining an audit trail is essential for forensics and compliance.
Limiting the set of instances that send such requests to a single proxy layer makes auditing simpler and more manageable.

### Static Egress IPs
Many customers require webhook requests to be sent from a list or range of static IPs in order to configure their firewalls. In a cloud environment with autoscaling, you
may not want to allocate static IPs to your application instances. In other situations, like serverless applications, it may be impossible to assign static IPs. With a centralized
egress proxy layer, you only need to assign static IPs to your proxy instances.

## Getting Started
1. Download the latest release for your platform
2. Run the downloaded binary:
```
whsentry
```

Webhook Sentry runs on port 9090 by default. You can configure the address and port in the `listeners` (TODO: ink) section of the config.

## Usage
### HTTP target

```
curl -x http://localhost:9090 http://www.google.com
```

### HTTPS target
HTTP clients create a `CONNECT` tunnel when a proxy is configured and the target is a `https` URL. This does not give us the benefits of initiating TLS from the proxy. To get around this behavior, Webhook Sentry supports a unique way of proxying to HTTPS targets. Pass a `X-WhSentry-TLS` header and change the protocol to `http`:

```
curl -v -x http://localhost:9090 --header 'X-WhSentry-TLS: true' http://www.google.com
```

Although `CONNECT` is supported, I strongly recommend using the header approach to take advantage of the TLS capabilities of Webhook Sentry, like mutual TLS and robust certificate validation.

### Mutual TLS
Specify `clientCertFile` and `clientKeyFile` in the YAML configuration to enable mutual TLS:
```
clientCertFile: /path/to/client.pem
clientKeyFile: /path/to/key.pem
```

## Protections
### SSRF attack protection
Webhook Sentry blocks access to private/internal IPs to prevent SSRF attacks:
```
$ curl -i -x http://localhost:9090 http://127.0.0.1:3000

HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
X-Whsentry-Reason: IP 127.0.0.1 is blocked
X-Whsentry-Reasoncode: 1000
Date: Fri, 18 Sep 2020 07:15:20 GMT
Content-Length: 24

IP 127.0.0.1 is blocked
```

Unlike naive implementations, it also correctly checks the IP after DNS resolution. This example makes use of the [1u.ms](http://1u.ms/) service which can serve up DNS records using any IP we want:
```
$ curl -i -x http://localhost:9090 http://make-127-0-0-1-rr.1u.ms

HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
X-Whsentry-Reason: IP 127.0.0.1 is blocked
X-Whsentry-Reasoncode: 1000
Date: Fri, 18 Sep 2020 07:21:58 GMT
Content-Length: 24

IP 127.0.0.1 is blocked
```

### DNS rebind attack prevention
A malicious attacker can set up their DNS such that it first resolves to a valid public IP adddress, but subsequent resolutions point to private/internal IP addresses. This can be used to exploit webhook implementations that validate the resolved IP using `getaddrinfo()` or equivalent, then pass the original URL to a HTTP client library which resolves the host a second time. Again, let's use 1u.ms to first return a valid public IP and then the loopback IP:

```
$ curl -i -x http://localhost:9090 http://make-3-221-81-55-rebind-127-0-0-1-rr.1u.ms/get

HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
Content-Length: 324
Content-Type: application/json
Date: Wed, 30 Sep 2020 07:38:47 GMT
Server: gunicorn/19.9.0

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "make-3-221-81-55-rebind-127-0-0-1-rr.1u.ms",
    "User-Agent": "Webhook Sentry/0.1",
    "X-Amzn-Trace-Id": "Root=1-5f743607-afdf257ca619f90a14fc92b8"
  },
  "origin": "73.189.176.226",
  "url": "http://make-3-221-81-55-rebind-127-0-0-1-rr.1u.ms/get"
}
```

## Limitations
* No IPv6 support
* No TLSv1.3 support




