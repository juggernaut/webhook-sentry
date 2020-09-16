# Webhook Sentry
Webhook Sentry is a proxy that helps you send [webhooks](https://en.wikipedia.org/wiki/Webhook) to your customers securely.

## Why?
### Security
Sending webhooks appears simple on the surface -- they're just HTTP requests after all. But sending them _securely_ is hard. If your application sends webhooks, does your implementation
1. Prevent SSRF attacks?
2. Protect against DNS rebind attacks?
3. Support mutual TLS?
4. Validate SSL certificate chains correctly?

By proxying webhooks through Webhook Sentry, you get all of these for free.

### Auditability
Sending webhooks involves making connections to untrusted and possibly malicious servers on the public internet. Maintaining an audit trail is essential for forensics and compliance.
Limiting the set of instances that send such requests to a single proxy layer makes auditing simpler and more manageable.

### Static Egress IPs
Many customers require webhook requests to be sent from a list or range of static IPs in order to configure their firewalls. In a cloud environment with autoscaling, you
may not want to allocate static IPs to your application instances. In other situations, like serverless applications, it may be impossible to assign static IPs. With a centralized
egress proxy layer, you can assign static IPs only to your proxy instances.






