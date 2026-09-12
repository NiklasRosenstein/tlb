---
title: Security and ownership
description: Namespace boundaries, credential access, resource ownership, and safe lifecycle operation.
---

A tunnel makes an application reachable through its provider. Decide who should connect and configure provider access
policies or application authentication before exposing sensitive services.

## Class administrators control workloads

A class can select the provider image and, for NetBird, a startup command and network capabilities. Treat the ability to
configure a class as permission to run workloads with that provider's credentials, subject to Kubernetes admission
controls.

A namespaced class must use the Service's namespace. References to Secrets in another namespace are rejected. A
cluster-scoped class can reference a central credential namespace, so its administrators must be trusted across the
namespaces that use it.

NetBird setup keys are copied into managed Secrets beside the Service. Cloudflare connector credentials are also mounted
beside the Service. Consider namespace readers and workload creators when deciding where a class is usable.

## Private binding journals

TLB stores durable binding Secrets in its controller namespace. These contain Service/class identities, teardown
credentials, external creation intent, and managed DNS identities.

Restrict access to these Secrets and write access to the controller namespace. Service annotations do not authorize
external ownership. Deleting or manually editing a journal can remove the information required to finish teardown.

Keep the controller namespace available until all managed bindings have finished cleanup. Run one installation per
cluster; replicas share this namespace and its Lease.

## Resource ownership

Managed resources carry binding, Service, and class UIDs. Updates require the expected binding label and Service owner
reference, then use UID and resource-version guards. Names alone are not ownership evidence.

The controller is authoritative for fields it declares in generated workloads. Configure replicas, images, and placement
through a class or Service. Extra fields owned by another manager can coexist, but edits to controller-declared fields
will be reconciled back.

For Cloudflare DNS, records also carry a binding marker. TLB refuses to adopt unrelated records at the requested
hostname. Saved record and tunnel IDs allow cleanup even if a resource's display name changes.

## Deletion order

Service deletion stops the tunnel workloads before removing their mounted configuration and managed persistent storage.
API-managed Cloudflare tunnels and DNS records are cleaned using persisted identity and credentials.

Class deletion coordinates cleanup of its own bindings. Other classes with the same name in another namespace have
different identities. Other owners' finalizers remain intact.

If credentials have been revoked, restore a valid credential in the Secret referenced by the persisted class. Cleanup
can refresh that credential after a provider error while preserving the original account and resource identity. Do not
bypass finalizers merely to make a terminating object disappear.
