# Kubeapi-load-balancer

A simple layer 4 reverse proxy to distribute the traffic to multiple 
kube-apiservers on the kubernetes-master units.

# User

Relate this charm to the kubernetes-master charm using the reverseproxy 
relation.

```
juju deploy kubeapi-load-balancer
juju deploy kubernetes-master
juju add-relation kubernetes-master:kube-api-endpoint kubeapi-load-balancer:reverseproxy 
```

Please see the 
[Canonical Distribution of Kubernetes](https://jujucharms.com/canonical-kubernetes/)
for more information on how this charm is used to reverse proxy traffic to the
kubernetes-master charm.
