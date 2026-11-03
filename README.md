# fwaas-ovn-l2

neutron-fwaas v2 driver for **VM ports** on ML2/OVN, for neutron-fwaas
**2025.2**. Subclass of the stock `OVNFwaasDriver`:

* accepts VM ports (`binding:vif_type` `ovs` / `vhostuser`), rejects router
  ports;
* writes rules with VM-port directions (egress = `from-lport` / `inport`,
  ingress = `to-lport` / `outport`, same as security groups);
* writes no default drop ACLs: traffic not matched by a rule is decided by
  security groups, so a port without port security keeps its traffic. On VM
  ports a policy of only allow rules does nothing; to deny everything else add
  an explicit deny rule;
* re-renders the whole policy when a rule is removed (stock code leaves stale
  ACL priorities);
* never auto-attaches new VM ports to a project's `default` firewall group.

## Build into kolla images

`kolla-build.conf`:

```ini
[neutron-base-plugin-fwaas-ovn-l2]
type = git
location = https://<your-git>/infra/fwaas-ovn-l2.git
reference = 0.2.0
```

For a quick local build without git:

```ini
[neutron-base-plugin-fwaas-ovn-l2]
type = local
location = /path/to/fwaas-ovn-l2
```

```sh
kolla-build --base ubuntu --openstack-release 2025.2 neutron-server
```

The `neutron-base` Dockerfile already adds `plugins-archive` and runs
`pip install -c upper-constraints.txt /plugins/*`, so no template override is
needed. pip needs `setuptools` from your PyPI mirror during the build.

## Enable

`/etc/kolla/config/neutron/neutron-server.conf` (neutron-server under uWSGI
reads only `neutron.conf` and `ml2_conf.ini`, not `fwaas_driver.ini`):

```ini
[service_providers]
service_provider = FIREWALL_V2:fwaas_db:fwaas_ovn_l2.driver.OVNVMPortFwaasDriver:default
```

The `stevedore ... Could not load fwaas_ovn_l2.driver.OVNVMPortFwaasDriver`
WARNING at start-up is harmless: neutron first looks the provider up as an
entry-point alias, then imports it by class path.

## SMTP block

```sh
for v in 4 6; do
  openstack firewall group rule create --name smtp-v$v --protocol tcp \
    --destination-port 25 --ip-version $v --action reject --share
done
openstack firewall group policy create --firewall-rule smtp-v4 \
  --firewall-rule smtp-v6 --share smtp-block
# one group per project (2025.2: ports must be in the group's project)
openstack firewall group create --name smtp-restricted --project <project> \
  --egress-firewall-policy smtp-block
openstack firewall group set   --port <port-id> smtp-restricted   # block
openstack firewall group unset --port <port-id> smtp-restricted   # unblock
```

FWaaS OSC commands need `python-neutronclient<12` (12.0.0+ moved them to
python-openstackclient).

## Operational notes

* Ports must be bound to a host before they can be added.
* Add all ports of a VM; a new interface is not added automatically.
* No FWaaS OVN DB sync exists in 2025.2. After restoring or rebuilding the
  OVN NB, re-attach ports (`unset` then `set`).
* 2026.1+: the upstream FWaaS `neutron-ovn-db-sync-util` plugin forces the
  stock driver and would add router-direction ACLs in `repair` mode. Run the
  utility only with `--sync_plugin neutron_nb_sync` / `neutron_sb_sync`.
* Groups created by 0.1.0 still carry 4 default drop ACLs; they are removed
  the next time the group's policy is re-applied
  (`firewall group unset --egress-firewall-policy` + `set`).

## Tests

`tests/test_driver.py` runs the driver against the real neutron-fwaas 2025.2
`acl.py` with neutron/neutron-lib stubbed:

```sh
python3 -I tests/test_driver.py <neutron-fwaas-2025.2-src> . /tmp/acls.json
```
