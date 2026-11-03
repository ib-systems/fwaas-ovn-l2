"""Tests for fwaas_ovn_l2.driver against the real neutron-fwaas 2025.2 acl.py.

neutron / neutron-lib / oslo are not installable here, so only the modules
the code under test imports are stubbed, with values copied from
neutron-lib master. acl.py, constants.py and fwaas_constants.py are the
real 2025.2 files. The base OVNFwaasDriver is a stub (its real module pulls
in all of neutron); the test drives the same acl calls the stock driver
makes.

Run: python test_driver.py <neutron-fwaas-2025.2-src> <package-src> <out.json>
"""
import json
import sys
import types


def stub(name, **attrs):
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    sys.modules[name] = mod
    return mod


fwaas_src, pkg_src, out_path = sys.argv[1:4]

# --- stubs for third-party modules (values from neutron-lib master) ---
stub('neutron_lib')
stub('neutron_lib.constants', INGRESS_DIRECTION='ingress',
     EGRESS_DIRECTION='egress', IP_VERSION_4=4, IP_VERSION_6=6,
     PROTO_NAME_TCP='tcp', PROTO_NAME_UDP='udp', PROTO_NAME_SCTP='sctp',
     PROTO_NAME_ICMP='icmp', PROTO_NAME_IPV6_ICMP='ipv6-icmp')
stub('neutron_lib.api')
stub('neutron_lib.api.definitions')
stub('neutron_lib.api.definitions.portbindings', VIF_TYPE='binding:vif_type',
     VIF_TYPE_OVS='ovs', VIF_TYPE_VHOST_USER='vhostuser')


class FirewallGroupPortInUse(Exception):
    def __init__(self, port_ids):
        super().__init__("Port(s) %s provided already associated with other "
                         "firewall group(s)." % port_ids)
        self.port_ids = port_ids


stub('neutron_lib.exceptions', NeutronException=Exception)
stub('neutron_lib.exceptions.firewall_v2',
     FirewallGroupPortInUse=FirewallGroupPortInUse)
stub('neutron')
stub('neutron._i18n', _=lambda s: s)
stub('neutron.common')
stub('neutron.common.ovn')
stub('neutron.common.ovn.utils',
     ovn_port_group_name=lambda i: 'pg_' + i.replace('-', '_'))


class _Log:
    def __getattr__(self, name):
        return lambda *a, **k: None


stub('oslo_log')
stub('oslo_log.log', getLogger=lambda n: _Log())
sys.modules['oslo_log'].log = sys.modules['oslo_log.log']

# Base driver stub: records precommit calls.
calls = []


class OVNFwaasDriver:
    def __init__(self, service_plugin):
        self.service_plugin = service_plugin
        self._nb_ovn = None

    def update_firewall_group_precommit(self, context, old, new):
        calls.append(('super_precommit', new['id']))

    def _process_acls_by_policies_or_rule(self, context, policy_ids,
                                          rule_info=None, op='add'):
        calls.append(('process', list(policy_ids), rule_info, op))


sys.path[:0] = [fwaas_src, pkg_src]
import neutron_fwaas.services.firewall.service_drivers.ovn as ovn_pkg  # noqa
stub('neutron_fwaas.services.firewall.service_drivers.ovn.exceptions',
     OperatorNotSupported=Exception)
l3 = stub('neutron_fwaas.services.firewall.service_drivers.ovn.'
          'firewall_l3_driver', OVNFwaasDriver=OVNFwaasDriver)
ovn_pkg.firewall_l3_driver = l3

from neutron_fwaas.services.firewall.service_drivers.ovn import acl  # noqa
from fwaas_ovn_l2 import driver  # noqa

stock_process = acl.process_rule_for_pg


# --- fake NB API recording what would be written ---
class Cmd:
    def __init__(self, name, kw):
        self.name, self.kw = name, kw

    def execute(self, check_error=False):
        return nb.rows


class FakeNB:
    def __init__(self):
        self.added, self.deleted, self.modified, self.rows = [], [], [], []
        self.pgs = []

    def pg_acl_add(self, **kw):
        self.added.append(kw)
        return Cmd('add', kw)

    def pg_acl_del(self, pg, direction, priority, match):
        self.deleted.append((pg, direction, priority, match))
        return Cmd('del', {})

    def db_set(self, table, uuid, *cols):
        self.modified.append((uuid, cols))
        return Cmd('set', {})

    def pg_acl_list(self, pg):
        return Cmd('list', {})

    def pg_add(self, **kw):
        self.pgs.append(kw)
        return Cmd('pg_add', kw)

    def transaction(self, check_error=False):
        nbself = self

        class _T:
            def __enter__(s):
                return Txn()

            def __exit__(s, *a):
                return False
        return _T()


class Txn:
    def add(self, cmd):
        pass


failures = []


def check(name, cond, detail=''):
    print(('PASS ' if cond else 'FAIL ') + name + (f'  [{detail}]' if detail and not cond else ''))
    if not cond:
        failures.append(name)


# 1. Before the driver is constructed the stock mapping is untouched.
nb = FakeNB()
acl.process_rule_for_pg(nb, Txn(), 'pg_x', {'id': 'r', 'action': 'reject', 'ip_version': 4, 'protocol': 'tcp', 'destination_port': '25'}, 'egress')
check('stock mapping unchanged before driver init', nb.added[0]['direction'] == 'to-lport' and nb.added[0]['match'].startswith('outport'))

drv = driver.OVNVMPortFwaasDriver(service_plugin=object())
driver.OVNVMPortFwaasDriver(service_plugin=object())  # second init must not double-swap

PG = 'pg_11111111_2222_3333_4444_555555555555'
smtp4 = {'id': 'smtp4', 'action': 'reject', 'ip_version': 4, 'protocol': 'tcp', 'destination_port': '25', 'position': 0}
smtp6 = {'id': 'smtp6', 'action': 'reject', 'ip_version': 6, 'protocol': 'tcp', 'destination_port': '25', 'position': 1}
http_in = {'id': 'http', 'action': 'allow', 'ip_version': 4, 'protocol': 'tcp', 'destination_port': '80', 'position': 0}

# 2. Egress reject (from the VM) -> from-lport / inport.
nb = FakeNB()
for r in (smtp4, smtp6):
    acl.process_rule_for_pg(nb, Txn(), PG, r, 'egress')
a4, a6 = nb.added
check('egress v4 reject -> from-lport', a4['direction'] == 'from-lport', a4)
check('egress v4 reject match', a4['match'] == f'inport == @{PG} && ip4 && tcp && tcp.dst == 25', a4['match'])
check('egress v4 reject action/priority', (a4['action'], a4['priority']) == ('reject', 2000), a4)
check('egress v6 reject match', a6['match'] == f'inport == @{PG} && ip6 && tcp && tcp.dst == 25', a6['match'])
check('egress v6 reject priority', a6['priority'] == 1999, a6)

# 3. Ingress rule (to the VM) -> to-lport / outport.
nb = FakeNB()
acl.process_rule_for_pg(nb, Txn(), PG, http_in, 'ingress')
check('ingress allow -> to-lport/outport', nb.added[0]['direction'] == 'to-lport' and nb.added[0]['match'].startswith(f'outport == @{PG}'), nb.added[0])

# 4. Default drops: 4 ACLs, both directions, priority 1001 (below SG 1002).
nb = FakeNB()
acl.add_default_acls_for_pg(nb, Txn(), PG)
dirs = sorted((a['direction'], a['match']) for a in nb.added)
check('4 default drops', len(nb.added) == 4 and all(a['priority'] == 1001 and a['action'] == 'drop' for a in nb.added), nb.added)
check('default drops cover both directions symmetrically',
      dirs == sorted([('from-lport', f'inport == @{PG} && ip4'), ('from-lport', f'inport == @{PG} && ip6'),
                      ('to-lport', f'outport == @{PG} && ip4'), ('to-lport', f'outport == @{PG} && ip6')]), dirs)


# 5. Rule delete/update finds the ACL written with VM directions.
class Row:
    def __init__(self, acl_dict, uuid):
        self.uuid = uuid
        self.direction = acl_dict['direction']
        self.priority = acl_dict['priority']
        self.external_ids = {'neutron:firewall_rule_id': acl_dict['neutron:firewall_rule_id']} if 'neutron:firewall_rule_id' in acl_dict else {}


nb = FakeNB()
acl.process_rule_for_pg(nb, Txn(), PG, smtp4, 'egress')
written = nb.added[0]
ext_key = [k for k in written if k.startswith('neutron:')][0]
row = Row(written, 'uuid-1')
row.external_ids = {ext_key: written[ext_key]}
nb.rows = [row]
acl.process_rule_for_pg(nb, Txn(), PG, smtp4, 'egress', op='del')
check('delete finds VM-direction ACL', nb.deleted == [(PG, 'from-lport', 2000, written['match'])], nb.deleted)
nb.deleted.clear()
acl.process_rule_for_pg(nb, Txn(), PG, dict(smtp4, destination_port='587'), 'egress', op='mod')
check('update finds VM-direction ACL', nb.modified and nb.modified[0][0] == 'uuid-1' and 'tcp.dst == 587' in nb.modified[0][1][0][1], nb.modified)

# 6. Port support.
check('VM port vif ovs supported', drv.is_supported_l2_port({'binding:vif_type': 'ovs'}))
check('VM port vhostuser supported', drv.is_supported_l2_port({'binding:vif_type': 'vhostuser'}))
check('baremetal/unbound not supported', not drv.is_supported_l2_port({'binding:vif_type': 'other'}) and not drv.is_supported_l2_port({'binding:vif_type': 'unbound'}))
check('router ports rejected', not drv.is_supported_l3_port({'device_owner': 'network:router_interface'}))

# 7. Default FWG auto-association blocked; other groups unaffected.
calls.clear()
try:
    drv.update_firewall_group_precommit(None, {'id': 'd', 'name': 'default', 'ports': []}, {'id': 'd', 'name': 'default', 'ports': ['vm1']})
    check('default FWG add blocked', False, 'no exception')
except FirewallGroupPortInUse as e:
    check('default FWG add blocked (PortInUse subclass, caught by plugin)', isinstance(e, FirewallGroupPortInUse) and type(e).__name__ == 'DefaultGroupAutoAttachDisabled' and e.port_ids == ['vm1'] and calls == [])
    check('honest message', 'auto-association is disabled' in driver.DefaultGroupAutoAttachDisabled.message)
drv.update_firewall_group_precommit(None, {'id': 'd', 'name': 'default', 'ports': ['vm1']}, {'id': 'd', 'name': 'default', 'ports': []})
check('default FWG port removal allowed', calls == [('super_precommit', 'd')])
calls.clear()
drv.update_firewall_group_precommit(None, {'id': 's', 'name': 'smtp-restricted', 'ports': []}, {'id': 's', 'name': 'smtp-restricted', 'ports': ['vm1']})
check('normal FWG add passes to stock precommit', calls == [('super_precommit', 's')])

# 8. No default drops: init creates only the port group; clear empties ACLs.
nb = FakeNB()
drv._nb_ovn = nb
drv._init_firewall_group(Txn(), '11111111-2222-3333-4444-555555555555')
check('init creates PG only', len(nb.pgs) == 1 and nb.pgs[0]['name'] == PG and nb.pgs[0]['acls'] == [] and nb.added == [], (nb.pgs, nb.added))
check('init PG keeps FWaaS external_ids', list(nb.pgs[0]['external_ids'].values()) == ['11111111-2222-3333-4444-555555555555'], nb.pgs[0])
nb = FakeNB()
drv._nb_ovn = nb
drv._clear_rules_for_firewall_group(None, Txn(), '11111111-2222-3333-4444-555555555555')
check('clear sets acls=[] (also drops old default drops)', nb.modified == [(PG, (('acls', []),))] and nb.added == [], nb.modified)

# 9. remove_rule re-renders the whole policy (no stale priorities).
calls.clear()
drv.remove_rule_postcommit(None, 'pol-1', {'firewall_rule_id': 'r1'})
check('remove_rule -> full re-render of the policy', calls == [('process', ['pol-1'], None, 'add')], calls)

# Dump the ACLs a smtp-restricted group would get (rules + 4 defaults) for ovn-trace.
nb = FakeNB()
for r in (smtp4, smtp6):
    acl.process_rule_for_pg(nb, Txn(), 'fwg_smtp', r, 'egress')
json.dump([{k: a[k] for k in ('direction', 'priority', 'match', 'action')} for a in nb.added], open(out_path, 'w'), indent=1)

print(f'\n{len(failures)} failure(s)')
sys.exit(1 if failures else 0)
