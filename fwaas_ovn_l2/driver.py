"""FWaaS v2 OVN driver for VM ports (neutron-fwaas 2025.2).

Stock OVNFwaasDriver maps directions as seen from a router port
(ingress -> from-lport/inport, egress -> to-lport/outport).
For a VM port it is the opposite, same as security groups.
This driver reuses the stock driver and:
  * accepts VM ports, rejects router ports;
  * swaps ingress/egress when rules are written to OVN;
  * writes no default drop ACLs: unmatched traffic is left to security
    groups (a port without port security keeps its traffic);
  * re-renders the whole policy when a rule is removed, so ACL priorities
    always match rule positions;
  * blocks auto-attach of new VM ports to the project's "default" group.
"""

from neutron.common.ovn import utils as ovn_utils
from neutron_lib.api.definitions import portbindings as pb_def
from neutron_lib import constants as const
from neutron_lib.exceptions import firewall_v2 as f_exc
from oslo_log import log as logging

from neutron_fwaas.common import fwaas_constants
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    acl as ovn_acl
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    constants as ovn_const
from neutron_fwaas.services.firewall.service_drivers.ovn import \
    firewall_l3_driver

LOG = logging.getLogger(__name__)

SUPPORTED_VIF_TYPES = (pb_def.VIF_TYPE_OVS, pb_def.VIF_TYPE_VHOST_USER)

_SWAP = {const.INGRESS_DIRECTION: const.EGRESS_DIRECTION,
         const.EGRESS_DIRECTION: const.INGRESS_DIRECTION}


class DefaultGroupAutoAttachDisabled(f_exc.FirewallGroupPortInUse):
    # Subclass so the plugin's auto-association handler still catches it.
    message = ("Ports %(port_ids)s are not added to the default firewall "
               "group: auto-association is disabled for VM ports "
               "(fwaas_ovn_l2).")


def _patch_acl_directions():
    original = ovn_acl.process_rule_for_pg
    if getattr(original, '_vm_port_directions', False):
        return

    def process_rule_for_pg(nb_idl, txn, pg_name, rule, direction,
                            op=ovn_const.OP_ADD):
        return original(nb_idl, txn, pg_name, rule, _SWAP[direction], op=op)

    process_rule_for_pg._vm_port_directions = True
    ovn_acl.process_rule_for_pg = process_rule_for_pg


class OVNVMPortFwaasDriver(firewall_l3_driver.OVNFwaasDriver):
    """OVN FWaaS v2 driver for VM ports."""

    def __init__(self, service_plugin):
        super().__init__(service_plugin)
        _patch_acl_directions()

    def is_supported_l2_port(self, port):
        return port.get(pb_def.VIF_TYPE) in SUPPORTED_VIF_TYPES

    def is_supported_l3_port(self, port):
        return False

    def _init_firewall_group(self, txn, fwg_id):
        # Port group only, no default drop ACLs.
        ovn_acl.create_pg_for_fwg(self._nb_ovn, fwg_id)

    def _clear_rules_for_firewall_group(self, context, txn, fwg_id):
        # Remove every ACL of the group (including default drops left by
        # an older version of this driver).
        pg_name = ovn_utils.ovn_port_group_name(fwg_id)
        txn.add(self._nb_ovn.db_set('Port_Group', pg_name, ('acls', [])))

    def remove_rule_postcommit(self, context, policy_id, rule_info):
        # Stock code deletes only the removed rule's ACL; the remaining
        # rules shift position in the DB but keep their old priorities.
        # Re-render the whole policy instead.
        self._process_acls_by_policies_or_rule(context, [policy_id])

    def update_firewall_group_precommit(self, context, old_firewall_group,
                                        new_firewall_group):
        if new_firewall_group.get('name') == fwaas_constants.DEFAULT_FWG:
            added = (set(new_firewall_group.get('ports') or []) -
                     set(old_firewall_group.get('ports') or []))
            if added:
                LOG.info("Not attaching ports %s to the default firewall "
                         "group %s: disabled for VM ports",
                         sorted(added), new_firewall_group.get('id'))
                raise DefaultGroupAutoAttachDisabled(port_ids=sorted(added))
        super().update_firewall_group_precommit(
            context, old_firewall_group, new_firewall_group)
