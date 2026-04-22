//! `ADD_SUBNET` / `DEL_SUBNET` — flooded subnet ownership gossip.

use super::MAX_NODES;
use crate::daemon::{ConnId, Daemon};

use crate::dispatch::{DispatchError, parse_add_subnet, parse_del_subnet};

use tinc_proto::{Request, Subnet};

impl Daemon {
    /// Subnets don't change topology - NO `graph()` call.
    pub(in crate::daemon) fn on_add_subnet(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_add_subnet(body)?;

        // tunnelserver indirect filter. Check BEFORE
        // lookup_or_add_node - don't pollute graph with indirect
        // names. ORDER: seen_request first - mark seen even on drop.
        let Some(conn_name) = self.flooded_prologue(
            from_conn,
            body,
            "ADD_SUBNET",
            &[&owner_name],
            format_args!("for {owner_name} ({subnet})"),
        ) else {
            return Ok(false);
        };

        // Lookup-first idempotency. With strictsubnets this lets
        // AUTHORIZED subnets through silently (load_all_nodes
        // preloaded; gossip finds it, return). UNAUTHORIZED falls
        // through. Without strictsubnets: belt-and-braces over
        // seen_request (saves lookup_or_add + script run).
        if self.subnets.contains(&subnet, &owner_name) {
            return Ok(false);
        }

        if self.node_ids.len() >= MAX_NODES && !self.node_ids.contains_key(&owner_name) {
            log::warn!(target: "tincd::proto",
                       "Dropping ADD_SUBNET for new node {owner_name}: \
                        node table full ({MAX_NODES})");
            return Ok(false);
        }
        let owner = self.lookup_or_add_node(&owner_name);

        // Peer wrong about us - retaliate DEL_SUBNET.
        if owner == self.myself {
            log::warn!(target: "tincd::proto",
                       "Got ADD_SUBNET from {conn_name} for ourself ({subnet})");
            // Dark in single-peer tests; reachable via stale gossip
            // in multi-peer mesh.
            // borrow-split: send_subnet takes &mut self; can't pass &self.name
            let nw = self.send_subnet(from_conn, Request::DelSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // tunnelserver second gate. Reached when owner IS the direct
        // peer but subnet wasn't preloaded from hosts/ ("unauthorized"
        // - tunnelserver implies strictsubnets; load_all_nodes
        // preloaded those; reaching here means NOT on disk). NO
        // forward. (50800c0d fixed a spurious forward here that made
        // three_daemon_tunnelserver intermittent.)
        if self.settings.tunnelserver {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (tunnelserver)");
            return Ok(false);
        }

        // strictsubnets - hosts/ file is authority. Forward (others
        // may not be strict) but don't add locally.
        if self.settings.strictsubnets {
            log::warn!(target: "tincd::proto",
                       "Ignoring unauthorized ADD_SUBNET for {owner_name} \
                        ({subnet}) (strictsubnets)");
            let nw = self.forward_request(from_conn, body);
            return Ok(nw);
        }

        // Reject peer claims on MACs we still actively lease.
        if let Subnet::Mac { addr, .. } = subnet
            && owner != self.myself
            && self.mac_leases.contains(addr)
        {
            log::warn!(target: "tincd::proto",
                "Rejecting ADD_SUBNET from {owner_name} for MAC \
                 {addr:02x?}: we hold the lease");
            return Ok(false);
        }

        self.subnets.add(subnet, owner_name.clone());
        self.tx_snap_refresh_subnets();

        // mac_table sync for route_mac.rs.
        if let Subnet::Mac { addr, .. } = subnet {
            self.mac_table.insert(addr, owner_name.clone());
        }

        // subnet-up only if reachable (else BecameReachable fires it
        // later).
        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(true, &owner_name, &subnet);
        }

        // seen.check above prevents the loop. tunnelserver already
        // returned at the unauthorized-subnet gate above, so this
        // path always forwards.
        let nw = self.forward_request(from_conn, body);

        Ok(nw)
    }

    /// DEL for unknown owner/subnet is warn-and-drop (NOT
    /// `lookup_or_add`).
    pub(in crate::daemon) fn on_del_subnet(
        &mut self,
        from_conn: ConnId,
        body: &[u8],
    ) -> Result<bool, DispatchError> {
        let (owner_name, subnet) = parse_del_subnet(body)?;

        let Some(conn_name) = self.flooded_prologue(
            from_conn,
            body,
            "DEL_SUBNET",
            &[&owner_name],
            format_args!("for {owner_name} ({subnet})"),
        ) else {
            return Ok(false);
        };

        // NOT lookup_or_add. Warn, return.
        let Some(&owner) = self.node_ids.get(&owner_name) else {
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which is not in our node tree");
            return Ok(false);
        };

        // Peer says we don't own a subnet we DO own. ORDERING: lookup
        // FIRST, bail if not found. Security audit `2f72c2ba`: without
        // that gate, a malicious peer sends DEL_SUBNET for a subnet
        // we never claimed; we retaliate ADD; victim adds bogus route
        // pointing at us.
        if owner == self.myself {
            // Don't lie about subnets we never owned.
            if !self.subnets.contains(&subnet, &self.name) {
                log::warn!(target: "tincd::proto",
                           "Got DEL_SUBNET from {conn_name} for ourself ({subnet}) \
                            which does not appear in our subnet tree");
                return Ok(false);
            }
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for ourself ({subnet})");
            // borrow-split: send_subnet takes &mut self; can't pass &self.name
            let nw = self.send_subnet(from_conn, Request::AddSubnet, &self.name.clone(), &subnet);
            return Ok(nw);
        }

        // AFTER retaliate, BEFORE forward+del.
        if self.settings.tunnelserver {
            return Ok(false);
        }

        let nw = self.forward_request(from_conn, body);

        // AFTER forward, BEFORE del. (not-found-strictsubnets case
        // folds into del()==false below: same observable behavior -
        // forward, no del.)
        if self.settings.strictsubnets {
            return Ok(nw);
        }

        // ORDERING: lookup gates script + del. Security audit
        // `2f72c2ba`: subnet-down for a subnet we never up'd is a
        // peer-triggers-fork-exec DoS (flood DEL with fresh nonces).
        // Do del() FIRST. We invert script-before-del (del() returns
        // bool) - script env doesn't read the table; same behavior.
        let did_del = self.subnets.del(&subnet, &owner_name);
        if did_del {
            self.tx_snap_refresh_subnets();
        }
        if !did_del {
            // Warn, no script.
            log::warn!(target: "tincd::proto",
                       "Got DEL_SUBNET from {conn_name} for {owner_name} \
                        which does not appear in his subnet tree");
            return Ok(nw);
        }

        let reachable = self.graph.node(owner).is_some_and(|n| n.reachable);
        if reachable {
            self.run_subnet_script(false, &owner_name, &subnet);
        }

        // mac_table sync; only remove if owner matches (defensive).
        if let Subnet::Mac { addr, .. } = subnet
            && self.mac_table.get(&addr).map(String::as_str) == Some(owner_name.as_str())
        {
            self.mac_table.remove(&addr);
        }

        Ok(nw)
    }
}
