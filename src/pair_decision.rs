//! RFC-001 Phase 1b — map a verified org-membership outcome + the receiver's
//! per-org policy to a pairing action.
//!
//! This is the bridge between [`crate::org_membership::evaluate_card_membership`]
//! (Phase 1, the offline verify chain) and the live accept/pin path. It is a
//! pure function over an [`OrgPolicy`] lookup that Phase 3 (slate-lotus's
//! `org_policies.json` table) implements. Keeping it pure means the Option-A /
//! Option-B / default-deny decision is unit-testable without any live state.
//!
//! Invariant (RFC-001 §5): the strongest action this can return is
//! `ORG_VERIFIED` (auto or via one-tap). `VERIFIED` still requires bilateral
//! SPAKE2+SAS and is never produced here. Anything that isn't a verified
//! membership in a *trusted* org falls through to `Manual` (today's default-deny
//! bilateral flow), preserving the v0.5.14 phonebook-scrape closure.

use crate::org_membership::MembershipOutcome;

/// Receiver-side inbound treatment for a peer that is a verified member of a
/// trusted org. Phase 3's policy table maps an `org_did` to one of these (or to
/// `None` = not in the receiver's trusted set → default-deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundMode {
    /// Option A (opt-in): pin `ORG_VERIFIED` with no operator tap.
    Auto,
    /// Option B (default): enqueue one pending-inbound; one operator tap → `ORG_VERIFIED`.
    Notify,
}

/// The receiver's per-org pairing policy. Phase 3 (slate-lotus) implements this
/// over `config/wire/org_policies.json` (first-match-wins, immutable
/// default-deny). `None` means the org is not in the receiver's trusted set.
pub trait OrgPolicy {
    fn inbound_mode(&self, org_did: &str) -> Option<InboundMode>;
}

/// The action P1b takes for a received card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairAction {
    /// Pin `ORG_VERIFIED` with no tap — the matched org opted into Option A.
    AutoOrgVerified { org_did: String },
    /// Enqueue one pending-inbound annotated org-vouched (Option B default);
    /// one operator tap promotes to `ORG_VERIFIED`.
    NotifyOrgEligible { org_did: String },
    /// No verified vouch from a trusted org — fall through to today's bilateral
    /// manual pending flow (default-deny).
    Manual,
}

/// Map a membership outcome + the receiver's policy to a pairing action.
///
/// Fail-closed: `NoClaim` / `Rejected` → `Manual`. Among the verified
/// `org_did`s, the strongest opted-in treatment wins (`Auto` > `Notify`); orgs
/// the receiver does not trust (`inbound_mode` → `None`) are ignored. The
/// result never exceeds `ORG_VERIFIED`.
pub fn decide(outcome: &MembershipOutcome, policy: &dyn OrgPolicy) -> PairAction {
    let org_dids = match outcome {
        MembershipOutcome::Verified { org_dids, .. } => org_dids,
        // No claim, or a claim that failed verification → no easing.
        MembershipOutcome::NoClaim | MembershipOutcome::Rejected { .. } => {
            return PairAction::Manual;
        }
    };

    // Auto wins if any verified org opted into it; otherwise the first Notify
    // org; otherwise no trusted vouch → manual. (inbound_mode is a cheap lookup.)
    if let Some(org_did) = org_dids
        .iter()
        .find(|&od| policy.inbound_mode(od) == Some(InboundMode::Auto))
    {
        return PairAction::AutoOrgVerified {
            org_did: org_did.clone(),
        };
    }
    if let Some(org_did) = org_dids
        .iter()
        .find(|&od| policy.inbound_mode(od) == Some(InboundMode::Notify))
    {
        return PairAction::NotifyOrgEligible {
            org_did: org_did.clone(),
        };
    }
    PairAction::Manual
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapPolicy(HashMap<String, InboundMode>);
    impl OrgPolicy for MapPolicy {
        fn inbound_mode(&self, org_did: &str) -> Option<InboundMode> {
            self.0.get(org_did).copied()
        }
    }

    fn verified(orgs: &[&str]) -> MembershipOutcome {
        MembershipOutcome::Verified {
            op_did:
                "did:wire:op:darby-0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            org_dids: orgs.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn policy(entries: &[(&str, InboundMode)]) -> MapPolicy {
        MapPolicy(entries.iter().map(|(k, v)| (k.to_string(), *v)).collect())
    }

    #[test]
    fn auto_when_org_opted_into_auto() {
        let out = verified(&["did:wire:org:slanchaai-1"]);
        let pol = policy(&[("did:wire:org:slanchaai-1", InboundMode::Auto)]);
        assert_eq!(
            decide(&out, &pol),
            PairAction::AutoOrgVerified {
                org_did: "did:wire:org:slanchaai-1".into()
            }
        );
    }

    #[test]
    fn notify_when_org_is_notify() {
        let out = verified(&["did:wire:org:slanchaai-1"]);
        let pol = policy(&[("did:wire:org:slanchaai-1", InboundMode::Notify)]);
        assert_eq!(
            decide(&out, &pol),
            PairAction::NotifyOrgEligible {
                org_did: "did:wire:org:slanchaai-1".into()
            }
        );
    }

    #[test]
    fn manual_when_org_untrusted() {
        let out = verified(&["did:wire:org:stranger-1"]);
        let pol = policy(&[("did:wire:org:slanchaai-1", InboundMode::Auto)]);
        assert_eq!(decide(&out, &pol), PairAction::Manual);
    }

    #[test]
    fn auto_beats_notify_across_orgs() {
        // Verified in two orgs; one Notify (listed first), one Auto. Auto wins.
        let out = verified(&["did:wire:org:notifyco-1", "did:wire:org:autoco-1"]);
        let pol = policy(&[
            ("did:wire:org:notifyco-1", InboundMode::Notify),
            ("did:wire:org:autoco-1", InboundMode::Auto),
        ]);
        assert_eq!(
            decide(&out, &pol),
            PairAction::AutoOrgVerified {
                org_did: "did:wire:org:autoco-1".into()
            }
        );
    }

    #[test]
    fn manual_on_no_claim() {
        let pol = policy(&[("did:wire:org:slanchaai-1", InboundMode::Auto)]);
        assert_eq!(
            decide(&MembershipOutcome::NoClaim, &pol),
            PairAction::Manual
        );
    }

    #[test]
    fn manual_on_rejected() {
        let pol = policy(&[("did:wire:org:slanchaai-1", InboundMode::Auto)]);
        let rejected = MembershipOutcome::Rejected {
            reason: "forged".into(),
        };
        assert_eq!(decide(&rejected, &pol), PairAction::Manual);
    }
}
