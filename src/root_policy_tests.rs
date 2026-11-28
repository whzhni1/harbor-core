//! Unit tests for the explicit root-policy configuration contract.

#[cfg(test)]
mod tests {
    use crate::state::{RootPolicy, RootPolicyConfig};

    #[test]
    fn explicit_policy_preserves_both_lists_and_selects_only_one() {
        let config = RootPolicyConfig::from_uci(
            Some("allowlist"),
            vec!["/mnt/data".into()],
            vec!["/etc".into()],
        )
        .unwrap();
        assert_eq!(config.policy, RootPolicy::Allowlist);
        assert_eq!(config.roots, vec!["/mnt/data".to_string()]);
        assert_eq!(config.excluded_roots, vec!["/etc".to_string()]);

        let unrestricted = RootPolicyConfig::from_uci(
            Some("unrestricted"),
            config.roots.clone(),
            config.excluded_roots.clone(),
        )
        .unwrap();
        assert_eq!(unrestricted.policy, RootPolicy::Unrestricted);
        assert_eq!(unrestricted.roots, vec!["/mnt/data".to_string()]);
        assert_eq!(unrestricted.excluded_roots, vec!["/etc".to_string()]);
    }

    #[test]
    fn missing_policy_is_allowed_only_without_root_lists() {
        assert_eq!(
            RootPolicyConfig::from_uci(None, vec![], vec![])
                .unwrap()
                .policy,
            RootPolicy::Unrestricted
        );
        assert!(RootPolicyConfig::from_uci(None, vec!["/mnt".into()], vec![]).is_err());
        assert!(RootPolicyConfig::from_uci(None, vec![], vec!["/etc".into()]).is_err());
        assert!(
            RootPolicyConfig::from_uci(None, vec!["/mnt".into()], vec!["/etc".into()]).is_err()
        );
    }

    #[test]
    fn active_empty_list_and_invalid_modes_are_rejected() {
        assert!(RootPolicyConfig::from_uci(Some("allowlist"), vec![], vec![]).is_err());
        assert!(RootPolicyConfig::from_uci(Some("denylist"), vec![], vec![]).is_err());
        assert!(RootPolicyConfig::from_uci(Some("typo"), vec![], vec![]).is_err());
        assert!(RootPolicyConfig::from_uci(Some("unrestricted"), vec![], vec![]).is_ok());
    }
}
