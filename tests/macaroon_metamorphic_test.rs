//! Metamorphic security tests for macaroon attenuation behavior.

use asupersync::cx::macaroon::{CaveatPredicate, MacaroonToken, VerificationContext};
use asupersync::security::key::AuthKey;

fn root_key() -> AuthKey {
    AuthKey::from_seed(42)
}

#[test]
fn test_attenuation_metamorphic_property() {
    let key = root_key();
    let token = MacaroonToken::mint(&key, "cap", "loc");

    // Property: Any attenuated token must be at most as permissive as the original.
    // i.e., if verify(attenuated) == OK, then verify(original) == OK.

    let attenuated = token
        .clone()
        .add_caveat(CaveatPredicate::TimeBefore(1000))
        .add_caveat(CaveatPredicate::MaxUses(5));

    // Test with various contexts
    let contexts = vec![
        VerificationContext::new().with_time(500).with_use_count(3),
        VerificationContext::new().with_time(1500).with_use_count(3),
        VerificationContext::new().with_time(500).with_use_count(10),
    ];

    for ctx in contexts {
        let result_orig = token.verify(&key, &ctx);
        let result_atten = attenuated.verify(&key, &ctx);

        if result_atten.is_ok() {
            assert!(
                result_orig.is_ok(),
                "Attenuated token passed but original failed!"
            );
        }
    }
}

#[test]
fn test_conjunction_metamorphic_property() {
    let key = root_key();
    let token = MacaroonToken::mint(&key, "cap", "loc");

    let c1 = CaveatPredicate::RegionScope(1);
    let c2 = CaveatPredicate::TaskScope(2);

    let t1 = token.clone().add_caveat(c1.clone());
    let t2 = token.clone().add_caveat(c2.clone());
    let t12 = token.clone().add_caveat(c1).add_caveat(c2);

    let contexts = vec![
        VerificationContext::new().with_region(1).with_task(2),
        VerificationContext::new().with_region(1).with_task(3),
        VerificationContext::new().with_region(4).with_task(2),
    ];

    for ctx in contexts {
        let r1 = t1.verify(&key, &ctx);
        let r2 = t2.verify(&key, &ctx);
        let r12 = t12.verify(&key, &ctx);

        if r12.is_ok() {
            assert!(
                r1.is_ok() && r2.is_ok(),
                "Conjunction passed but individual caveats failed!"
            );
        } else {
            // If conjunction failed, at least one individual must fail OR it's a signature mismatch (not possible here)
            assert!(
                r1.is_err() || r2.is_err(),
                "Conjunction failed but both individual caveats passed!"
            );
        }
    }
}
