use wire::macaroon::{Caveat, Macaroon, VerifyContext};

fn context() -> VerifyContext {
    VerifyContext {
        sender: "did:wire:paul-aaaaaaaa".to_string(),
        recipient: "did:wire:willard-bbbbbbbb".to_string(),
        kind: 1000,
        now: "2026-05-15T20:00:00Z".to_string(),
        rate_count: Some(0),
    }
}

#[test]
fn mint_and_verify_happy_path() {
    let root_key = b"test root key";
    let macaroon = Macaroon::mint(
        "root-1",
        "delegate-1",
        vec![
            Caveat::Sender("did:wire:paul-aaaaaaaa".to_string()),
            Caveat::Recipient("did:wire:willard-bbbbbbbb".to_string()),
            Caveat::Kind(1000),
            Caveat::Expiry("2026-05-15T21:00:00Z".to_string()),
        ],
        root_key,
    )
    .unwrap();

    macaroon.verify(root_key, &context()).unwrap();
    let encoded = macaroon.serialize().unwrap();
    let decoded = Macaroon::deserialize(&encoded).unwrap();
    decoded.verify(root_key, &context()).unwrap();
}

#[test]
fn expiry_caveat_rejects_after_ttl() {
    let root_key = b"test root key";
    let macaroon = Macaroon::mint(
        "root-1",
        "delegate-1",
        vec![Caveat::Expiry("2026-05-15T19:00:00Z".to_string())],
        root_key,
    )
    .unwrap();

    assert!(macaroon.verify(root_key, &context()).is_err());
}

#[test]
fn sender_caveat_rejects_mismatch() {
    let root_key = b"test root key";
    let macaroon = Macaroon::mint(
        "root-1",
        "delegate-1",
        vec![Caveat::Sender("did:wire:alice-cccccccc".to_string())],
        root_key,
    )
    .unwrap();

    assert!(macaroon.verify(root_key, &context()).is_err());
}

#[test]
fn tampering_rejects() {
    let root_key = b"test root key";
    let mut macaroon =
        Macaroon::mint("root-1", "delegate-1", vec![Caveat::Kind(1000)], root_key).unwrap();
    macaroon.caveats.push(Caveat::Kind(1001));

    assert!(macaroon.verify(root_key, &context()).is_err());
}
