use wire::character::Character;
fn main() {
    let seeds = [
        "did:wire:paul-a1b2c3d4",
        "did:wire:slancha-spark-e5f6a7b8",
        "did:wire:foxtrot-planner-12345678",
        "did:wire:raven-reviewer-87654321",
        "did:wire:test-cafebabe",
        "did:wire:test-deadbeef",
        "did:wire:test-feedface",
        "did:wire:claude-session-01",
        "did:wire:claude-session-02",
        "did:wire:willard-spark-99999999",
    ];
    println!("Sample characters (colored output requires 256-color terminal):");
    println!();
    for seed in seeds {
        let c = Character::from_did(seed);
        println!(
            "  {}   {:<20} primary={} accent={} ansi=({},{})",
            c.colored(),
            c.nickname,
            c.palette.primary_hex,
            c.palette.accent_hex,
            c.palette.ansi256_primary,
            c.palette.ansi256_accent,
        );
    }
}
