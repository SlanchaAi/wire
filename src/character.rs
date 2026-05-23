//! Character — deterministic nickname, emoji, and color palette per identity.
//!
//! Each wire identity has a Character derived deterministically from its DID
//! (or any other stable seed). Same DID → same Character forever. Used for:
//!
//! - Terminal statusline display (`wire whoami --colored`)
//! - Visual disambiguation between multiple Claude sessions on the same host
//! - Future agent-card publication (federation lifecycle)
//!
//! Character is *display layer* only. It does not affect protocol semantics,
//! signing, or peer routing — those continue to use the DID. Character is the
//! human-friendly handle the operator sees.
//!
//! See `.planning/research/identity-primitive-survey-2026-05-22.md` for the
//! ecosystem survey that motivated the field naming (`persona` not `soul`,
//! per Letta convention) and lifecycle gating.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A character for an identity: human-readable nickname, emoji, and palette.
///
/// Constructed deterministically from a seed (typically the DID). The same
/// seed always produces the same Character — operators can rely on
/// "🦊 foxtrot-meadow" persisting across daemon restarts, machine migration,
/// and process boundaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Character {
    /// Adjective-noun pair, lowercase, hyphen-joined. e.g. `"foxtrot-meadow"`.
    pub nickname: String,
    /// Single-codepoint (or VS-16-qualified) emoji glyph. e.g. `"🦊"`.
    pub emoji: String,
    /// Two-color palette for terminal/UI display.
    pub palette: Palette,
}

/// Two-color palette derived from the same seed as the nickname/emoji.
///
/// Primary is bounded to be terminal-readable on both light and dark
/// backgrounds (L ∈ [0.50, 0.65]). Accent shifts hue +30° and lifts L to
/// [0.65, 0.80] for highlights. Saturation is bounded [0.55, 0.80] to avoid
/// muddy / neon extremes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Palette {
    /// Primary color as `#rrggbb`. Use for the nickname/emoji glyph itself.
    pub primary_hex: String,
    /// Accent color as `#rrggbb`. Use for highlights, borders, accents.
    pub accent_hex: String,
    /// Primary mapped onto the ANSI 256-color cube (16..=231).
    pub ansi256_primary: u8,
    /// Accent mapped onto the ANSI 256-color cube (16..=231).
    pub ansi256_accent: u8,
}

impl Character {
    /// Derive a Character from a wire DID (e.g. `did:wire:paul-a1b2c3d4`).
    ///
    /// SHA-256 of the DID drives both nickname/emoji selection and HSL hue.
    /// The function is total and deterministic — every input string yields
    /// some valid Character.
    pub fn from_did(did: &str) -> Self {
        Self::from_seed(did.as_bytes())
    }

    /// Derive a Character from a DID, optionally overriding the nickname
    /// and/or emoji with operator-chosen values.
    ///
    /// v0.7.0-alpha.3: agents can name themselves. The palette stays
    /// deterministic (derived from DID hash) so the visual color identity
    /// remains stable even when the operator picks a custom name; only
    /// the textual + emoji fields override. Empty-string override is
    /// treated as "unset" (falls back to auto-derived).
    pub fn from_did_with_override(
        did: &str,
        nickname_override: Option<&str>,
        emoji_override: Option<&str>,
    ) -> Self {
        let auto = Self::from_did(did);
        Self {
            nickname: nickname_override
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or(auto.nickname),
            emoji: emoji_override
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or(auto.emoji),
            palette: auto.palette,
        }
    }

    /// Derive a Character from an arbitrary byte seed.
    ///
    /// Exposed for testing and for callers that already have a high-entropy
    /// seed (e.g. an Ed25519 public key). Production code generally calls
    /// `from_did` instead.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(seed);
        let digest = h.finalize();
        // 32 bytes of entropy. Use distinct slices for each derived field so
        // adjustments to one decision do not perturb the others.
        let adj_idx = u32::from_be_bytes(digest[0..4].try_into().unwrap()) as usize % ADJECTIVES.len();
        let noun_idx =
            u32::from_be_bytes(digest[4..8].try_into().unwrap()) as usize % NOUNS.len();
        let emoji_idx =
            u32::from_be_bytes(digest[8..12].try_into().unwrap()) as usize % EMOJIS.len();
        // Hue in [0, 360). Saturation + lightness drawn from bounded ranges.
        let hue_raw = u32::from_be_bytes(digest[12..16].try_into().unwrap());
        let hue_deg = (hue_raw % 3600) as f32 / 10.0; // 0.0..360.0
        let sat = 0.55 + (digest[16] as f32 / 255.0) * 0.25; // 0.55..0.80
        let light = 0.50 + (digest[17] as f32 / 255.0) * 0.15; // 0.50..0.65
        let accent_hue_deg = (hue_deg + 30.0) % 360.0;
        let accent_light = 0.65 + (digest[18] as f32 / 255.0) * 0.15; // 0.65..0.80

        let (pr, pg, pb) = hsl_to_rgb(hue_deg, sat, light);
        let (ar, ag, ab) = hsl_to_rgb(accent_hue_deg, sat, accent_light);

        Self {
            nickname: format!("{}-{}", ADJECTIVES[adj_idx], NOUNS[noun_idx]),
            emoji: EMOJIS[emoji_idx].to_string(),
            palette: Palette {
                primary_hex: format!("#{:02x}{:02x}{:02x}", pr, pg, pb),
                accent_hex: format!("#{:02x}{:02x}{:02x}", ar, ag, ab),
                ansi256_primary: rgb_to_ansi256(pr, pg, pb),
                ansi256_accent: rgb_to_ansi256(ar, ag, ab),
            },
        }
    }

    /// `"🦊 foxtrot-meadow"` — plain, no ANSI escapes. Safe in any output.
    pub fn short(&self) -> String {
        format!("{} {}", self.emoji, self.nickname)
    }

    /// `short()` wrapped in ANSI 256-color foreground escapes for the primary
    /// color. Renders correctly in any terminal supporting 256 colors (the
    /// universal lower bound — every modern emulator). For terminals without
    /// color support, escapes will be visible-but-harmless.
    pub fn colored(&self) -> String {
        format!(
            "\x1b[38;5;{}m{} {}\x1b[0m",
            self.palette.ansi256_primary, self.emoji, self.nickname
        )
    }
}

/// HSL → RGB. h ∈ [0, 360), s ∈ [0, 1], l ∈ [0, 1]. Returns u8 triplet.
/// Standard formula; no clamping needed when s/l are already in-range.
fn hsl_to_rgb(h: f32, s: f32, l: f32) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let h_prime = h / 60.0;
    let x = c * (1.0 - ((h_prime % 2.0) - 1.0).abs());
    let (r1, g1, b1) = match h_prime as i32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    let r = ((r1 + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    let g = ((g1 + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    let b = ((b1 + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    (r, g, b)
}

/// Nearest color in the ANSI 256 6×6×6 cube. Returns an index in 16..=231.
fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    let q = |c: u8| -> u8 { ((c as u16 * 5 + 127) / 255) as u8 }; // round to 0..=5
    16 + 36 * q(r) + 6 * q(g) + q(b)
}

/// 120 short, neutral adjectives. Nature, abstract, gentle tone.
const ADJECTIVES: &[&str] = &[
    "amber", "azure", "balmy", "blithe", "brisk", "calm", "cedar", "chill", "cinder", "clear",
    "coral", "cosmic", "crisp", "dawn", "deep", "dusky", "dewy", "drift", "ember", "emerald",
    "feral", "ferny", "festive", "fjord", "foxtrot", "frosty", "gentle", "ginger", "glassy",
    "glint", "gold", "grove", "harbor", "hazel", "heath", "hush", "ivory", "jade", "kelp",
    "kindly", "lavender", "linen", "lonely", "loud", "lucid", "lunar", "marble", "marsh",
    "meadow", "mellow", "mild", "minted", "misty", "moonlit", "morning", "mossy", "muted",
    "neon", "nimble", "noble", "north", "olive", "onyx", "opal", "outback", "pearl", "pewter",
    "pine", "placid", "plum", "prairie", "quiet", "raven", "redwood", "river", "rosy", "ruby",
    "rustic", "sage", "salt", "sandy", "scarlet", "sea", "shadow", "shore", "silken", "silver",
    "slate", "smoky", "soft", "solar", "spruce", "starry", "steady", "stone", "summer",
    "sunlit", "swift", "tawny", "teal", "thistle", "topaz", "twilight", "umber", "valley",
    "velvet", "verdant", "vesper", "violet", "vivid", "warm", "willow", "windy", "winter",
    "wisp", "woven", "wren", "yarrow", "yonder", "zen", "zephyr",
];

/// 120 short, evocative nouns. Geographic features, weather, materials, fauna.
const NOUNS: &[&str] = &[
    "ash", "atlas", "bay", "beacon", "birch", "blossom", "bough", "branch", "brook", "canyon",
    "cedar", "cinder", "cirrus", "cliff", "comet", "compass", "coral", "cove", "creek", "crest",
    "crow", "cypress", "delta", "dew", "dune", "ember", "fern", "field", "finch", "fjord",
    "flame", "flax", "fleck", "fog", "foam", "forest", "fox", "frost", "garnet", "geyser",
    "glade", "glen", "glimmer", "grove", "harbor", "haze", "heath", "hollow", "hush", "ivy",
    "jasper", "juniper", "kelp", "kettle", "knoll", "lake", "lark", "laurel", "leaf", "ledge",
    "lichen", "linden", "loft", "lotus", "lupin", "maple", "marsh", "meadow", "mesa", "mist",
    "moor", "moss", "moth", "mountain", "nettle", "oak", "ocean", "opal", "orchard", "owl",
    "palm", "petal", "pine", "plain", "pond", "poppy", "quartz", "quill", "raven", "reef",
    "ridge", "river", "rook", "sage", "sand", "savanna", "shale", "sheaf", "shore", "shrub",
    "sky", "slate", "spruce", "starling", "stone", "summit", "swallow", "thicket", "thrush",
    "tide", "topaz", "trout", "valley", "vesper", "vine", "wave", "willow", "wisp", "wren",
];

/// 64 curated emojis. All single Unicode codepoint (or VS-16 qualified) —
/// no flags, no skin tone, no ZWJ family/profession sequences. Render
/// consistently across iTerm, Terminal.app, Alacritty, kitty, GNOME Terminal,
/// Konsole, and tmux. Themed: animals, nature, abstract.
const EMOJIS: &[&str] = &[
    "🦊", "🐺", "🦅", "🦉", "🐝", "🐻", "🦌", "🐢", "🐙", "🐬", "🦋", "🐸", "🦔", "🦣", "🦏",
    "🐅", "🐆", "🐊", "🦓", "🦒", "🦘", "🐈", "🐇", "🦦", "🦥", "🦡", "🦢", "🦩", "🐉", "🦕",
    "🦎", "🐍", "🦂", "🦀", "🦞", "🐳", "🐡", "🦈", "🦭", "🐧", "🦃", "🦚", "🦜", "🦤", "🦆",
    "🌲", "🌳", "🌴", "🌵", "🌷", "🌸", "🌺", "🌻", "🍄", "🌿", "🌱", "🍃", "🌊", "🌋", "🌙",
    "🌟", "🌈", "🔥", "💎",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn deterministic_same_did() {
        let a = Character::from_did("did:wire:paul-a1b2c3d4");
        let b = Character::from_did("did:wire:paul-a1b2c3d4");
        assert_eq!(a, b);
    }

    #[test]
    fn different_dids_differ() {
        let a = Character::from_did("did:wire:paul-a1b2c3d4");
        let b = Character::from_did("did:wire:paul-e5f6a7b8");
        assert_ne!(a, b);
    }

    #[test]
    fn nickname_is_hyphenated_pair() {
        let c = Character::from_did("did:wire:test-deadbeef");
        let parts: Vec<&str> = c.nickname.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].chars().all(|ch| ch.is_ascii_lowercase()));
        assert!(parts[1].chars().all(|ch| ch.is_ascii_lowercase()));
    }

    #[test]
    fn emoji_is_in_curated_set() {
        let c = Character::from_did("did:wire:test-cafebabe");
        assert!(EMOJIS.contains(&c.emoji.as_str()));
    }

    #[test]
    fn palette_hex_is_well_formed() {
        let c = Character::from_did("did:wire:test-12345678");
        assert!(c.palette.primary_hex.starts_with('#'));
        assert_eq!(c.palette.primary_hex.len(), 7);
        assert!(c.palette.accent_hex.starts_with('#'));
        assert_eq!(c.palette.accent_hex.len(), 7);
    }

    #[test]
    fn ansi256_in_cube_range() {
        let c = Character::from_did("did:wire:test-87654321");
        assert!((16..=231).contains(&c.palette.ansi256_primary));
        assert!((16..=231).contains(&c.palette.ansi256_accent));
    }

    #[test]
    fn short_format() {
        let c = Character::from_did("did:wire:fixed-seed-here");
        let short = c.short();
        assert!(short.contains(&c.emoji));
        assert!(short.contains(&c.nickname));
        assert_eq!(short, format!("{} {}", c.emoji, c.nickname));
    }

    #[test]
    fn colored_includes_ansi_escape() {
        let c = Character::from_did("did:wire:colored-test");
        let colored = c.colored();
        assert!(colored.starts_with("\x1b[38;5;"));
        assert!(colored.ends_with("\x1b[0m"));
        assert!(colored.contains(&c.nickname));
    }

    #[test]
    fn no_nickname_collisions_10k_samples() {
        // 14400 possible nickname combinations; in 10k random DIDs we'll
        // see *some* collisions by birthday paradox (~3500 expected). Check
        // that *characters* (full triple) are unique enough — collisions in
        // (nickname, emoji, primary_hex) below 1% across 10k samples.
        let mut chars: HashSet<(String, String, String)> = HashSet::new();
        let mut collisions = 0;
        for i in 0..10_000 {
            let did = format!("did:wire:test-{:08x}", i);
            let c = Character::from_did(&did);
            let key = (c.nickname.clone(), c.emoji.clone(), c.palette.primary_hex.clone());
            if !chars.insert(key) {
                collisions += 1;
            }
        }
        assert!(
            collisions < 100,
            "saw {collisions} character-triple collisions in 10k samples (>1%)"
        );
    }

    #[test]
    fn word_lists_have_expected_size() {
        assert!(ADJECTIVES.len() >= 100, "adjective list too small");
        assert!(NOUNS.len() >= 100, "noun list too small");
        assert!(EMOJIS.len() >= 50, "emoji list too small");
    }

    #[test]
    fn no_duplicate_words() {
        let adj_set: HashSet<&&str> = ADJECTIVES.iter().collect();
        assert_eq!(adj_set.len(), ADJECTIVES.len(), "duplicate adjective");
        let noun_set: HashSet<&&str> = NOUNS.iter().collect();
        assert_eq!(noun_set.len(), NOUNS.len(), "duplicate noun");
        let emoji_set: HashSet<&&str> = EMOJIS.iter().collect();
        assert_eq!(emoji_set.len(), EMOJIS.len(), "duplicate emoji");
    }

    #[test]
    fn hsl_to_rgb_known_values() {
        // Red: H=0, S=1, L=0.5 → (255, 0, 0)
        let (r, g, b) = hsl_to_rgb(0.0, 1.0, 0.5);
        assert_eq!(r, 255);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
        // Green: H=120, S=1, L=0.5 → (0, 255, 0)
        let (r, g, b) = hsl_to_rgb(120.0, 1.0, 0.5);
        assert_eq!(r, 0);
        assert_eq!(g, 255);
        assert_eq!(b, 0);
        // Blue: H=240, S=1, L=0.5 → (0, 0, 255)
        let (r, g, b) = hsl_to_rgb(240.0, 1.0, 0.5);
        assert_eq!(r, 0);
        assert_eq!(g, 0);
        assert_eq!(b, 255);
    }

    #[test]
    fn rgb_to_ansi256_matches_cube() {
        // Pure black corner of cube → 16. Pure white → 231.
        assert_eq!(rgb_to_ansi256(0, 0, 0), 16);
        assert_eq!(rgb_to_ansi256(255, 255, 255), 231);
        // Red corner (255, 0, 0) → 16 + 5*36 = 196.
        assert_eq!(rgb_to_ansi256(255, 0, 0), 196);
        // Green corner (0, 255, 0) → 16 + 5*6 = 46.
        assert_eq!(rgb_to_ansi256(0, 255, 0), 46);
    }
}
