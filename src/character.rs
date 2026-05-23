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

    /// Derive a Character from a pinned peer's agent-card JSON object.
    ///
    /// v0.7.0-alpha.6: when a peer has published their operator-chosen
    /// character (display.nickname / display.emoji on their signed
    /// agent-card), we honor it. Otherwise falls back to auto-derived
    /// from their DID — same as `from_did`.
    ///
    /// v0.7.0-alpha.8 (review-fix #1): peer-published override fields
    /// are sanitized (control chars stripped, length-capped) before use
    /// so a malicious peer cannot inject ANSI/OSC escape sequences via
    /// their display.nickname / display.emoji and execute terminal
    /// control codes on every `wire peers` / `wire whoami` render.
    /// Override that fully sanitizes to empty falls back to auto-derived.
    ///
    /// v0.7.0-alpha.8 (review-fix #8): missing or non-string `did`
    /// returns a distinctive "unknown peer" sentinel character rather
    /// than collapsing all such peers onto the empty-string-derived
    /// character. Surfaces partially-corrupt pinned cards to operators
    /// rather than masking them as one fake identity.
    ///
    /// Backward compat: agent-cards without the `display` field land in
    /// the auto-derived path automatically.
    pub fn from_card(card: &serde_json::Value) -> Self {
        let did_opt = card.get("did").and_then(|d| d.as_str());
        let did = match did_opt {
            Some(d) if !d.is_empty() => d,
            _ => return Self::unknown_peer(),
        };
        let display = card.get("display").and_then(|d| d.as_object());
        let nick = display
            .and_then(|d| d.get("nickname"))
            .and_then(|n| n.as_str())
            .map(sanitize_display_text)
            .filter(|s| !s.is_empty());
        let emoji = display
            .and_then(|d| d.get("emoji"))
            .and_then(|e| e.as_str())
            .map(sanitize_display_text)
            .filter(|s| !s.is_empty());
        Self::from_did_with_override(did, nick.as_deref(), emoji.as_deref())
    }

    /// Sentinel for peers whose pinned agent-card lacks a usable DID.
    /// Distinct, visible, non-overlapping with the auto-derived space
    /// (no real DID will hash to the empty string, and the explicit "?"
    /// emoji isn't in the curated EMOJIS list).
    fn unknown_peer() -> Self {
        Self {
            nickname: "unknown-peer".to_string(),
            emoji: "❓".to_string(),
            palette: Palette {
                primary_hex: "#7d7d7d".to_string(),
                accent_hex: "#a8a8a8".to_string(),
                ansi256_primary: 244,
                ansi256_accent: 248,
            },
        }
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
        let adj_idx =
            u32::from_be_bytes(digest[0..4].try_into().unwrap()) as usize % ADJECTIVES.len();
        let noun_idx = u32::from_be_bytes(digest[4..8].try_into().unwrap()) as usize % NOUNS.len();
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

/// v0.7.0-alpha.8 (review-fix #1): sanitize operator-chosen or peer-
/// published display text (nickname or emoji) for safe terminal render.
///
/// Strips Unicode Control category chars (`is_control()` — covers C0
/// + DEL + C1 including ESC U+001B which gates ANSI/OSC/CSI escape
/// sequences), then caps length to `MAX_DISPLAY_CHARS` codepoints so a
/// malicious peer can't ship a 10MB nickname that destroys the
/// statusline layout.
///
/// Used at write time (`wire identity rename` rejects sanitization-
/// reduced inputs as an error) and at read time (`Character::from_card`
/// silently strips for defense-in-depth against pinned cards that
/// pre-date this validation).
pub const MAX_DISPLAY_CHARS: usize = 64;

pub fn sanitize_display_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_DISPLAY_CHARS)
        .collect()
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

/// ~256 short, neutral adjectives. Nature, abstract, texture, mood.
/// v0.7.0-alpha.4: doubled from the alpha.1 set of 120 to widen the
/// combinatorial space and reduce nickname collisions at scale.
const ADJECTIVES: &[&str] = &[
    "agate",
    "alpine",
    "amber",
    "ancient",
    "antique",
    "arctic",
    "ashen",
    "auburn",
    "autumn",
    "azure",
    "balmy",
    "blithe",
    "brave",
    "breezy",
    "briar",
    "bright",
    "brisk",
    "bronze",
    "brushed",
    "bubbling",
    "burnished",
    "calm",
    "candle",
    "cedar",
    "chestnut",
    "chill",
    "chipper",
    "cinder",
    "clay",
    "clear",
    "cliffside",
    "cobalt",
    "copper",
    "coral",
    "cordial",
    "cosmic",
    "crimson",
    "crisp",
    "crystal",
    "curious",
    "dapper",
    "dappled",
    "dawn",
    "daydream",
    "deep",
    "delta",
    "dewy",
    "distant",
    "drift",
    "drowsy",
    "dune",
    "dusky",
    "eager",
    "echoing",
    "ember",
    "emerald",
    "feral",
    "ferny",
    "festive",
    "fjord",
    "flaxen",
    "fluted",
    "fond",
    "forest",
    "foxtrot",
    "fragrant",
    "frosted",
    "frosty",
    "garnet",
    "gentle",
    "ginger",
    "glacial",
    "glassy",
    "gleaming",
    "glint",
    "glossy",
    "gold",
    "graceful",
    "granite",
    "grove",
    "hammered",
    "harbor",
    "hardy",
    "hazel",
    "heath",
    "honey",
    "humble",
    "hush",
    "indigo",
    "ivory",
    "jade",
    "jaunty",
    "juniper",
    "keen",
    "kelp",
    "kindly",
    "knit",
    "lacquered",
    "lapis",
    "lavender",
    "leaden",
    "lichen",
    "lilac",
    "linen",
    "lively",
    "lonely",
    "lucid",
    "lunar",
    "marble",
    "marsh",
    "meadow",
    "mellow",
    "merry",
    "mild",
    "minted",
    "misted",
    "misty",
    "moonlit",
    "morning",
    "mossy",
    "muted",
    "neon",
    "nimble",
    "noble",
    "north",
    "ochre",
    "olive",
    "onyx",
    "opal",
    "orchid",
    "outback",
    "pearl",
    "pearled",
    "peat",
    "petal",
    "pewter",
    "pine",
    "placid",
    "plucky",
    "plum",
    "polar",
    "polished",
    "poppy",
    "prairie",
    "primrose",
    "prussian",
    "purpled",
    "quartz",
    "quiet",
    "quill",
    "raven",
    "reckless",
    "redwood",
    "restless",
    "ribbon",
    "river",
    "rosemary",
    "rosy",
    "ruby",
    "rusted",
    "rustic",
    "russet",
    "saffron",
    "sage",
    "salt",
    "sandy",
    "satin",
    "scarlet",
    "sea",
    "shaded",
    "shadow",
    "shimmer",
    "shining",
    "shore",
    "silken",
    "silver",
    "skylit",
    "slate",
    "slatey",
    "smoky",
    "smolder",
    "snowy",
    "soft",
    "solar",
    "splendid",
    "spruce",
    "starry",
    "steadfast",
    "steady",
    "sterling",
    "stone",
    "sturdy",
    "sublime",
    "summer",
    "sunlit",
    "sunny",
    "supple",
    "sweetbay",
    "swift",
    "tawny",
    "teal",
    "tender",
    "terra",
    "thistle",
    "thrushlike",
    "tidal",
    "tinder",
    "tinkling",
    "topaz",
    "torrid",
    "tranquil",
    "trillium",
    "twilight",
    "umber",
    "valley",
    "velvet",
    "vernal",
    "verdant",
    "vesper",
    "vibrant",
    "violet",
    "vivid",
    "warm",
    "warmer",
    "weathered",
    "westwind",
    "whispered",
    "wildflower",
    "willow",
    "winterly",
    "windy",
    "winter",
    "wisp",
    "withered",
    "witty",
    "woodland",
    "woven",
    "wren",
    "wry",
    "yarrow",
    "yonder",
    "zen",
    "zephyr",
];

/// ~256 short, evocative nouns. Geographic features, weather, materials,
/// flora, fauna, objects, light.
/// v0.7.0-alpha.4: doubled from the alpha.1 set of 120.
const NOUNS: &[&str] = &[
    "anchor",
    "ash",
    "aspen",
    "atlas",
    "aurora",
    "badger",
    "bark",
    "bay",
    "bayou",
    "beacon",
    "beaver",
    "bell",
    "birch",
    "bison",
    "blossom",
    "bough",
    "branch",
    "breeze",
    "briar",
    "brook",
    "bud",
    "bunting",
    "burrow",
    "butte",
    "caldera",
    "camellia",
    "canyon",
    "cardinal",
    "caribou",
    "cedar",
    "chime",
    "chinook",
    "cinder",
    "cirrus",
    "cliff",
    "cloudburst",
    "comet",
    "compass",
    "copper",
    "coral",
    "cove",
    "creek",
    "crest",
    "cricket",
    "crow",
    "cumulus",
    "cyclone",
    "cypress",
    "dale",
    "delta",
    "dew",
    "dewdrop",
    "dolphin",
    "dove",
    "dragonfly",
    "dune",
    "dusk",
    "eagle",
    "ember",
    "fern",
    "field",
    "finch",
    "fjord",
    "flame",
    "flax",
    "fleck",
    "fog",
    "foam",
    "forest",
    "fox",
    "frost",
    "garnet",
    "gander",
    "geode",
    "geyser",
    "glade",
    "gleam",
    "glen",
    "glimmer",
    "gorge",
    "grove",
    "hare",
    "harbor",
    "haze",
    "headland",
    "hearth",
    "heath",
    "heron",
    "hollow",
    "hummingbird",
    "ibis",
    "iris",
    "ivy",
    "jasmine",
    "jasper",
    "jay",
    "juniper",
    "kelp",
    "kestrel",
    "kettle",
    "kingfisher",
    "knoll",
    "lagoon",
    "lake",
    "lantern",
    "lark",
    "laurel",
    "leaf",
    "leaflet",
    "ledge",
    "lichen",
    "lily",
    "linden",
    "lion",
    "loft",
    "loon",
    "lotus",
    "lupin",
    "lynx",
    "magnolia",
    "magpie",
    "maple",
    "marmot",
    "marsh",
    "meadow",
    "meadowlark",
    "mesa",
    "mist",
    "moor",
    "moss",
    "moth",
    "mountain",
    "narwhal",
    "nettle",
    "nightingale",
    "nimbus",
    "oak",
    "ocean",
    "ochre",
    "opal",
    "orchard",
    "orchid",
    "oriole",
    "otter",
    "owl",
    "palm",
    "pelican",
    "petal",
    "pine",
    "pinion",
    "plain",
    "plateau",
    "plover",
    "pond",
    "poppy",
    "prairie",
    "prism",
    "puffin",
    "quartz",
    "quill",
    "raindrop",
    "rapid",
    "raven",
    "ravine",
    "redwood",
    "reef",
    "ridge",
    "river",
    "robin",
    "rook",
    "rosemary",
    "rowan",
    "sable",
    "saffron",
    "sage",
    "salmon",
    "sand",
    "sandbar",
    "sandpiper",
    "sapling",
    "savanna",
    "scrub",
    "sea",
    "shadow",
    "shale",
    "shard",
    "sheaf",
    "shore",
    "shrub",
    "sky",
    "slate",
    "snowdrop",
    "snowfall",
    "snowflake",
    "sparrow",
    "spindle",
    "spire",
    "spring",
    "sprout",
    "spruce",
    "squall",
    "starling",
    "starshine",
    "steppe",
    "stone",
    "stratus",
    "summit",
    "swallow",
    "swift",
    "tarn",
    "tern",
    "thaw",
    "thicket",
    "thistle",
    "thrush",
    "tide",
    "tideline",
    "tinder",
    "topaz",
    "tournesol",
    "trillium",
    "trout",
    "tundra",
    "twilight",
    "twig",
    "valley",
    "vesper",
    "vine",
    "violet",
    "wallaby",
    "warbler",
    "wave",
    "weasel",
    "whirlwind",
    "willow",
    "wisp",
    "wolf",
    "wood",
    "wren",
    "yarrow",
    "yew",
    "zephyr",
];

/// ~144 curated emojis. All single Unicode codepoint —
/// no flags, no skin tone, no ZWJ family/profession sequences. Render
/// consistently across iTerm, Terminal.app, Alacritty, kitty, GNOME
/// Terminal, Konsole, and tmux.
/// v0.7.0-alpha.4: more than doubled from the alpha.1 set of 64. Themed
/// across animals (fauna heavy because they're the most evocative),
/// flora, weather/sky, food, music, and abstract symbols.
const EMOJIS: &[&str] = &[
    // Animals — mammals
    "🦊", "🐺", "🐻", "🐅", "🐆", "🦓", "🦒", "🦌", "🦘", "🐇", "🦔", "🦣", "🦏", "🐈", "🐱", "🐶",
    "🐰", "🦦", "🦥", "🦡", "🦨", "🦄", "🐴", "🐗", "🐘", "🦬", "🦫", "🐪", "🦙", "🐭", "🐹", "🐀",
    // Animals — birds
    "🦅", "🦉", "🦢", "🦩", "🐧", "🦃", "🦚", "🦜", "🦤", "🦆", "🐓", "🐔", "🐦", "🪶",
    // Animals — reptiles + amphibians
    "🐊", "🦎", "🐍", "🐢", "🦕", "🦖", "🐸", // Animals — sea
    "🐙", "🐬", "🐳", "🐋", "🐡", "🦈", "🦭", "🐟", "🐠", "🦀", "🦞", "🦐", "🐚",
    // Animals — bugs
    "🐝", "🦋", "🐌", "🐞", "🦗", "🕷", "🦂", // Plants — trees
    "🌲", "🌳", "🌴", "🌵", "🌱", "🌿", "🍃", "🍀", "🍁", "🍂", // Plants — flowers
    "🌷", "🌸", "🌺", "🌻", "🌼", "🌹", "🪻", "🪷", "🍄", // Plants — fruits
    "🍇", "🍈", "🍉", "🍊", "🍋", "🍌", "🍍", "🥭", "🍎", "🍏", "🍐", "🍑", "🍒", "🍓", "🫐", "🥝",
    // Weather + sky
    "🌊", "🌋", "🌙", "🌟", "🌈", "🔥", "❄", "💧", "⚡", "☀", "☁", "⛄",
    // Light + abstract
    "💎", "🪄", "🔮", "🧿", "🌠", // Music
    "🎵", "🎶", "🎷", "🎸", "🎹", "🎺", "🎻", "🥁", "🪕", "🪈", // Objects + travel
    "⚓", "🧭", "🏺", "🪴", "🗿", "🛡", "🗝", "🎲", "🎭", "🎨", "🎯", "🪐",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
            let key = (
                c.nickname.clone(),
                c.emoji.clone(),
                c.palette.primary_hex.clone(),
            );
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
    fn sanitize_strips_ansi_escape() {
        // The core attack vector: peer publishes display.nickname with
        // ESC ] 0 ; pwned BEL → terminal renames window. ESC + BEL are
        // U+001B / U+0007 (control chars); the `]` and `;` and visible
        // text are printable and survive but are harmless without ESC.
        let out = sanitize_display_text("\x1b]0;owned\x07");
        assert!(!out.contains('\x1b'), "ESC must be stripped: {out:?}");
        assert!(!out.contains('\x07'), "BEL must be stripped: {out:?}");
        // The visible-but-now-harmless residue.
        assert_eq!(out, "]0;owned");
        // CSI sequences also defanged (ESC gone).
        let out2 = sanitize_display_text("\x1b[2J\x1b[H");
        assert!(!out2.contains('\x1b'));
        assert_eq!(out2, "[2J[H");
        // Newlines / tabs / DEL also stripped.
        assert_eq!(sanitize_display_text("hello\nworld"), "helloworld");
        assert_eq!(sanitize_display_text("a\tb\x7fc"), "abc");
    }

    #[test]
    fn sanitize_preserves_unicode_emoji_and_text() {
        assert_eq!(
            sanitize_display_text("🦊 foxtrot-meadow"),
            "🦊 foxtrot-meadow"
        );
        assert_eq!(sanitize_display_text("café résumé"), "café résumé");
    }

    #[test]
    fn sanitize_caps_length() {
        let long = "a".repeat(200);
        let out = sanitize_display_text(&long);
        assert_eq!(out.chars().count(), MAX_DISPLAY_CHARS);
    }

    #[test]
    fn from_card_with_empty_did_returns_unknown_sentinel() {
        // The exact silent-collision scenario from review-fix #8: a
        // pinned peer card with null/missing/empty did used to collapse
        // every such peer onto from_did("") — same character for all.
        let card = json!({"handle": "broken"});
        let c = Character::from_card(&card);
        assert_eq!(c.nickname, "unknown-peer");
        assert_eq!(c.emoji, "❓");
    }

    #[test]
    fn from_card_with_null_did_returns_unknown_sentinel() {
        let card = json!({"did": null, "handle": "broken"});
        let c = Character::from_card(&card);
        assert_eq!(c.nickname, "unknown-peer");
    }

    #[test]
    fn from_card_strips_escape_from_published_nickname() {
        // Defense-in-depth: even if a malicious peer signed a card with
        // ANSI escapes in display.nickname before this validation
        // shipped, we strip them at read time so the operator's
        // terminal stays safe.
        let card = json!({
            "did": "did:wire:malicious-deadbeef",
            "display": {"nickname": "\x1b]0;OWNED\x07evil", "emoji": "🦊"},
        });
        let c = Character::from_card(&card);
        // ESC + OSC delimiters removed; what's left is the visible text.
        assert!(!c.nickname.contains('\x1b'));
        assert!(!c.nickname.contains('\x07'));
        assert!(c.nickname.contains("OWNED")); // visible text preserved
        assert_eq!(c.emoji, "🦊");
    }

    #[test]
    fn from_card_with_published_override_uses_it() {
        let card = json!({
            "did": "did:wire:friend-12345678",
            "display": {"nickname": "the-forge", "emoji": "🔨"},
        });
        let c = Character::from_card(&card);
        assert_eq!(c.nickname, "the-forge");
        assert_eq!(c.emoji, "🔨");
    }

    #[test]
    fn from_card_without_display_falls_back_to_did() {
        let card = json!({"did": "did:wire:friend-12345678"});
        let c = Character::from_card(&card);
        let auto = Character::from_did("did:wire:friend-12345678");
        assert_eq!(c, auto);
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
