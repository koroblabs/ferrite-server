//! Breakage: a device asking again and again for a blocked name while it uses
//! the site that name belongs to. That is what an app looks like when a list
//! broke it — Instagram opens, but the feed never comes because a list blocks
//! the address it is fetched from. An advert or a tracker is usually another
//! site's name, which the device isn't otherwise using, so it doesn't count.
//!
//! The site of a name is the catalog service it belongs to (so
//! `cdninstagram.com` is Instagram's, like `instagram.com`), else its
//! registrable domain. A blocked answer is cached by the device for the client
//! TTL (a minute by default), so tries arrive about that often: a few of them
//! within ten minutes, while the same site answers, is the signal. What blocked
//! the name, and whether the block was the user's own choice, is for the API
//! to judge — this only keeps the pairs, for a day.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;
use serde::Serialize;

use ferrite_core::types::{QueryEntry, QueryStatus};

/// Queries closer together than this are one try: A, AAAA and HTTPS of the
/// same lookup.
const SAME_TRY: i64 = 5;
/// The tries, and the site answering, are counted within this window.
const WINDOW: i64 = 10 * 60;
/// Tries in the window that make a suspect.
const MIN_TRIES: usize = 3;
/// A suspect is shown this long after its last try.
const KEEP: i64 = 24 * 3600;
/// Bounds on what is kept, whatever the traffic.
const MAX_SUSPECTS: usize = 100;
const MAX_SITES_PER_DEVICE: usize = 512;
const MAX_TRIED_PER_DEVICE: usize = 512;
/// Old entries are swept at most this often.
const SWEEP_EVERY: i64 = 60;

/// One device, one blocked name it keeps asking for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suspect {
    /// The device key: its MAC when known, else its IP.
    pub device: String,
    pub domain: String,
    /// The site the name belongs to: a catalog service's name, or the
    /// registrable domain.
    pub site: String,
    /// Tries within the window, at the last one.
    pub tries: u32,
    /// Unix seconds: when it became a suspect, and its last try.
    pub first: i64,
    pub last: i64,
}

struct Tried {
    site: Site,
    /// Start of each try within the window, oldest first.
    at: VecDeque<i64>,
}

/// The site a name belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Site {
    /// What two names are compared by: `service:<id>`, or the registrable
    /// domain.
    pub key: String,
    /// What the panel calls it: the service's name, or the domain.
    pub label: String,
}

#[derive(Default)]
struct State {
    /// Per device: blocked names it asked for lately.
    tried: HashMap<String, HashMap<String, Tried>>,
    /// Per device: sites that answered it lately, and when last.
    reached: HashMap<String, HashMap<String, i64>>,
    /// (device, domain) → suspect.
    suspects: HashMap<(String, String), Suspect>,
    swept: i64,
}

/// Keeps the pairs; fed by the stats writer, read by the panel.
#[derive(Default)]
pub struct BreakageWatch {
    state: Mutex<State>,
}

impl std::fmt::Debug for BreakageWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakageWatch").finish_non_exhaustive()
    }
}

/// The catalog service `domain` belongs to, else its registrable domain;
/// `None` for a name with neither (`printer`, a bare suffix).
pub fn site_of(domain: &str) -> Option<Site> {
    let domain = domain.trim_end_matches('.');
    if let Some(service) = ferrite_core::services::owner_of(domain) {
        return Some(Site {
            key: format!("service:{}", service.id),
            label: service.name.clone(),
        });
    }
    let registrable = psl::domain_str(domain)?;
    Some(Site {
        key: registrable.to_string(),
        label: registrable.to_string(),
    })
}

impl BreakageWatch {
    /// One query, as the stats writer drains it; `device` is the key it is
    /// counted under.
    pub fn push(&self, entry: &QueryEntry, device: &str) {
        let Some(site) = site_of(&entry.domain) else {
            return;
        };
        let now = entry.timestamp.timestamp();
        let mut st = self.state.lock();
        if now - st.swept >= SWEEP_EVERY {
            st.sweep(now);
        }
        if entry.status == QueryStatus::Blocked {
            st.blocked(device, &entry.domain, site, now);
        } else {
            st.answered(device, site.key, now);
        }
    }

    /// Suspects, the latest try first.
    pub fn suspects(&self) -> Vec<Suspect> {
        let mut out: Vec<Suspect> = self.state.lock().suspects.values().cloned().collect();
        out.sort_unstable_by(|a, b| b.last.cmp(&a.last).then_with(|| a.domain.cmp(&b.domain)));
        out
    }

    /// Stop suspecting `domain`, on every device.
    pub fn drop_domain(&self, domain: &str) {
        let mut st = self.state.lock();
        st.suspects.retain(|(_, d), _| d != domain);
        for tried in st.tried.values_mut() {
            tried.remove(domain);
        }
    }

    /// Forget everything: the query log or statistics were cleared.
    pub fn clear(&self) {
        *self.state.lock() = State::default();
    }
}

impl State {
    fn blocked(&mut self, device: &str, domain: &str, site: Site, now: i64) {
        let tried = self.tried.entry(device.to_string()).or_default();
        if !tried.contains_key(domain) && tried.len() >= MAX_TRIED_PER_DEVICE {
            return;
        }
        let entry = tried.entry(domain.to_string()).or_insert_with(|| Tried {
            site,
            at: VecDeque::new(),
        });
        if entry.at.back().is_none_or(|&t| now - t >= SAME_TRY) {
            entry.at.push_back(now);
        }
        while entry.at.front().is_some_and(|&t| now - t > WINDOW) {
            entry.at.pop_front();
        }
        let tries = entry.at.len();
        let site = entry.site.clone();
        let key = (device.to_string(), domain.to_string());
        if let Some(s) = self.suspects.get_mut(&key) {
            s.last = now;
            s.tries = tries as u32;
            return;
        }
        let reached = self
            .reached
            .get(device)
            .and_then(|r| r.get(&site.key))
            .is_some_and(|&t| now - t <= WINDOW);
        if tries >= MIN_TRIES && reached {
            self.suspect(key, site.label, tries, now);
        }
    }

    /// The site answered the device: names of it the device kept being
    /// refused become suspects now, if they weren't.
    fn answered(&mut self, device: &str, site: String, now: i64) {
        let reached = self.reached.entry(device.to_string()).or_default();
        if reached.contains_key(&site) || reached.len() < MAX_SITES_PER_DEVICE {
            reached.insert(site.clone(), now);
        }
        let Some(tried) = self.tried.get(device) else {
            return;
        };
        let due: Vec<(String, String, usize)> = tried
            .iter()
            .filter(|(_, t)| {
                t.site.key == site
                    && t.at.len() >= MIN_TRIES
                    && t.at.back().is_some_and(|&last| now - last <= WINDOW)
            })
            .map(|(domain, t)| (domain.clone(), t.site.label.clone(), t.at.len()))
            .collect();
        for (domain, label, tries) in due {
            let key = (device.to_string(), domain);
            if !self.suspects.contains_key(&key) {
                self.suspect(key, label, tries, now);
            }
        }
    }

    fn suspect(&mut self, key: (String, String), site: String, tries: usize, now: i64) {
        if self.suspects.len() >= MAX_SUSPECTS
            && let Some(oldest) = self
                .suspects
                .iter()
                .min_by_key(|(_, s)| s.last)
                .map(|(k, _)| k.clone())
        {
            self.suspects.remove(&oldest);
        }
        let (device, domain) = key.clone();
        self.suspects.insert(
            key,
            Suspect {
                device,
                domain,
                site,
                tries: tries as u32,
                first: now,
                last: now,
            },
        );
    }

    fn sweep(&mut self, now: i64) {
        self.swept = now;
        for tried in self.tried.values_mut() {
            tried.retain(|_, t| t.at.back().is_some_and(|&last| now - last <= WINDOW));
        }
        self.tried.retain(|_, t| !t.is_empty());
        for reached in self.reached.values_mut() {
            reached.retain(|_, &mut t| now - t <= WINDOW);
        }
        self.reached.retain(|_, r| !r.is_empty());
        self.suspects.retain(|_, s| now - s.last <= KEEP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn q(domain: &str, status: QueryStatus, at: i64) -> QueryEntry {
        QueryEntry {
            id: 0,
            timestamp: Utc.timestamp_opt(1_800_000_000 + at, 0).unwrap(),
            domain: domain.into(),
            query_type: 1,
            client_ip: "192.168.1.20".into(),
            device: "aa:bb:cc:dd:ee:ff".into(),
            status,
            latency_ms: 0,
            upstream: None,
            rcode: 0,
        }
    }

    const PHONE: &str = "aa:bb:cc:dd:ee:ff";

    #[test]
    fn a_blocked_name_of_a_site_in_use_asked_again_and_again_is_a_suspect() {
        let w = BreakageWatch::default();
        w.push(&q("i.instagram.com", QueryStatus::Upstream, 0), PHONE);
        for minute in 0..3 {
            w.push(
                &q("graph.instagram.com", QueryStatus::Blocked, minute * 60),
                PHONE,
            );
        }
        let s = w.suspects();
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].domain, "graph.instagram.com");
        assert_eq!(s[0].site, "Instagram", "a catalog service is named as such");
        assert_eq!(s[0].tries, 3);
    }

    #[test]
    fn a_lookup_is_one_try_whatever_it_asks() {
        let w = BreakageWatch::default();
        w.push(&q("example.com", QueryStatus::Cached, 0), PHONE);
        // A, AAAA and HTTPS of one lookup, three times over: still one try.
        for at in [0, 1, 2] {
            w.push(&q("api.example.com", QueryStatus::Blocked, at), PHONE);
        }
        assert!(w.suspects().is_empty());
        w.push(&q("api.example.com", QueryStatus::Blocked, 60), PHONE);
        w.push(&q("api.example.com", QueryStatus::Blocked, 120), PHONE);
        assert_eq!(w.suspects()[0].site, "example.com");
    }

    #[test]
    fn another_sites_tracker_is_not_a_suspect() {
        let w = BreakageWatch::default();
        w.push(&q("www.example.com", QueryStatus::Upstream, 0), PHONE);
        for minute in 0..10 {
            w.push(
                &q("ads.doubleclick.net", QueryStatus::Blocked, minute * 60),
                PHONE,
            );
        }
        assert!(w.suspects().is_empty());
    }

    #[test]
    fn the_site_answering_after_the_tries_counts_too() {
        let w = BreakageWatch::default();
        for minute in 0..3 {
            w.push(
                &q("cdn.example.org", QueryStatus::Blocked, minute * 60),
                PHONE,
            );
        }
        assert!(w.suspects().is_empty());
        w.push(&q("example.org", QueryStatus::Upstream, 200), PHONE);
        assert_eq!(w.suspects().len(), 1);
    }

    #[test]
    fn tries_spread_wider_than_the_window_dont_add_up() {
        let w = BreakageWatch::default();
        w.push(&q("example.net", QueryStatus::Upstream, 0), PHONE);
        for at in [0, WINDOW + 10, 2 * WINDOW + 20] {
            w.push(&q("example.net", QueryStatus::Upstream, at), PHONE);
            w.push(&q("x.example.net", QueryStatus::Blocked, at), PHONE);
        }
        assert!(w.suspects().is_empty());
    }

    #[test]
    fn devices_are_judged_apart() {
        let w = BreakageWatch::default();
        // The laptop uses the site; the phone keeps asking for the name.
        w.push(&q("example.com", QueryStatus::Upstream, 0), "laptop");
        for minute in 0..3 {
            w.push(
                &q("api.example.com", QueryStatus::Blocked, minute * 60),
                PHONE,
            );
        }
        assert!(w.suspects().is_empty());
    }

    #[test]
    fn a_suspect_lasts_a_day_and_goes_with_its_domain_or_a_clear() {
        let w = BreakageWatch::default();
        w.push(&q("example.com", QueryStatus::Upstream, 0), PHONE);
        for minute in 0..3 {
            w.push(
                &q("api.example.com", QueryStatus::Blocked, minute * 60),
                PHONE,
            );
        }
        assert_eq!(w.suspects().len(), 1);
        // Still there long after the window, gone after a day.
        w.push(&q("other.test", QueryStatus::Upstream, 3 * 3600), PHONE);
        assert_eq!(w.suspects().len(), 1);
        w.push(&q("other.test", QueryStatus::Upstream, KEEP + 600), PHONE);
        assert!(w.suspects().is_empty());

        for minute in 0..3 {
            w.push(
                &q(
                    "example.com",
                    QueryStatus::Upstream,
                    KEEP + 700 + minute * 60,
                ),
                PHONE,
            );
            w.push(
                &q(
                    "api.example.com",
                    QueryStatus::Blocked,
                    KEEP + 700 + minute * 60,
                ),
                PHONE,
            );
        }
        assert_eq!(w.suspects().len(), 1);
        w.drop_domain("api.example.com");
        assert!(w.suspects().is_empty());

        for minute in 0..3 {
            w.push(
                &q(
                    "example.com",
                    QueryStatus::Upstream,
                    KEEP + 2000 + minute * 60,
                ),
                PHONE,
            );
            w.push(
                &q(
                    "api.example.com",
                    QueryStatus::Blocked,
                    KEEP + 2000 + minute * 60,
                ),
                PHONE,
            );
        }
        assert_eq!(w.suspects().len(), 1);
        w.clear();
        assert!(w.suspects().is_empty());
    }

    #[test]
    fn names_without_a_site_are_left_alone() {
        let w = BreakageWatch::default();
        for minute in 0..5 {
            w.push(&q("printer", QueryStatus::Blocked, minute * 60), PHONE);
        }
        assert!(w.suspects().is_empty());
    }
}
