//! Display labels for actors and operators, shared by the daemon and its
//! clients so that the same peer is named the same way everywhere. The
//! canonical label of an actor is its WebFinger handle `user@host`.

use url::Url;

/// Remote strings, made safe for display.
pub fn sanitize(s: Option<&str>) -> Option<String> {
    let s: String = s?.chars().filter(|c| !c.is_control()).take(100).collect();
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Host of an actor or operator id.
pub fn host(id: &str) -> Option<String> {
    Url::parse(id).ok()?.host_str().map(str::to_string)
}

/// WebFinger handle `user@host` from an actor's `preferredUsername` and id.
pub fn actor_handle(username: Option<&str>, id: &str) -> Option<String> {
    Some(format!("{}@{}", sanitize(username)?, host(id)?))
}

/// Label for an actor: its handle, else its id without the scheme. Actors of
/// one operator differ only in the path, so the fallback has to keep it.
pub fn actor_label(handle: Option<&str>, id: &str) -> String {
    if let Some(h) = handle {
        return h.to_string();
    }
    let Ok(url) = Url::parse(id) else {
        return id.to_string();
    };
    match url.host_str() {
        Some(host) => format!("{host}{}", url.path().trim_end_matches('/')),
        None => id.to_string(),
    }
}

/// Label for an operator: its host, else the id itself.
pub fn operator_label(id: &str) -> String {
    host(id).unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_needs_username_and_host() {
        assert_eq!(
            actor_handle(Some("feed"), "https://a.example/actor"),
            Some("feed@a.example".into())
        );
        assert_eq!(actor_handle(None, "https://a.example/actor"), None);
        assert_eq!(actor_handle(Some("feed"), "not a url"), None);
        assert_eq!(actor_handle(Some("  "), "https://a.example/actor"), None);
    }

    #[test]
    fn labels_fall_back_to_host_then_id() {
        let id = "https://a.example/actor";
        assert_eq!(actor_label(Some("feed@a.example"), id), "feed@a.example");
        assert_eq!(actor_label(None, id), "a.example/actor");
        assert_eq!(actor_label(None, "https://a.example/"), "a.example");
        assert_eq!(actor_label(None, "urn:x"), "urn:x");
        assert_eq!(operator_label("https://a.example/org"), "a.example");
    }

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize(Some("a\u{1b}[31mb")), Some("a[31mb".into()));
        assert_eq!(sanitize(Some("")), None);
    }
}
