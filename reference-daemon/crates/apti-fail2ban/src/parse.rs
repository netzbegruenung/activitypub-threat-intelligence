//! Parsing of fail2ban log lines and mapping of jails to AP-TI behaviours.

use std::net::IpAddr;
use std::sync::OnceLock;

use apti_core::Behavior;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Value};

use crate::config::Push;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Ban,
    RestoreBan,
    IncreaseBan,
    Unban,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEvent {
    pub time: DateTime<Utc>,
    pub jail: String,
    pub action: Action,
    pub ip: String,
}

fn line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[,.]\d+)?\s+fail2ban\.actions\s*\[\d+\]:\s+[A-Z]+\s+\[(?P<jail>[^\]]+)\]\s+(?P<action>Restore Ban|Increase Ban|Ban|Unban)\s+(?P<ip>[0-9A-Fa-f:.]+(?:/\d{1,3})?)",
        )
        .expect("static regex")
    })
}

/// Parse one fail2ban log line. Timestamps are in the host's local time.
pub fn parse_line(line: &str) -> Option<BanEvent> {
    let c = line_re().captures(line)?;
    let naive = NaiveDateTime::parse_from_str(&c["ts"], "%Y-%m-%d %H:%M:%S").ok()?;
    let time = Local
        .from_local_datetime(&naive)
        .earliest()?
        .with_timezone(&Utc);
    let ip = &c["ip"];
    let host = ip.split('/').next().unwrap_or(ip);
    host.parse::<IpAddr>().ok()?;
    let action = match &c["action"] {
        "Ban" => Action::Ban,
        "Restore Ban" => Action::RestoreBan,
        "Increase Ban" => Action::IncreaseBan,
        _ => Action::Unban,
    };
    Some(BanEvent {
        time,
        jail: c["jail"].to_string(),
        action,
        ip: ip.to_string(),
    })
}

/// Turn a ban event into an aptid observation (`POST /api/v1/observations`
/// item), or `None` if it must not be reported.
pub fn to_observation(ev: &BanEvent, cfg: &Push) -> Option<Value> {
    match ev.action {
        Action::Ban | Action::IncreaseBan => {}
        Action::RestoreBan if cfg.report_restored => {}
        Action::RestoreBan | Action::Unban => return None,
    }
    if cfg.ignore_jails.contains(&ev.jail) {
        return None;
    }
    let (behavior, port, service) = match cfg.jails.get(&ev.jail) {
        Some(m) => (
            m.behavior.parse::<Behavior>().ok()?,
            m.port,
            m.service.clone(),
        ),
        None => (
            cfg.default_behavior.as_deref()?.parse::<Behavior>().ok()?,
            None,
            None,
        ),
    };
    let mut o = json!({
        "value": ev.ip,
        "behavior": behavior.as_str(),
        "seenAt": ev.time,
    });
    if let Some(p) = port {
        o["port"] = json!(p);
    }
    if let Some(s) = service {
        o["service"] = json!(s);
    }
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JailMap;
    use std::collections::BTreeMap;

    fn push_cfg() -> Push {
        let mut jails = BTreeMap::new();
        jails.insert(
            "sshd".to_string(),
            JailMap {
                behavior: "ssh-bruteforce".into(),
                port: Some(22),
                service: Some("ssh".into()),
            },
        );
        jails.insert(
            "postfix-sasl".to_string(),
            JailMap {
                behavior: "auth-bruteforce".into(),
                port: None,
                service: Some("smtp".into()),
            },
        );
        Push {
            log: "/x".into(),
            state_file: "/y".into(),
            batch_interval_secs: 30,
            poll_interval_ms: 1000,
            ignore_jails: vec!["aptid-ssh".into()],
            report_restored: false,
            default_behavior: None,
            max_queue: 10,
            jails,
        }
    }

    #[test]
    fn parses_ban_lines() {
        let l =
            "2026-10-03 12:00:01,123 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 45.13.7.9";
        let e = parse_line(l).unwrap();
        assert_eq!(e.jail, "sshd");
        assert_eq!(e.action, Action::Ban);
        assert_eq!(e.ip, "45.13.7.9");
        let expected = Local
            .from_local_datetime(
                &NaiveDateTime::parse_from_str("2026-10-03 12:00:01", "%Y-%m-%d %H:%M:%S").unwrap(),
            )
            .earliest()
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(e.time, expected);

        let l = "2026-10-03 12:00:01,123 fail2ban.actions [99]: NOTICE [postfix-sasl] Restore Ban 2a01:4f8:1::17";
        let e = parse_line(l).unwrap();
        assert_eq!(
            (e.jail.as_str(), e.action, e.ip.as_str()),
            ("postfix-sasl", Action::RestoreBan, "2a01:4f8:1::17")
        );

        let l = "2026-10-03 12:00:01,123 fail2ban.actions [99]: NOTICE [sshd] Increase Ban 45.13.7.9 (2 # 2:00:00 -> 2026-10-03 14:00:01)";
        assert_eq!(parse_line(l).unwrap().action, Action::IncreaseBan);

        let l = "2026-10-03 12:10:01,123 fail2ban.actions [99]: NOTICE [sshd] Unban 45.13.7.9";
        assert_eq!(parse_line(l).unwrap().action, Action::Unban);
    }

    #[test]
    fn ignores_other_lines() {
        for l in [
            "2026-10-03 12:00:01,123 fail2ban.filter [1]: INFO [sshd] Found 45.13.7.9 - 2026-10-03 12:00:00",
            "2026-10-03 12:00:01,123 fail2ban.actions [1]: WARNING [sshd] 45.13.7.9 already banned",
            "2026-10-03 12:00:01,123 fail2ban.actions [1]: NOTICE [sshd] Ban not-an-ip",
            "garbage",
            "",
        ] {
            assert_eq!(parse_line(l), None, "{l}");
        }
    }

    #[test]
    fn maps_jails() {
        let cfg = push_cfg();
        let ev = |jail: &str, action| BanEvent {
            time: Utc::now(),
            jail: jail.into(),
            action,
            ip: "45.13.7.9".into(),
        };
        let o = to_observation(&ev("sshd", Action::Ban), &cfg).unwrap();
        assert_eq!(o["behavior"], "ssh-bruteforce");
        assert_eq!(o["port"], 22);
        assert_eq!(o["service"], "ssh");
        let o = to_observation(&ev("postfix-sasl", Action::IncreaseBan), &cfg).unwrap();
        assert!(o.get("port").is_none());
        assert!(to_observation(&ev("sshd", Action::Unban), &cfg).is_none());
        assert!(to_observation(&ev("sshd", Action::RestoreBan), &cfg).is_none());
        assert!(
            to_observation(&ev("aptid-ssh", Action::Ban), &cfg).is_none(),
            "ignored jail"
        );
        assert!(
            to_observation(&ev("nginx-http-auth", Action::Ban), &cfg).is_none(),
            "unmapped jail"
        );

        let mut cfg = cfg;
        cfg.report_restored = true;
        cfg.default_behavior = Some("other".into());
        assert!(to_observation(&ev("sshd", Action::RestoreBan), &cfg).is_some());
        assert_eq!(
            to_observation(&ev("nginx-http-auth", Action::Ban), &cfg).unwrap()["behavior"],
            "other"
        );
    }
}
