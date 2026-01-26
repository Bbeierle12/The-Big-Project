//! Alert severity scoring stage.
//!
//! Adjusts the base severity of a normalized alert based on contextual signals
//! such as whether the alert targets a critical port.

use netsec_models::alert::{NormalizedAlert, Severity};

use crate::PipelineConfig;

/// Score the alert and return the final severity.
///
/// Currently checks if the alert targets a critical port and boosts severity by 1 level.
pub async fn score(alert: &NormalizedAlert, config: &PipelineConfig) -> Severity {
    let mut numeric = severity_to_score(alert.severity);

    if is_critical_port_alert(alert, &config.critical_ports) {
        numeric += 1;
    }

    // Clamp to valid range
    numeric = numeric.min(4);

    score_to_severity(numeric)
}

/// Convert a [`Severity`] to a numeric score (0-4).
pub fn severity_to_score(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Convert a numeric score (0-4) back to a [`Severity`].
pub fn score_to_severity(score: u8) -> Severity {
    match score {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

/// Check if the alert's raw_data references a critical port.
///
/// Looks for `port`, `dst_port`, or `dest_port` fields in `raw_data`.
pub fn is_critical_port_alert(alert: &NormalizedAlert, critical_ports: &[u16]) -> bool {
    let raw = &alert.raw_data;

    for key in &["port", "dst_port", "dest_port"] {
        if let Some(port_val) = raw.get(key) {
            if let Some(port) = port_val.as_u64() {
                if critical_ports.contains(&(port as u16)) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use netsec_models::alert::AlertCategory;

    fn make_alert(severity: Severity, raw_data: serde_json::Value) -> NormalizedAlert {
        NormalizedAlert {
            source_tool: "test".to_string(),
            severity,
            category: AlertCategory::Other,
            title: "Score test".to_string(),
            description: "".to_string(),
            device_ip: Some("10.0.0.1".to_string()),
            fingerprint: "fp-score".to_string(),
            raw_data,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_no_boost() {
        let config = PipelineConfig::default();
        let alert = make_alert(Severity::Low, serde_json::json!({"port": 8080}));
        let result = score(&alert, &config).await;
        assert_eq!(result, Severity::Low);
    }

    #[tokio::test]
    async fn test_critical_port_boost() {
        let config = PipelineConfig::default();
        let alert = make_alert(Severity::Low, serde_json::json!({"port": 22}));
        let result = score(&alert, &config).await;
        assert_eq!(result, Severity::Medium); // Low + 1 = Medium
    }

    #[tokio::test]
    async fn test_high_plus_critical_equals_critical() {
        let config = PipelineConfig::default();
        let alert = make_alert(Severity::High, serde_json::json!({"dest_port": 3389}));
        let result = score(&alert, &config).await;
        assert_eq!(result, Severity::Critical); // High + 1 = Critical
    }

    #[tokio::test]
    async fn test_clamp_at_critical() {
        let config = PipelineConfig::default();
        let alert = make_alert(Severity::Critical, serde_json::json!({"port": 445}));
        let result = score(&alert, &config).await;
        assert_eq!(result, Severity::Critical); // Critical + 1 clamped to Critical
    }

    #[test]
    fn test_severity_roundtrip() {
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let score = severity_to_score(sev);
            let back = score_to_severity(score);
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn test_port_detection_from_raw_data() {
        let critical = vec![22, 3389, 445];

        // port field
        let a1 = make_alert(Severity::Info, serde_json::json!({"port": 22}));
        assert!(is_critical_port_alert(&a1, &critical));

        // dst_port field
        let a2 = make_alert(Severity::Info, serde_json::json!({"dst_port": 3389}));
        assert!(is_critical_port_alert(&a2, &critical));

        // dest_port field
        let a3 = make_alert(Severity::Info, serde_json::json!({"dest_port": 445}));
        assert!(is_critical_port_alert(&a3, &critical));

        // non-critical port
        let a4 = make_alert(Severity::Info, serde_json::json!({"port": 8080}));
        assert!(!is_critical_port_alert(&a4, &critical));

        // no port field at all
        let a5 = make_alert(Severity::Info, serde_json::json!({"other": "value"}));
        assert!(!is_critical_port_alert(&a5, &critical));
    }
}
