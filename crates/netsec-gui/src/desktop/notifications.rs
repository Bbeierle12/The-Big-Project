//! Native desktop notifications using notify-rust.

use notify_rust::{Notification, Timeout};

/// Notification urgency level.
#[derive(Debug, Clone, Copy)]
pub enum NotificationUrgency {
    Low,
    Normal,
    Critical,
}

/// Show a desktop notification.
pub fn show_notification(title: &str, body: &str, _urgency: NotificationUrgency) {
    // Note: urgency hint is platform-specific and not always available
    // On Windows, we just show the notification without urgency hints
    let timeout = match _urgency {
        NotificationUrgency::Critical => Timeout::Never, // Critical stays until dismissed
        _ => Timeout::Milliseconds(5000),
    };

    if let Err(e) = Notification::new()
        .summary(title)
        .body(body)
        .appname("NetWatch")
        .timeout(timeout)
        .show()
    {
        tracing::warn!("Failed to show notification: {}", e);
    }
}

/// Show an alert notification.
pub fn notify_alert(severity: &str, title: &str, message: &str) {
    let urgency = match severity.to_lowercase().as_str() {
        "critical" => NotificationUrgency::Critical,
        "high" => NotificationUrgency::Critical,
        "medium" => NotificationUrgency::Normal,
        _ => NotificationUrgency::Low,
    };

    let title = format!("[{}] {}", severity.to_uppercase(), title);
    show_notification(&title, message, urgency);
}

/// Show a scan completion notification.
pub fn notify_scan_completed(scan_type: &str, target: &str, status: &str) {
    let (title, urgency) = if status == "completed" {
        (
            format!("Scan Completed: {}", scan_type),
            NotificationUrgency::Normal,
        )
    } else {
        (
            format!("Scan Failed: {}", scan_type),
            NotificationUrgency::Critical,
        )
    };

    let body = format!("Target: {}\nStatus: {}", target, status);
    show_notification(&title, &body, urgency);
}

/// Show a device discovered notification.
pub fn notify_device_discovered(ip: &str, hostname: Option<&str>) {
    let title = "New Device Discovered";
    let body = if let Some(host) = hostname {
        format!("{} ({})", host, ip)
    } else {
        ip.to_string()
    };
    show_notification(title, &body, NotificationUrgency::Normal);
}

/// Show a vulnerability found notification.
pub fn notify_vulnerability(severity: &str, cve: &str, device: &str) {
    let urgency = match severity.to_lowercase().as_str() {
        "critical" | "high" => NotificationUrgency::Critical,
        "medium" => NotificationUrgency::Normal,
        _ => NotificationUrgency::Low,
    };

    let title = format!("Vulnerability Found: {}", cve);
    let body = format!("Severity: {}\nDevice: {}", severity, device);
    show_notification(&title, &body, urgency);
}
