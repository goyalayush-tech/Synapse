//! Verdict Types
//!
//! Verdicts are the output of policy evaluation. A policy can:
//! - **Allow**: The event passes unchanged
//! - **Deny**: The event is rejected with a reason
//! - **Transform**: The event is modified before proceeding
//!
//! # Design Notes
//!
//! Verdicts are designed to be:
//! - Serializable (for audit logs)
//! - Cheap to clone (for parallel evaluation)
//! - Extensible (custom verdict types via TransformAction)

use serde::{Deserialize, Serialize};

/// The result of policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Verdict {
    /// Event is allowed to proceed unchanged
    Allow,

    /// Event is denied with a reason
    Deny(VerdictReason),

    /// Event is transformed before proceeding
    Transform(TransformAction),
}

impl Verdict {
    /// Create an allow verdict
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Create a deny verdict with a reason
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny(VerdictReason {
            code: "POLICY_VIOLATION".to_string(),
            message: reason.into(),
            policy_id: None,
        })
    }

    /// Create a deny verdict with a specific code
    pub fn deny_with_code(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Deny(VerdictReason {
            code: code.into(),
            message: message.into(),
            policy_id: None,
        })
    }

    /// Create a transform verdict
    pub fn transform(action: TransformAction) -> Self {
        Self::Transform(action)
    }

    /// Check if the verdict allows the event
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Transform(_))
    }

    /// Check if the verdict denies the event
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// Get the denial reason if denied
    pub fn denial_reason(&self) -> Option<&VerdictReason> {
        match self {
            Self::Deny(reason) => Some(reason),
            _ => None,
        }
    }

    /// Attach policy ID to the verdict
    pub fn with_policy(mut self, policy_id: impl Into<String>) -> Self {
        match &mut self {
            Self::Deny(reason) => {
                reason.policy_id = Some(policy_id.into());
            }
            Self::Transform(action) => {
                action.policy_id = Some(policy_id.into());
            }
            Self::Allow => {}
        }
        self
    }
}

/// Reason for denying an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictReason {
    /// Error code (machine-readable)
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Policy that generated this verdict
    pub policy_id: Option<String>,
}

impl VerdictReason {
    /// Create a new verdict reason
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            policy_id: None,
        }
    }
}

impl std::fmt::Display for VerdictReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Action to transform an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformAction {
    /// Type of transformation
    pub kind: TransformKind,
    /// New payload (if replacing)
    pub new_payload: Option<String>,
    /// Fields to add/modify
    pub set_fields: Vec<(String, serde_json::Value)>,
    /// Fields to remove
    pub remove_fields: Vec<String>,
    /// Policy that generated this transformation
    pub policy_id: Option<String>,
}

impl TransformAction {
    /// Create a new transform action that replaces the payload
    pub fn replace_payload(payload: impl Into<String>) -> Self {
        Self {
            kind: TransformKind::ReplacePayload,
            new_payload: Some(payload.into()),
            set_fields: Vec::new(),
            remove_fields: Vec::new(),
            policy_id: None,
        }
    }

    /// Create a new transform action that modifies fields
    pub fn modify_fields() -> Self {
        Self {
            kind: TransformKind::ModifyFields,
            new_payload: None,
            set_fields: Vec::new(),
            remove_fields: Vec::new(),
            policy_id: None,
        }
    }

    /// Add a field to set
    pub fn set_field(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.set_fields.push((key.into(), value));
        self
    }

    /// Add a field to remove
    pub fn remove_field(mut self, key: impl Into<String>) -> Self {
        self.remove_fields.push(key.into());
        self
    }

    /// Create a redact action
    pub fn redact(fields: Vec<String>) -> Self {
        Self {
            kind: TransformKind::Redact,
            new_payload: None,
            set_fields: Vec::new(),
            remove_fields: fields,
            policy_id: None,
        }
    }
}

/// Types of transformations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformKind {
    /// Replace the entire payload
    ReplacePayload,
    /// Modify specific fields
    ModifyFields,
    /// Redact sensitive data
    Redact,
    /// Enrich with additional data
    Enrich,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_allow() {
        let verdict = Verdict::allow();
        assert!(verdict.is_allowed());
        assert!(!verdict.is_denied());
        assert!(verdict.denial_reason().is_none());
    }

    #[test]
    fn test_verdict_deny() {
        let verdict = Verdict::deny("Rate limit exceeded");
        assert!(!verdict.is_allowed());
        assert!(verdict.is_denied());

        let reason = verdict.denial_reason().expect("should have reason");
        assert_eq!(reason.code, "POLICY_VIOLATION");
        assert_eq!(reason.message, "Rate limit exceeded");
    }

    #[test]
    fn test_verdict_deny_with_code() {
        let verdict = Verdict::deny_with_code("RATE_LIMIT", "Too many requests");
        let reason = verdict.denial_reason().expect("should have reason");
        assert_eq!(reason.code, "RATE_LIMIT");
        assert_eq!(reason.message, "Too many requests");
    }

    #[test]
    fn test_verdict_transform() {
        let action = TransformAction::modify_fields()
            .set_field("sanitized", serde_json::json!(true))
            .remove_field("secret");

        let verdict = Verdict::transform(action);
        assert!(verdict.is_allowed());
        assert!(!verdict.is_denied());
    }

    #[test]
    fn test_verdict_with_policy() {
        let verdict = Verdict::deny("test").with_policy("rate-limit-v1");
        let reason = verdict.denial_reason().expect("should have reason");
        assert_eq!(reason.policy_id, Some("rate-limit-v1".to_string()));
    }

    #[test]
    fn test_verdict_serialization() {
        let verdict = Verdict::deny_with_code("AUTH_FAILED", "Invalid token");
        let json = serde_json::to_string(&verdict).expect("should serialize");
        let parsed: Verdict = serde_json::from_str(&json).expect("should deserialize");

        let reason = parsed.denial_reason().expect("should have reason");
        assert_eq!(reason.code, "AUTH_FAILED");
    }
}
