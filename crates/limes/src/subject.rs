use core::option::Option::Some;

use crate::error::{Error, Result};

/// A subject is a unique identifier for a user.
#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct Subject {
    sub: String,
    idp_id: Option<String>,
}

impl Subject {
    /// Create a new subject.
    ///
    /// - `idp_id`: The unique identifier of the `IdP` this subject is from. None ids should only be used for single tenant setups.
    /// - `sub`: The unique identifier of the subject in the `IdP`.
    #[must_use]
    pub fn new(idp_id: Option<String>, sub: String) -> Self {
        Self {
            sub,
            idp_id: idp_id.filter(|s| !s.is_empty()),
        }
    }

    /// Get the subject ID inside the `IdP`
    #[must_use]
    pub fn subject_in_idp(&self) -> &str {
        &self.sub
    }

    /// Get the unique identifier of the `IdP`.
    #[must_use]
    pub fn idp_id(&self) -> Option<&String> {
        self.idp_id.as_ref()
    }
}

/// Format a subject as a string.
/// The subject is formatted as `<idp_id><separator><sub>` if `seperator` is provided.
/// Otherwise, the subject is formatted as `<sub>`. Use a separator of `None` for single tenant setups.
#[must_use]
pub fn format_subject(subject: &Subject, separator: Option<char>) -> String {
    if let Some(separator) = separator {
        format!(
            "{}{}{}",
            subject.idp_id.as_deref().unwrap_or(""),
            separator,
            subject.sub
        )
    } else {
        subject.sub.clone()
    }
}

/// Parse a subject from a string.
/// If `separator` is provided, the subject is expected to be formatted as `<idp_id><separator><sub>`.
/// Otherwise, the subject is expected to be formatted as `<sub>`.
///
/// # Errors
/// - If the subject is not formatted correctly.
pub fn parse_subject(subject: &str, separator: Option<char>) -> Result<Subject> {
    if let Some(separator) = separator {
        let parts = subject.split_once(separator);
        if let Some((idp_id, sub)) = parts {
            Ok(Subject::new(Some(idp_id.to_string()), sub.to_string()))
        } else {
            Err(Error::InvalidSubject {
                subject: subject.to_string(),
            })
        }
    } else {
        Ok(Subject::new(None, subject.to_string()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_format_subject_multi_tenant() {
        let subject = Subject::new(Some("idp".to_string()), "sub".to_string());
        assert_eq!(format_subject(&subject, Some(':')), "idp:sub");
    }

    #[test]
    fn test_format_subject_single_tenant() {
        let subject = Subject::new(None, "sub".to_string());
        assert_eq!(format_subject(&subject, None), "sub");
    }

    #[test]
    fn test_parse_subject_multi_tenant() {
        let subject = "idp:sub";
        let parsed = parse_subject(subject, Some(':')).unwrap();
        assert_eq!(parsed.idp_id(), Some("idp".to_string()).as_ref());
        assert_eq!(parsed.subject_in_idp(), "sub");
    }

    #[test]
    fn test_parse_subject_multi_tenant_invalid() {
        let subject = "idp";
        let parsed = parse_subject(subject, Some(':'));
        assert!(parsed.is_err());
    }
}
