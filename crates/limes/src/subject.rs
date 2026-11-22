/// A subject is a unique identifier for a user.
#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "valuable", derive(valuable::Valuable))]
pub struct Subject {
    #[cfg_attr(feature = "valuable", valuable(rename = "id"))]
    sub: String,
    #[cfg_attr(feature = "valuable", valuable(rename = "idp"))]
    idp_id: Option<String>,
}

impl Subject {
    /// Create a new subject.
    ///
    /// - `idp_id`: The unique identifier of the identity provider this subject is from. None ids should only be used for single tenant setups.
    /// - `sub`: The unique identifier of the subject in the identity provider.
    #[must_use]
    pub fn new(idp_id: Option<String>, sub: String) -> Self {
        Self {
            sub,
            idp_id: idp_id.filter(|s| !s.is_empty()),
        }
    }

    /// Get the subject ID inside the identity provider.
    #[must_use]
    pub fn subject_in_idp(&self) -> &str {
        &self.sub
    }

    /// Get the unique identifier of the identity provider.
    #[must_use]
    pub fn idp_id(&self) -> Option<&str> {
        self.idp_id.as_deref()
    }
}
