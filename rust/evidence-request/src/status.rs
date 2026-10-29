//! The interop profile's verification statuses (§7.1), shared by the checks
//! this crate runs.

/// A §7.1 verification status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    NotChecked,
    NotPresent,
    Inconclusive,
}

impl Status {
    /// The status as the profile writes it: `PASS`, `FAIL`, `NOT_CHECKED`,
    /// `NOT_PRESENT` or `INCONCLUSIVE`.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::NotChecked => "NOT_CHECKED",
            Status::NotPresent => "NOT_PRESENT",
            Status::Inconclusive => "INCONCLUSIVE",
        }
    }
}
