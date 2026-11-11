//! Coarse access rights. The launcher maps these onto Landlock access rights.

use std::fmt;
use std::ops::{BitAnd, BitOr};

use serde::{Deserialize, Serialize};

/// A set of access rights on a file or directory tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Access {
    /// Read files, list directories.
    pub read: bool,
    /// Write, create, truncate, rename and delete (within a directory tree, or one file).
    pub write: bool,
    /// Execute files.
    pub exec: bool,
}

impl Access {
    /// No access.
    pub const NONE: Access = Access {
        read: false,
        write: false,
        exec: false,
    };
    /// Read only.
    pub const R: Access = Access {
        read: true,
        write: false,
        exec: false,
    };
    /// Read and write.
    pub const RW: Access = Access {
        read: true,
        write: true,
        exec: false,
    };
    /// Read and execute.
    pub const RX: Access = Access {
        read: true,
        write: false,
        exec: true,
    };

    /// True if no right is set.
    pub fn is_empty(self) -> bool {
        self == Access::NONE
    }

    /// True if every right in `other` is also in `self`.
    pub fn contains(self, other: Access) -> bool {
        (self & other) == other
    }

    /// The verb for the most significant right in `self`, for messages.
    pub fn verb(self) -> &'static str {
        if self.write {
            "write"
        } else if self.exec {
            "execute"
        } else {
            "read"
        }
    }
}

impl BitAnd for Access {
    type Output = Access;
    fn bitand(self, rhs: Access) -> Access {
        Access {
            read: self.read && rhs.read,
            write: self.write && rhs.write,
            exec: self.exec && rhs.exec,
        }
    }
}

impl BitOr for Access {
    type Output = Access;
    fn bitor(self, rhs: Access) -> Access {
        Access {
            read: self.read || rhs.read,
            write: self.write || rhs.write,
            exec: self.exec || rhs.exec,
        }
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        let mut s = String::with_capacity(3);
        if self.read {
            s.push('r');
        }
        if self.write {
            s.push('w');
        }
        if self.exec {
            s.push('x');
        }
        f.write_str(&s)
    }
}

impl TryFrom<String> for Access {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Access> for String {
    fn from(value: Access) -> Self {
        value.to_string()
    }
}

impl std::str::FromStr for Access {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            return Ok(Access::NONE);
        }
        let mut a = Access::NONE;
        for c in s.chars() {
            match c {
                'r' if !a.read => a.read = true,
                'w' if !a.write => a.write = true,
                'x' if !a.exec => a.exec = true,
                _ => return Err(format!("invalid access `{s}` (use r, rw, rx or rwx)")),
            }
        }
        if a.is_empty() {
            return Err("empty access".into());
        }
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_ops() {
        for s in ["r", "rw", "rx", "rwx", "w", "x", "-"] {
            let a: Access = s.parse().expect(s);
            assert_eq!(a.to_string(), s);
        }
        assert!("rr".parse::<Access>().is_err());
        assert!("q".parse::<Access>().is_err());
        assert_eq!(Access::RW & Access::RX, Access::R);
        assert_eq!(Access::R | Access::RX, Access::RX);
        assert!(Access::RW.contains(Access::R));
        assert!(!Access::R.contains(Access::RW));
    }
}
