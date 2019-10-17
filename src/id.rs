use std::convert::TryFrom;
use std::fmt;

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub struct Id {
    pub user: String,
    pub password: String,
    pub encoded: String,
}

impl Id {
    pub fn new(user: &str, password: &str) -> Self {
        Id {
            user: user.into(),
            password: password.into(),
            encoded: base64::encode(&format!("{}:{}", user, password)),
        }
    }

    pub fn basic(&self) -> String {
        format!("Basic {}", self.encoded)
    }

    pub fn from_basic(s: &str) -> Self {
        let parsed = s.trim().trim_start_matches("Basic ").trim();
        let decoded = String::from_utf8_lossy(&base64::decode(parsed)
            .expect("base64 decode error"))
            .to_string();
        Id::try_from(decoded.as_str()).expect("Invalid Basic Id")
    }
}

impl std::str::FromStr for Id {
    type Err = std::io::Error;
    fn from_str(s: &str) ->  Result<Self, Self::Err> {
        Ok(Id::from_basic(s))
    }
}

impl TryFrom<&str> for Id {
    type Error = std::io::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let split = s.trim().split(':').collect::<Vec<&str>>();
        match split.len() {
            2 => Ok(Id::new(split[0], split[1])),
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.user, self.password)
    }
}

#[test]
fn encode_id() {
    let id = Id::new("derp", "flerp");
    dbg!(&id);
    assert_eq!(format!("{}", id.basic()), "Basic ZGVycDpmbGVycA==");
}

#[test]
fn convert_id() {
    let id_try = Id::try_from("derp:flerp").unwrap();
    let id_exp = Id::new("derp", "flerp");
    assert_eq!(id_try, id_exp);
}

#[test]
fn convert_id_err() {
    assert!(Id::try_from("").is_err());
    assert!(Id::try_from("derpflerp").is_err());
    assert!(Id::try_from(":derpflerp:").is_err());
    assert!(Id::try_from(":derpflerp").is_ok());
    assert!(Id::try_from("derpflerp:").is_ok());

    let id = Id::try_from(":derpflerp").unwrap();
    assert!(id.user.is_empty() && !id.password.is_empty());

    let id = Id::try_from("derpflerp:").unwrap();
    assert!(!id.user.is_empty() && id.password.is_empty());
}
