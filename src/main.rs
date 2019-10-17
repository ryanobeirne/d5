use base64;
use std::{convert::TryFrom, fmt, collections::HashMap, env, net, sync::Arc, sync::Mutex};
use warp::{header, reply::with_status, Filter};
use warp::{http::StatusCode as Code, reject::custom as warp_err};

type WarpResult = Result<String, warp::Rejection>;
type DB = Arc<Mutex<HashMap<String, String>>>;
use crate::Err::*;

fn main() {
    // Configuration via env variables
    let port = env::var("PORT").unwrap_or_default().parse().unwrap_or(3030);
    let addr = env::var("HOST")
        .unwrap_or_default()
        .parse()
        .unwrap_or_else(|_| net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)));

    // Optional key for single-user mode; `USER:PASSWORD`
    // We must base64-encode the key and prefix it with `Basic ` to match curl's format
    let prefix = |s| format!("Basic {}", s);
    let key = env::var("KEY").map(|s| base64::encode(&s)).map(prefix).ok();
    let key = warp::any().map(move || key.clone());

    // Store all IP addresses in a thread-safe hash map
    let db: DB = Arc::new(Mutex::new(HashMap::new()));
    let db = warp::any().map(move || db.clone());

    let get = warp::get2()
        .and(header("authorization"))
        .and(db.clone())
        .and_then(move |id: String, ip: DB| -> WarpResult {
            match ip.lock().map_err(|_| warp_err(Db))?.get(&id) {
                Some(ip) => {
                    println!("GET:\tip:{}\tid:{}", &ip, &id);
                    Ok(ip.to_string())
                },
                None => Err(warp::reject::custom(NotFound)),
            }
        });

    let post = warp::post2()
        .and(header("X-Forwarded-For").or(header("remote_addr")).unify())
        .and(warp::header::<String>("authorization"))
        .and(db.clone())
        .and(key.clone())
        .and_then(move |ip: String, id: String, db: DB, key: Option<String>| {
            let dbgip = ip.clone();
            let dbgid = id.clone();
            if key.is_some() && key.unwrap() != id {
                return Err(warp_err(Unauthorized));
            }
            db.lock().map_err(|_| warp_err(Db))?.insert(id, ip.clone());
            println!("POST:\tip:{}\tid:{}", dbgip, dbgid);
            Ok(ip)
        });

    let delete = warp::delete2()
        .and(header("authorization"))
        .and(db)
        .and_then(move |id: String, db: DB| -> WarpResult {
            match db.lock().map_err(|_| warp_err(Db))?.remove(&id) {
                Some(ip) => {
                    println!("DELETE:\tip:{}\tid:{}", &ip, &id);
                    Ok(format!("IP deleted for ID: {}", &id))
                },
                None => Err(warp_err(NotFound)),
            }
        });

    let handle_err = |err: warp::Rejection| match err.find_cause::<Err>() {
        Some(Db) => Ok(with_status(Db.to_string(), Code::INTERNAL_SERVER_ERROR)),
        Some(NotFound) => Ok(with_status(NotFound.to_string(), Code::NOT_FOUND)),
        Some(Unauthorized) => Ok(with_status(Unauthorized.to_string(), Code::UNAUTHORIZED)),
        None => Err(err),
    };

    eprintln!("d5 running on {}:{}", addr, port);
    warp::serve(get.or(post).or(delete).recover(handle_err)).run((addr, port));
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Id {
    user: String,
    password: String,
    encoded: String,
}

impl Id {
    fn new(user: &str, password: &str) -> Self {
        Id { 
            user: user.into(),
            password: password.into(),
            encoded: base64::encode(&format!("{}:{}", user, password)),
        }
    }

    fn basic(&self) -> String {
        format!("Basic {}", self.encoded)
    }
}

impl TryFrom<&str> for Id {
    type Error = std::io::Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let split = s.trim().split(':').collect::<Vec<&str>>();
        match split.len() {
            2 => Ok(Id::new(split[0], split[1])),
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
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
    assert!(Id::try_from("derpflerp").is_err());
    assert!(Id::try_from(":derpflerp:").is_err());
    assert!(Id::try_from(":derpflerp").is_ok());
    assert!(Id::try_from("derpflerp:").is_ok());

    let id = Id::try_from(":derpflerp").unwrap();
    assert!(id.user.is_empty());

    let id = Id::try_from("derpflerp:").unwrap();
    assert!(id.password.is_empty());
}

#[derive(Debug)]
enum Err {
    Db,
    NotFound,
    Unauthorized,
}

impl fmt::Display for Err {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", match self {
            Self::Db => "Internal server error.",
            Self::NotFound => "No IP found for that username–password pair.",
            Self::Unauthorized => "Unauthorized request.",
        })
    }
}

impl std::error::Error for Err {}
