use std::{collections::HashMap, convert::TryFrom, env, fmt, net, sync::Arc, sync::RwLock};
use warp::{header, reply::with_status, Filter};
use warp::{http::StatusCode as Code, reject::custom as warp_err};

mod id;
use id::Id;

type WarpResult = Result<String, warp::Rejection>;
type DB = Arc<RwLock<HashMap<Id, String>>>;
type Key = Id;
use crate::Err::*;
use Rest::*;

fn main() {
    // Configuration via env variables
    let port = env::var("PORT").unwrap_or_default().parse().unwrap_or(3030);
    let addr = env::var("HOST")
        .unwrap_or_default()
        .parse()
        .unwrap_or_else(|_| net::IpAddr::V4(net::Ipv4Addr::new(127, 0, 0, 1)));

    // Optional key for single-user mode; `USER:PASSWORD`
    let key = env::var("KEY")
        .map(|k| {
            Key::try_from(k.as_str())
                .map_err(|_| {
                    eprintln!("Invalid key!");
                    std::process::exit(1);
                })
                .unwrap()
        })
        .ok();

    let display_key = key.clone();

    let key = warp::any().map(move || key.clone());

    // Store all IP addresses in a thread-safe hash map
    let db: DB = Arc::new(RwLock::new(HashMap::new()));
    let db = warp::any().map(move || db.clone());

    let get = warp::get2()
        .and(header("authorization"))
        .and(db.clone())
        .and_then(move |id: String, db: DB| -> WarpResult {
            let id = Id::from_basic(&id);
            match db.read().map_err(|_| warp_err(Db))?.get(&id) {
                Some(ip) => {
                    log(&Get, &id, &ip);
                    Ok(ip.to_string())
                }
                None => Err(warp::reject::custom(NotFound)),
            }
        });

    let show = warp::get2()
        .and(header("X-Forwarded-For").or(header("remote_addr")).unify())
        .and_then(move |ip: String| -> WarpResult {
            log(&Get, "UNKNOWN", &ip);
            Ok(ip)
        });

    let post = warp::post2()
        .and(header("X-Forwarded-For").or(header("remote_addr")).unify())
        .and(warp::header::<String>("authorization"))
        .and(db.clone())
        .and(key.clone())
        .and_then(move |ip: String, id: String, db: DB, key: Option<Key>| {
            let id = Id::from_basic(&id);
            if key.is_some() && key.unwrap() != id {
                return Err(warp_err(Unauthorized));
            }
            log(&Post, &id.user, &ip);
            db.write().map_err(|_| warp_err(Db))?.insert(id, ip.clone());
            Ok(ip)
        });

    let delete = warp::delete2()
        .and(header("authorization"))
        .and(db)
        .and_then(move |id: Id, db: DB| -> WarpResult {
            match db.write().map_err(|_| warp_err(Db))?.remove(&id) {
                Some(ip) => {
                    log(&Delete, &id.user, &ip);
                    Ok(format!("IP deleted for ID: {}", &id))
                }
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

    if let Some(k) = display_key {
        eprintln!("Using key '{}'", k);
    }

    warp::serve(get.or(post).or(delete).or(show).recover(handle_err)).run((addr, port));
}

fn log<X, Y, Z>(rest: X, id: Y, ip: Z)
where
    X: fmt::Display,
    Y: fmt::Display,
    Z: fmt::Display,
{
    println!("[{}] USER:{} IP:{}", rest, id, ip);
}

/// The HTTP REST methods
#[derive(Debug)]
enum Rest {
    Post,
    Get,
    // Put,
    // Patch,
    Delete,
}

impl fmt::Display for Rest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_uppercase())
    }
}

#[derive(Debug)]
enum Err {
    Db,
    NotFound,
    Unauthorized,
}

impl fmt::Display for Err {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}",
            match self {
                Self::Db => "Internal server error.",
                Self::NotFound => "No IP found for that username–password pair.",
                Self::Unauthorized => "Unauthorized request.",
            }
        )
    }
}

impl std::error::Error for Err {}
