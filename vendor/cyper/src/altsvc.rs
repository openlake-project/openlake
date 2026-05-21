//! Vendored and modified from `altsvc` crate.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid parameter: {0}")]
    Parameter(String),
    #[error("invalid value of 'ma': {0}")]
    MaValue(String),
    #[error("invalid value of 'persist': {0}")]
    PersistValue(String),
    #[error("invalid value of 'alt-authority': {0}")]
    AltAuthorityValue(String),
    #[error("invalid port number: {0}")]
    PortNumber(String),
}

#[derive(Debug)]
pub enum AltService {
    Clear,
    Services(Vec<Service>),
}

#[derive(Debug, Default)]
pub struct Service {
    id: String,
    authority: AltAuthority,
    max_age: Option<u64>,
    persist: bool,
}

#[derive(Debug, Default)]
pub struct AltAuthority {
    pub host: String,
    pub port: u16,
}

pub fn parse(s: &str) -> Result<AltService, ParseError> {
    if s == "clear" {
        return Ok(AltService::Clear);
    }

    let mut ret = Vec::new();
    let services = s.split(",");
    for svc_string in services {
        let svc_string = svc_string.trim();
        if svc_string.is_empty() {
            continue;
        }
        let mut svc = Service::default();
        let params = svc_string.split(";");
        for kv in params {
            let raw_kv = kv.trim();
            if raw_kv.is_empty() {
                continue;
            }
            let kv_split: Vec<&str> = raw_kv.split("=").collect();
            if kv_split.len() != 2 {
                return Err(ParseError::Parameter(raw_kv.to_string()));
            }
            let k = kv_split[0];
            let v = kv_split[1];
            match k {
                "ma" => {
                    let ma = v.parse().map_err(|_| ParseError::MaValue(v.to_string()))?;
                    svc.max_age = Some(ma);
                }
                "persist" => {
                    let persist = v
                        .parse::<i32>()
                        .map_err(|_| ParseError::PersistValue(v.to_string()))?;
                    if persist != 1 {
                        continue;
                    }
                    svc.persist = true;
                }
                _ => {
                    let raw_value = v.trim_matches('"');
                    let alt_auth_split: Vec<&str> = raw_value.split(":").collect();
                    if alt_auth_split.len() != 2 {
                        return Err(ParseError::AltAuthorityValue(raw_value.to_string()));
                    }
                    svc.id = k.to_string();
                    let host = alt_auth_split[0].to_string();
                    let port = alt_auth_split[1].to_string();
                    let port = port
                        .parse()
                        .map_err(|_| ParseError::PortNumber(port.to_string()))?;
                    svc.authority = AltAuthority { host, port };
                }
            }
        }
        ret.push(svc);
    }
    Ok(AltService::Services(ret))
}

#[derive(Debug)]
struct AltHostEntry {
    insert_time: Instant,
    max_age: u64,
}

#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    map: Arc<Mutex<HashMap<String, AltHostEntry>>>,
}

impl KnownHosts {
    pub fn try_insert(&self, host: &str, srv: &crate::altsvc::Service) -> bool {
        if srv.id == "h3"
            && (srv.authority.host.is_empty() || srv.authority.host == host)
            && srv.authority.port == 443
        {
            self.map.lock().unwrap().insert(
                host.to_string(),
                AltHostEntry {
                    insert_time: Instant::now(),
                    max_age: srv.max_age.unwrap_or(86400), // 24 hours
                },
            );
            return true;
        }
        false
    }

    pub fn find(&self, host: &str) -> bool {
        let mut map = self.map.lock().unwrap();
        if let Some((host, entry)) = map.remove_entry(host)
            && (Instant::now() - entry.insert_time).as_secs() <= entry.max_age
        {
            map.insert(host, entry);
            return true;
        }
        false
    }

    pub fn clear(&self, host: &str) {
        self.map.lock().unwrap().remove(host);
    }
}
