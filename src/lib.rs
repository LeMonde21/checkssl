use std::sync::{Arc};
use rustls::Session;
use std::net::TcpStream;
use std::io::{Write, Error, ErrorKind};
use std::fmt::Debug;
use x509_parser::{parse_x509_der};
use x509_parser::objects::*;
use x509_parser::extensions::*;
use chrono::{Utc, TimeZone, DateTime};
use serde::{Serialize, Deserialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerCert {
    pub issuer_common_name: String,
    pub subject_common_name: String,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub issuer_country: String,
    pub subject_country: String,
    pub issuer_state: String,
    pub subject_state: String,
    pub issuer_locality: String,
    pub subject_locality: String,
    pub issuer_organization: String,
    pub subject_organization: String,
    pub not_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub is_valid: bool,
    pub time_to_expiration: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct IntermediateCert {
    pub issuer_common_name: String,
    pub subject_common_name: String,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub issuer_country: String,
    pub subject_country: String,
    pub issuer_state: String,
    pub subject_state: String,
    pub issuer_locality: String,
    pub subject_locality: String,
    pub issuer_organization: String,
    pub subject_organization: String,
    pub not_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub is_valid: bool,
    pub time_to_expiration: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Cert {
    pub server: ServerCert,
    pub intermediate: IntermediateCert,
}

pub struct CheckSSL();

impl CheckSSL {
    /// Check ssl from domain with port 443
    ///
    /// Example
    ///
    /// ```no_run
    /// use checkssl::CheckSSL;
    ///
    /// match CheckSSL::from_domain("rust-lang.org") {
    ///   Ok(certificate) => {
    ///     // do something with certificate
    ///     assert!(certificate.server.is_valid);
    ///   }
    ///   Err(e) => {
    ///     // ssl invalid
    ///     eprintln!(e);
    ///   }
    /// }
    /// ```
    pub fn from_domain(domain: &str) -> Result<Cert, std::io::Error> {
        let mut config = rustls::ClientConfig::new();
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        let rc_config = Arc::new(config);
        let site = match webpki::DNSNameRef::try_from_ascii_str(domain) {
            Ok(val) => val,
            Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e.to_string())),
        };

        let mut sess = rustls::ClientSession::new(&rc_config, site);
        let mut sock = TcpStream::connect(format!("{}:443", domain))?;
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);

        let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
                          domain);
        tls.write_all(req.as_bytes())?;

        let mut server_cert = ServerCert {
            issuer_common_name: "".to_string(),
            signature_algorithm: "".to_string(),
            sans: Vec::new(),
            issuer_country: "".to_string(),
            subject_country: "".to_string(),
            issuer_state: "".to_string(),
            subject_state: "".to_string(),
            issuer_locality: "".to_string(),
            subject_locality: "".to_string(),
            issuer_organization: "".to_string(),
            not_after: Utc::now(),
            not_before: Utc::now(),
            is_valid: false,
            time_to_expiration: "".to_string(),
            subject_common_name: "".to_string(),
            subject_organization: "".to_string(),
        };

        let mut intermediate_cert = IntermediateCert {
            issuer_common_name: "".to_string(),
            signature_algorithm: "".to_string(),
            sans: vec![],
            issuer_country: "".to_string(),
            subject_country: "".to_string(),
            issuer_state: "".to_string(),
            subject_state: "".to_string(),
            issuer_locality: "".to_string(),
            subject_locality: "".to_string(),
            issuer_organization: "".to_string(),
            not_after: Utc::now(),
            not_before: Utc::now(),
            is_valid: false,
            time_to_expiration: "".to_string(),
            subject_common_name: "".to_string(),
            subject_organization: "".to_string(),
        };

        if let Some(certificates) = tls.sess.get_peer_certificates() {
            for certificate in certificates.iter() {
                let x509cert = match parse_x509_der(certificate.as_ref()) {
                    Ok((_, x509cert)) => x509cert,
                    Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
                };

                let is_ca = match x509cert.tbs_certificate.basic_constraints() {
                    Some((_, basic_constraints)) => basic_constraints.ca,
                    None => false,
                };

                //check if it's ca or not, if ca then insert to intermediate certificate
                if is_ca {
                    intermediate_cert.is_valid = x509cert.validity().is_valid();
                    intermediate_cert.not_after = Utc.timestamp(x509cert.tbs_certificate.validity.not_after.timestamp(), 0);
                    intermediate_cert.not_before = Utc.timestamp(x509cert.tbs_certificate.validity.not_before.timestamp(), 0);

                    match oid2sn(&x509cert.signature_algorithm.algorithm) {
                        Ok(s) => {
                            intermediate_cert.signature_algorithm = s.to_string();
                        }
                        Err(_e) => return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                    }


                    if let Some(time_to_expiration) = x509cert.tbs_certificate.validity.time_to_expiration() {
                        intermediate_cert.time_to_expiration = format!("{:?} day(s)", time_to_expiration.as_secs() / 60 / 60 / 24)
                    }

                    let issuer = x509cert.issuer();
                    let subject = x509cert.subject();

                    for rdn_seq in &issuer.rdn_seq {
                        match oid2sn(&rdn_seq.set[0].attr_type) {
                            Ok(s) => {
                                let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                match s {
                                    "C" => intermediate_cert.issuer_country = rdn_content,
                                    "ST" => intermediate_cert.issuer_state = rdn_content,
                                    "L" => intermediate_cert.issuer_locality = rdn_content,
                                    "CN" => intermediate_cert.issuer_common_name = rdn_content,
                                    "O" => intermediate_cert.issuer_organization = rdn_content,
                                    _ => {}
                                }
                            }
                            Err(_e) => return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                        }
                    }

                    for rdn_seq in &subject.rdn_seq {
                        match oid2sn(&rdn_seq.set[0].attr_type) {
                            Ok(s) => {
                                let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                match s {
                                    "C" => intermediate_cert.subject_country = rdn_content,
                                    "ST" => intermediate_cert.subject_state = rdn_content,
                                    "L" => intermediate_cert.subject_locality = rdn_content,
                                    "CN" => intermediate_cert.subject_common_name = rdn_content,
                                    "O" => intermediate_cert.subject_organization = rdn_content,
                                    _ => {}
                                }
                            }
                            Err(_e) => return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                        }
                    }
                } else {
                    server_cert.is_valid = x509cert.validity().is_valid();
                    server_cert.not_after = Utc.timestamp(x509cert.tbs_certificate.validity.not_after.timestamp(), 0);
                    server_cert.not_before = Utc.timestamp(x509cert.tbs_certificate.validity.not_before.timestamp(), 0);

                    match oid2sn(&x509cert.signature_algorithm.algorithm) {
                        Ok(s) => {
                            server_cert.signature_algorithm = s.to_string();
                        }
                        Err(_e) => return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                    }

                    if let Some((_, san)) = x509cert.tbs_certificate.subject_alternative_name() {
                        for name in san.general_names.iter() {
                            match name {
                                GeneralName::DNSName(dns) => {
                                    server_cert.sans.push(dns.to_string())
                                }
                                _ => {}
                            }
                        }
                    }


                    if let Some(time_to_expiration) = x509cert.tbs_certificate.validity.time_to_expiration() {
                        server_cert.time_to_expiration = format!("{:?} day(s)", time_to_expiration.as_secs() / 60 / 60 / 24)
                    }

                    let issuer = x509cert.issuer();
                    let subject = x509cert.subject();

                    for rdn_seq in &issuer.rdn_seq {
                        match oid2sn(&rdn_seq.set[0].attr_type) {
                            Ok(s) => {
                                let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                match s {
                                    "C" => server_cert.issuer_country = rdn_content,
                                    "ST" => server_cert.issuer_state = rdn_content,
                                    "L" => server_cert.issuer_locality = rdn_content,
                                    "CN" => server_cert.issuer_common_name = rdn_content,
                                    "O" => server_cert.issuer_organization = rdn_content,
                                    _ => {}
                                }
                            }
                            Err(_e) => return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                        }
                    }

                    for rdn_seq in &subject.rdn_seq {
                        match oid2sn(&rdn_seq.set[0].attr_type) {
                            Ok(s) => {
                                let rdn_content = rdn_seq.set[0].attr_value.content.as_str().unwrap().to_string();
                                match s {
                                    "C" => server_cert.subject_country = rdn_content,
                                    "ST" => server_cert.subject_state = rdn_content,
                                    "L" => server_cert.subject_locality = rdn_content,
                                    "CN" => server_cert.subject_common_name = rdn_content,
                                    "O" => server_cert.subject_organization = rdn_content,
                                    _ => {}
                                }
                            }
                            Err(_e) => return Err(Error::new(ErrorKind::Other, "Error converting Oid to Nid".to_string())),
                        }
                    }
                }
            }

            let cert = Cert {
                server: server_cert,
                intermediate: intermediate_cert,
            };

            Ok(cert)
        } else {
            Err(Error::new(ErrorKind::NotFound, "certificate not found".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_ssl_server_is_valid() {
        assert!(CheckSSL::from_domain("rust-lang.org").unwrap().server.is_valid);
    }

    #[test]
    fn test_check_ssl_server_is_invalid() {
        let actual = CheckSSL::from_domain("expired.badssl.com").map_err(|e| e.kind());
        let expected = Err(ErrorKind::InvalidData);

        assert_eq!(expected, actual);
    }
}
