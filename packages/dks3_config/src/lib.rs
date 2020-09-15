use config::{Environment, File, FileFormat};
use rsa::{PublicKeyPemEncoding, RSAPrivateKey, RSAPublicKey};
use serde_derive::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::io::Write;
use std::path::Path;
use std::{fs, io};

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("Encountered an error in configuration: {0:#?}")]
    FormatError(config::ConfigError),

    #[error("Encountered a Toml syntax error in configuration: {0:#?}")]
    TomlError(toml::ser::Error),

    #[error("Encountered an error writing configuration to disk: {0:#?}")]
    WriteError(io::Error),
}

impl From<toml::ser::Error> for ConfigError {
    fn from(e: toml::ser::Error) -> Self {
        Self::TomlError(e)
    }
}

impl From<config::ConfigError> for ConfigError {
    fn from(e: config::ConfigError) -> Self {
        Self::FormatError(e)
    }
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        Self::WriteError(e)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Security {
    #[cfg(feature = "client")]
    public_key: String,

    #[cfg(feature = "server")]
    private_key: String,
}

impl Security {
    #[cfg(feature = "client")]
    pub fn public_key_pkcs1(&self) -> String {
        let pem = rsa::pem::parse(self.public_key.as_bytes()).expect("Public key is not valid PEM");

        RSAPublicKey::try_from(pem)
            .expect("Public key is not valid RSA key material")
            .to_pem_pkcs1()
            .expect("Public key is not encodable")
    }

    #[cfg(feature = "server")]
    pub fn private_key_pkcs1(&self) -> String {
        let pem =
            rsa::pem::parse(self.private_key.as_bytes()).expect("Private key is not valid PEM");

        RSAPrivateKey::try_from(pem)
            .expect("Private key is not valid RSA key material")
            .to_pem_pkcs1()
            .expect("Private key is not encodable")
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Server {
    hostname: String,

    #[cfg(feature = "server")]
    bind_address: String,
}

impl Server {
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_address
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    security: Security,
    server: Server,
}

pub struct ConfigBuilder {
    builder: config::Config,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        let mut builder = config::Config::new();

        // Merging env vars into the config builder should never fail.
        builder.merge(Environment::with_prefix("DKS3")).unwrap();
        builder.merge(Environment::with_prefix("DS3")).unwrap();

        Self { builder }
    }
}

impl ConfigBuilder {
    pub fn add_text<S>(mut self, text: S) -> Result<Self, ConfigError>
    where
        S: AsRef<str>,
    {
        self.builder
            .merge(File::from_str(text.as_ref(), FileFormat::Toml))?;

        Ok(self)
    }

    pub fn add_file<P>(mut self, path: P) -> Result<Self, ConfigError>
    where
        P: AsRef<Path>,
    {
        self.builder.merge(File::from(path.as_ref()))?;

        Ok(self)
    }

    pub fn build(self) -> Result<Config, ConfigError> {
        Ok(self.builder.try_into()?)
    }
}

impl Config {
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let toml = toml::to_string(self)?;
        let mut file = fs::File::create(path.as_ref())?;
        file.write_all(toml.as_bytes())?;

        Ok(())
    }

    pub fn security(&self) -> &Security {
        &self.security
    }

    pub fn server(&self) -> &Server {
        &self.server
    }
}

#[test]
pub fn test_read_config() {
    let config = ConfigBuilder::default()
        .add_text(
            r#"
[server]
hostname = "localhost"
bind_address = "127.0.0.1"

[security]
public_key = """
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwqgt5OxJs8x58vJE3XiqoGyG5Sc/fw8qaWztAE1U9qgGvFahyYAy
lbbrg6Fn+ZlueBRIJMPnisUIblZjlLR86s0XshP82pH4hBG9o6V7ntx3CcaYjw+M
be0NcNoUDMFv4/eLS6xK6xwxgZGfH5YA3sD2QfyBkAGnH6IXE+yfKt9T2pgY/jjI
CvDac3XKqq6nsOKm/Zij5nC0ZJJPB+uKlOmsSuPmo/K7RoSNaV6mch/W909HxR3W
gPCXiTlkXwpmncjhI0iCFPaJ4U5ElryetVMMcE/DWwFOIM88zfxIIFX0DvAsdMgo
1sPZ+2rQVzgaFR1LgHbbx1ppeEvCNHo+3wIDAQAB
-----END RSA PUBLIC KEY-----
"""

private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIDGgIBAAKCAQEAwqgt5OxJs8x58vJE3XiqoGyG5Sc/fw8qaWztAE1U9qgGvFah
yYAylbbrg6Fn+ZlueBRIJMPnisUIblZjlLR86s0XshP82pH4hBG9o6V7ntx3CcaY
jw+Mbe0NcNoUDMFv4/eLS6xK6xwxgZGfH5YA3sD2QfyBkAGnH6IXE+yfKt9T2pgY
/jjICvDac3XKqq6nsOKm/Zij5nC0ZJJPB+uKlOmsSuPmo/K7RoSNaV6mch/W909H
xR3WgPCXiTlkXwpmncjhI0iCFPaJ4U5ElryetVMMcE/DWwFOIM88zfxIIFX0DvAs
dMgo1sPZ+2rQVzgaFR1LgHbbx1ppeEvCNHo+3wIDAQABAoIBAQC1m+L1qd45eZRt
LctCNco7UgWo1i1Phf6zzYRwu7WBStK99LWNIaYQOFESxgwTuyptrb6BTqU/uwRa
rQ7LNnk1N5Pb+Pn3kiiiT0r22vWzCU2mOTssff0usfPQTiZWoEKcFeBIAb8EC5HE
qPAkr/av3KfkeIkIqgIaaUfOtvzpKUKqP4WR5hm1QIqdzGYsoWxDe/fALRsF4YbG
0hcEwIsuUhPhm+8CgvuNDwgbDq4SlIOQoMEP3JEZY/r2QCUkgZO2gOcOgRGKqtkC
psVUINOLOTXJ0Vnvxeqtu+27OvYCoaGPwC1Cnd0oBVL80Q5Yre5GZlE4jcGQ7F2g
ewHufosBAoGBAOGNP6sXh2NGzBidW3ik85mgpNq036ofY70jugCvhcFBG6G14r8i
5YYG6kj5twtw1PbJZrDZpKU/joBWG7jtht+UIoDImbF2z8BYlhXk2W9vT9tdLMrh
diWE1xHL7Qp/c7T143rjg9TzFNpmYDt8AmJdhQiakv1n5EbwADrHi0xPAoGBANzv
P+l1B7HBp9KOoRYhKh6fbiaaGCd8POkmjEg4ep7TzLE8epHsXDrorEyiNAtGJZID
wQ8HfCLLU5pJ4RjZ430oCzSlaLXXAdPCqozWGloQEOuYFKcT9GwV9oMi2RMZqsuR
n4wCGPP4LAWAdWqUJlCAegz57JoVLcrbQj2p9XBx
-----END RSA PRIVATE KEY-----"""
"#,
        )
        .and_then(|c| c.build())
        .unwrap();

    assert_eq!("localhost", config.server().hostname());
    assert_eq!("127.0.0.1", config.server().bind_addr());
    assert!(!config.security().public_key_pkcs1().is_empty());
    assert!(!config.security().private_key_pkcs1().is_empty());
}
