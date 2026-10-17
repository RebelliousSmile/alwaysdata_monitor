//! Origines admises d'une source : liste blanche codée en dur (schéma
//! `https`, hôte, port), jamais lue dans la configuration ni dans la
//! réponse d'un tiers. L'origine entière est comparée, pas l'hôte seul : un
//! autre port du même hôte n'est pas admis.

use url::Url;

use super::SyncError;

/// Origine `https://<hôte>:<port>`, hôte en minuscules, port explicite ou
/// 443.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Origine d'une URL ; refusée si le schéma n'est pas `https` ou si
    /// l'URL porte des identifiants (`user:pass@`).
    pub fn of(url: &Url) -> Result<Self, SyncError> {
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(SyncError::OriginRefused);
        }
        let host = url.host_str().ok_or(SyncError::OriginRefused)?;
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port: url.port_or_known_default().unwrap_or(443),
        })
    }
}

/// Liste fermée des origines d'une source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origins(Vec<Origin>);

impl Origins {
    /// Liste codée en dur d'une source (`SourceMeta.origins`).
    pub fn fixed(list: &[(&str, u16)]) -> Self {
        Self(
            list.iter()
                .map(|(host, port)| Origin {
                    host: host.to_ascii_lowercase(),
                    port: *port,
                })
                .collect(),
        )
    }

    /// Origines épinglées par les tests (`SyncOptions::endpoint_override`) :
    /// elles remplacent celles de la source.
    pub fn pinned(urls: &[&Url]) -> Result<Self, SyncError> {
        urls.iter()
            .map(|u| Origin::of(u))
            .collect::<Result<_, _>>()
            .map(Self)
    }

    /// Origine de l'URL si elle est admise.
    pub fn admit(&self, url: &Url) -> Result<Origin, SyncError> {
        let origin = Origin::of(url)?;
        if self.0.contains(&origin) {
            Ok(origin)
        } else {
            Err(SyncError::OriginRefused)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("url")
    }

    #[test]
    fn whole_origin_is_compared() {
        let origins = Origins::fixed(&[("dumps.example.org", 443)]);
        assert!(
            origins
                .admit(&url("https://dumps.example.org/a/all.zip"))
                .is_ok()
        );
        assert!(
            origins
                .admit(&url("https://DUMPS.example.org:443/x"))
                .is_ok()
        );
        for bad in [
            "http://dumps.example.org/all.zip",
            "https://dumps.example.org:8443/all.zip",
            "https://autre.example.org/all.zip",
            "https://dumps.example.org.example.net/all.zip",
            "https://user:pass@dumps.example.org/all.zip",
            "https://user@dumps.example.org/all.zip",
        ] {
            assert_eq!(
                origins.admit(&url(bad)),
                Err(SyncError::OriginRefused),
                "{bad}"
            );
        }
    }

    #[test]
    fn pinned_origins_keep_their_port() {
        let a = url("https://192.0.2.10:8443/");
        let origins = Origins::pinned(&[&a]).expect("épinglée");
        assert!(
            origins
                .admit(&url("https://192.0.2.10:8443/all.zip"))
                .is_ok()
        );
        assert!(origins.admit(&url("https://192.0.2.10/all.zip")).is_err());
    }
}
