use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;

const REVIEWER_NONCE_BYTES: usize = 32;

#[derive(Clone)]
pub struct ReviewerNonce([u8; REVIEWER_NONCE_BYTES]);

impl ReviewerNonce {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; REVIEWER_NONCE_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn matches(&self, candidate: &str) -> bool {
        if candidate.len() != 43 {
            return false;
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate) else {
            return false;
        };
        let Ok(decoded) = <[u8; REVIEWER_NONCE_BYTES]>::try_from(decoded) else {
            return false;
        };

        bool::from(self.0.ct_eq(&decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_nonce_round_trips_as_url_safe_base64_without_padding() {
        let nonce = ReviewerNonce::generate().expect("generate reviewer nonce");
        let encoded = nonce.encoded();

        assert_eq!(encoded.len(), 43);
        assert!(!encoded.contains('='));
        assert!(nonce.matches(&encoded));
        assert!(nonce.clone().matches(&encoded));
    }

    #[test]
    fn malformed_or_wrong_length_candidates_are_rejected() {
        let nonce = ReviewerNonce([7_u8; REVIEWER_NONCE_BYTES]);
        let too_short = URL_SAFE_NO_PAD.encode([7_u8; REVIEWER_NONCE_BYTES - 1]);
        let too_long = URL_SAFE_NO_PAD.encode([7_u8; REVIEWER_NONCE_BYTES + 1]);
        let padded = format!("{}=", nonce.encoded());

        assert!(!nonce.matches("not*base64"));
        assert!(!nonce.matches(&"*".repeat(43)));
        assert!(!nonce.matches(""));
        assert!(!nonce.matches(&too_short));
        assert!(!nonce.matches(&too_long));
        assert!(!nonce.matches(&padded));
    }

    #[test]
    fn different_nonce_is_rejected() {
        let nonce = ReviewerNonce([1_u8; REVIEWER_NONCE_BYTES]);
        let other = ReviewerNonce([2_u8; REVIEWER_NONCE_BYTES]);

        assert!(!nonce.matches(&other.encoded()));
    }
}
