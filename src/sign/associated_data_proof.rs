use k256::{
    ecdsa::{
        signature::hazmat::PrehashVerifier, Signature, VerifyingKey,
    },
    elliptic_curve::{
        group::GroupEncoding, ops::Reduce, point::AffineCoordinates,
        subtle::ConstantTimeEq,
    },
    sha2::{Digest, Sha256},
    ProjectivePoint, Scalar, U256,
};

/// Associated-data proof: the untweaked nonce point `R'`.
pub struct AssociatedDataProof {
    /// Untweaked nonce point before associated-data scalar multiplication.
    pub big_r_prime: ProjectivePoint,
}

impl AssociatedDataProof {
    /// Verify an associated-data proof against a threshold ECDSA signature.
    pub fn verify(
        &self,
        vk: &VerifyingKey,
        message_hash: &[u8; 32],
        sign: &Signature,
        associated_data: &[u8],
    ) -> bool {
        if vk.verify_prehash(message_hash, sign).is_err() {
            return false;
        }

        let sig_bytes = sign.to_bytes();
        let (r_bytes, _) = sig_bytes.split_at(32);
        let r = Scalar::reduce(U256::from_be_slice(r_bytes));
        assert_eq!(r.is_zero().unwrap_u8(), 0);

        let ad_tweak = AssociatedDataProof::ro(&self.big_r_prime, associated_data);
        let big_r = self.big_r_prime * ad_tweak;
        let r_x = <Scalar as Reduce<U256>>::reduce_bytes(&big_r.to_affine().x());

        !bool::from(r_x.ct_ne(&r))
    }

    /// Hash-to-scalar for associated data: `H(R' || AD)`.
    pub fn ro(big_r: &ProjectivePoint, ad: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(big_r.to_bytes());
        hasher.update(ad);
        let digest: [u8; 32] = hasher.finalize().into();
        Scalar::reduce(U256::from_be_slice(&digest))
    }
}
