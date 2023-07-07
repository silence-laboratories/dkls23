use super::SignHashFn;
use std::path::PathBuf;
use url::Url;

xflags::xflags! {
    cmd dkls23-party {
        repeated -v, --verbose

        /// Generate reusable set of keys for key generation protocol
        cmd party-keys {
            /// File name to save generated keys
            required path: PathBuf
        }

        /// Participate as one or more parties in DKG protocol
        cmd key-gen {
            /// Party descriptor in form:
            ///   session-id:share:party-keys-file:rank
            ///
            /// Provide this option for each party
            repeated --party party: String

            /// Number of parties
            required --n n: u8

            /// Theshold
            required --t t: u8

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }

        /// Load key share file file and extract the public key
        cmd share-pubkey {
            required share: PathBuf
        }

        /// Participate as one or more parties in signature geneation protocol
        cmd sign-gen {
            required --message message: String

            /// Party descriptor in form:
            ///  session-id:keyshare-file:signture-file
            repeated --party party: String

            /// Total number of parties, threshold
            required --t t: u8

            optional --hash-fn hash_fn: SignHashFn

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }

        /// Register session and output N session IDs for a DKG
        cmd key-sess {
            /// Number of parties
            required --n n: u8
            /// Threshold
            required --t t: u8

            /// Base of URL of the coordinator service
            optional --coordinator url: Url

            /// Lifetime of the session in seconds
            optional --lifetime lifetime: u32
        }

        /// Register session and output T session IDs for signature
        /// generation protocol
        cmd sign-sess {
            /// Number of parties, threshold
            required --t t: u8

            /// Message to sign
            required --message message: String

            /// Base of URL of the coordinator service
            optional --coordinator url: Url

            /// Lifetime of the session in seconds
            optional --lifetime lifetime: u32
        }

        /// Session details
        cmd session {
            required id: String
            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }

        cmd serve {
            /// Port to listen on, 8080 by default
            optional --port port: u16

            /// Interface to listne on, 0.0.0.0 by default
            optional --host host: String

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }
    }
}
