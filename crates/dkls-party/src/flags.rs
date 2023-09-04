use super::SignHashFn;
use std::path::PathBuf;
use url::Url;

xflags::xflags! {
    cmd dkls23-party {
        repeated -v, --verbose

        /// Generate Ed25519 key and save to specified file.
        cmd gen-party-keys {
            /// File name to save generated keys
            required output: PathBuf
        }

        /// Load Ed25519 secret key output out as hex string.
        /// With option --public output public.
        cmd load-party-keys {
            required input: PathBuf
            optional --public
        }

        /// Create a DKG setup message
        cmd keygen-setup {
            /// Instance ID, hex
            required --instance inst: String

            /// Time To Live for a setup message
            required --ttl ttl: u32

            /// Theshold
            required -t,--threshold t: u8

            /// Ed25519 public key of the participant of key generation
            repeated --party parties: String

            /// Ed25519 key to sign the setup message
            required --sign sign: PathBuf

            /// Output of setup message
            required --output path: PathBuf
        }

        /// Participate as one or more parties in DKG protocol
        cmd key-gen {
            /// Name of file containing setup message
            required --setup setup: PathBuf

            /// Hex string of public key to verify the setup message
            required --setup-vk setup_vk: String

            /// Hex string of the instance ID
            required --instance instance: String

            /// Party public key.
            ///
            repeated --party party: String

            optional --prefix prefix: PathBuf

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }

        /// Load key share file file and extract the public key
        cmd share-pubkey {
            required share: PathBuf
        }

        ///
        cmd sign-setup {
            /// Instance ID, hex
            required --instance inst: String

            /// Time To Live for a setup message
            required --ttl ttl: u32

            /// Public key as hex string of distributed key to create a signature
            required --public-key public_key: String

            /// Ed25519 public key of the participant of key generation
            repeated --party party: String

            /// Ed25519 key to sign the setup message
            required --sign sign: PathBuf

            /// Message to sign
            required --message message: String

            /// Hash algorithm
            optional --hash-fn hash: SignHashFn

            /// Output of setup message
            required --output path: PathBuf

        }

        /// Participate as one or more parties in signature geneation protocol
        cmd sign-gen {
            /// Name of file containing setup message
            required --setup setup: PathBuf

            /// Hex string of public key to verify the setup message
            required --setup-vk setup_vk: String

            /// Hex string of the instance ID
            required --instance instance: String

            /// Party signing key.
            ///
            repeated --party party: String

            required --prefix prefix: PathBuf

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }

        cmd serve {
            /// Port to listen on, 8080 by default
            optional --port port: u16

            /// Interface to listne on, 0.0.0.0 by default
            optional --host host: String

            /// Listen on host:port. Ignore --port/--host options
            repeated --listen listen: String

            /// Base of URL of the coordinator service
            optional --coordinator url: Url
        }
    }
}
