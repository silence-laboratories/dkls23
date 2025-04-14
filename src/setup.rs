// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//!
//! Protocol setup message
//!

use std::time::Duration;

use derivation_path::DerivationPath;
use k256::ProjectivePoint;
pub use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::{InstanceId, MessageTag, MsgId};

use crate::{keygen::Keyshare, sign::PreSign};

/// Tag for all setup messages
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Tag of a broadcast message indicating that sender
/// won't participate in the protocol. The payload of
/// the message contains error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

/// An iterator for parties in range 0..total except me.
pub struct AllOtherParties {
    total: usize,
    me: usize,
    curr: usize,
}

impl Iterator for AllOtherParties {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let val = self.curr;

            if val >= self.total {
                return None;
            }

            self.curr += 1;

            if val != self.me {
                return Some(val);
            }
        }
    }
}

impl ExactSizeIterator for AllOtherParties {
    fn len(&self) -> usize {
        self.total - 1
    }
}

/// Type that provides a protocol participant details.
pub trait ProtocolParticipant {
    /// Type of a signature, added at end of all broadcast messages
    /// passed between participants.
    type MessageSignature: SignatureEncoding;

    /// Type to sign broadcast messages, some kind of SecretKey.
    type MessageSigner: Signer<Self::MessageSignature>;

    /// Type to verify signed message, a verifying key. AsRef<[u8]> is
    /// used to get external representation of the key to derive
    /// message ID.
    type MessageVerifier: Verifier<Self::MessageSignature> + AsRef<[u8]>;

    /// Return total number of participants of a distributed protocol.
    fn total_participants(&self) -> usize;

    /// Return a verifying key for a messages from a participant with
    /// given index.
    fn verifier(&self, index: usize) -> &Self::MessageVerifier;

    /// A signer to sign messages from the participant.
    fn signer(&self) -> &Self::MessageSigner;

    /// Return an index of the participant in a protocol.
    /// This is a value in range 0..self.total_participants()
    fn participant_index(&self) -> usize;

    /// Each execution of a distributed protocol requires
    /// a unique instance id to derive all IDs of messages.
    fn instance_id(&self) -> &InstanceId;

    /// Return message Time To Live.
    fn message_ttl(&self) -> Duration;

    /// Return reference to participant's own verifier
    fn participant_verifier(&self) -> &Self::MessageVerifier {
        self.verifier(self.participant_index())
    }

    /// Return iterator of all participant's indexes except own one.
    fn all_other_parties(&self) -> AllOtherParties {
        AllOtherParties {
            curr: 0,
            total: self.total_participants(),
            me: self.participant_index(),
        }
    }

    /// Generate ID of a message from this party to some other (or broadcast)
    /// if passed receiver is None.
    fn msg_id(&self, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        self.msg_id_from(self.participant_index(), receiver, tag)
    }

    /// Generate ID of a message from given sender to a given
    /// receiver.  Receiver is designed by its index and is None for a
    /// broadcase message.
    fn msg_id_from(
        &self,
        sender: usize,
        receiver: Option<usize>,
        tag: MessageTag,
    ) -> MsgId {
        let receiver = receiver
            .map(|p| self.verifier(p))
            .map(AsRef::<[u8]>::as_ref);

        MsgId::new(
            self.instance_id(),
            self.verifier(sender).as_ref(),
            receiver.as_ref().map(AsRef::as_ref),
            tag,
        )
    }
}

impl<M: ProtocolParticipant> ProtocolParticipant for &M {
    type MessageSignature = M::MessageSignature;
    type MessageSigner = M::MessageSigner;
    type MessageVerifier = M::MessageVerifier;

    fn total_participants(&self) -> usize {
        (**self).total_participants()
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        (**self).verifier(index)
    }

    fn signer(&self) -> &Self::MessageSigner {
        (**self).signer()
    }

    fn participant_index(&self) -> usize {
        (**self).participant_index()
    }

    fn participant_verifier(&self) -> &Self::MessageVerifier {
        (**self).participant_verifier()
    }

    fn instance_id(&self) -> &InstanceId {
        (**self).instance_id()
    }

    fn message_ttl(&self) -> Duration {
        (**self).message_ttl()
    }
}

/// A setup message for keygen::run()
pub trait KeygenSetupMessage: ProtocolParticipant {
    /// Threshold parameter.
    fn threshold(&self) -> u8;

    /// Return a rank of a participat with given index.
    /// May panic is index is out of range.
    fn participant_rank(&self, _party_index: usize) -> u8 {
        0
    }

    /// Derive key_id from a public_key.
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32];

    /// Additional data to incorpatate into resulting Keyshare.
    fn keyshare_extra(&self) -> &[u8] {
        &[]
    }
}

impl<M: KeygenSetupMessage> KeygenSetupMessage for &M {
    fn threshold(&self) -> u8 {
        (**self).threshold()
    }

    fn participant_rank(&self, party_index: usize) -> u8 {
        (**self).participant_rank(party_index)
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        (**self).derive_key_id(public_key)
    }

    fn keyshare_extra(&self) -> &[u8] {
        (**self).keyshare_extra()
    }
}

/// A setup message for sign::pre_signature()
pub trait PreSignSetupMessage: ProtocolParticipant {
    /// A shared reference to a Keyshare.
    fn keyshare(&self) -> &Keyshare;

    /// Key chain path for this signature
    fn chain_path(&self) -> &DerivationPath;

    /// Additional data to incorpatate into resulting PreSignature.
    fn presignature_extra(&self) -> &[u8] {
        &[]
    }
}

/// A setup message for sign::finish()
pub trait FinalSignSetupMessage: ProtocolParticipant {
    /// Pre-signature created by sign::pre_signature()
    fn pre_signature(&self) -> &PreSign;

    /// Hash of a message to sign.
    fn message_hash(&self) -> [u8; 32];
}

/// A setup message for sign::run()
pub trait SignSetupMessage: PreSignSetupMessage {
    /// Hash of a message to sign.
    fn message_hash(&self) -> [u8; 32];
}

/// A setup message for key export.
pub trait KeyExporterSetupMessage<PK, KS>: ProtocolParticipant {
    /// Public key of a receiver party.
    fn receiver_public_key(&self) -> &PK;

    /// A shared reference to a Keyshare.
    fn keyshare(&self) -> &KS;
}

/// A setup message for a reciever of exported key.
pub trait KeyExportReceiverSetupMessage<SK>: ProtocolParticipant {
    /// Private key to decrypt P2P messages.
    fn receiver_private_key(&self) -> &SK;

    /// A shared reference to a Keyshare.
    fn keyshare(&self) -> &Keyshare;
}

/// A setup message for quorum_change::run()
pub trait QuorumChangeSetupMessage<KS, PK>: ProtocolParticipant {
    /// A shared reference to a Keyshare.
    fn old_keyshare(&self) -> Option<&KS>;

    /// New threshold parameter.
    fn new_threshold(&self) -> u8;

    /// New participant rank. Panics is `party_id` is out of range.
    fn new_participant_rank(&self, _party_id: u8) -> u8 {
        0
    }

    /// Expected public key.
    fn expected_public_key(&self) -> &PK;

    /// return new_party_id by party_index
    fn new_party_id(&self, index: usize) -> Option<u8> {
        self.new_party_indices()
            .iter()
            .position(|p| p == &index)
            .map(|p| p as u8)
    }

    /// list of old party indices
    fn old_party_indices(&self) -> &[usize];

    /// List of indices of new parties in a list of protocol
    /// participants. Order of indices defines assignment of party-id
    /// to new key shares.
    fn new_party_indices(&self) -> &[usize];

    /// Additional data to incorpatate into resulting Keyshare.
    fn keyshare_extra(&self) -> &[u8] {
        &[]
    }

    /// Derive key_id from a public_key.
    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32];
}

impl<KS, PK, M: QuorumChangeSetupMessage<KS, PK>>
    QuorumChangeSetupMessage<KS, PK> for &M
{
    fn old_keyshare(&self) -> Option<&KS> {
        (**self).old_keyshare()
    }

    fn new_threshold(&self) -> u8 {
        (**self).new_threshold()
    }

    fn expected_public_key(&self) -> &PK {
        (**self).expected_public_key()
    }

    fn old_party_indices(&self) -> &[usize] {
        (**self).old_party_indices()
    }

    fn new_party_indices(&self) -> &[usize] {
        (**self).new_party_indices()
    }

    fn derive_key_id(&self, public_key: &[u8]) -> [u8; 32] {
        (**self).derive_key_id(public_key)
    }
}

/// Setup for DKG
pub mod keygen;

/// Setup for DSG
pub mod sign;

/// Setup for Finish PreSignature
pub mod finish;

/// Setup for Key export
pub mod key_export;

pub use keys::*;

mod keys;

/// Setup for Quorum Change
pub mod quorum_change;
