// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::{marker::PhantomData, sync::Arc, time::Duration};

use signature::{SignatureEncoding, Signer, Verifier};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::{
    keygen::Keyshare,
    setup::{
        self,
        keys::{NoSignature, NoSigningKey, NoVerifyingKey},
        ProtocolParticipant,
    },
};

use sl_mpc_mate::message::InstanceId;

/// Default Time-To-Live (TTL) value for messages in seconds
const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

/// Module containing the setup message for the key exporter.
/// This module defines the message structure and functionality for the party
/// that exports a key in a multi-party computation protocol.
pub mod exporter;

/// Module containing the setup message for the key export receiver.
/// This module defines the message structure and functionality for the party
/// that receives an exported key in a multi-party computation protocol.
pub mod receiver;
