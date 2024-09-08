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

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

/// Setup message for key exporter
pub mod exporter;

/// Setup message for key export receiver
pub mod receiver;
