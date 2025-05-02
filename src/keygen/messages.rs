// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use sl_oblivious::{endemic_ot::EndemicOTMsg2, soft_spoken::PPRFOutput};

use crate::proto::*;

/// Type for the key generation protocol's message 3. P2P
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
#[allow(missing_docs)]
pub struct KeygenMsg3 {
    pub d_i: ScalarBytes,

    pub base_ot_msg2: EndemicOTMsg2,

    pub pprf_output: PPRFOutput,

    pub chain_code_sid: [u8; 32],

    /// Random 32 bytes
    pub r_i_2: [u8; 32],

    /// seed_i_j values
    pub seed_i_j: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<KeygenMsg3>() == 1);

/// Type for the Quorum change protocol's message P2P 1
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
#[allow(missing_docs)]
pub struct QCP2PMsg1 {
    pub commitment_2_i: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<QCP2PMsg1>() == 1);

/// Type for the Quorum change protocol's message P2P 2
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
#[allow(missing_docs)]
pub struct QCP2PMsg2 {
    pub p_i: ScalarBytes,
    pub r_2_i: [u8; 32],
    pub root_chain_code: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<QCP2PMsg2>() == 1);

/// Type for the Quorum change protocol's P2P OT message 2
#[derive(Clone, Copy, bytemuck::AnyBitPattern, bytemuck::NoUninit)]
#[repr(C)]
#[allow(missing_docs)]
pub struct QCOTMsg2 {
    pub base_ot_msg2: EndemicOTMsg2,

    pub pprf_output: PPRFOutput,

    /// seed_i_j values
    pub seed_i_j: [u8; 32],
}

const _: () = assert!(core::mem::align_of::<QCOTMsg2>() == 1);
