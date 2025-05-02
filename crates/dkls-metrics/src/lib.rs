// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

pub mod dkg;
pub mod dsg;
pub mod flags;
pub mod key_refresh;
pub mod relay;

pub fn dkg_ranks(n: u8, ranks: &[u8]) -> Vec<u8> {
    ranks
        .iter()
        .chain(std::iter::repeat(&0u8))
        .take(n as usize)
        .cloned()
        .collect()
}
