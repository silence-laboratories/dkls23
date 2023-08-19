///!
///

use sl_mpc_mate::message::MessageTag;

/// Tag for all setup messages
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Magic designates a particular MPC protocol
pub enum Magic {
    /// Distributed Key generation
    DKG = 1,

    /// Distributed Signature Generation
    DSG = 2,
}

/// Setup for DKG
pub mod keygen;

// /// Setup for DSG
// pub mod sign;
