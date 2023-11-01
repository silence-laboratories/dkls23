use std::time::Duration;

use crate::setup::ABORT_MESSAGE_TAG;
use sl_mpc_mate::message::*;

fn abort_message_id(instance: &InstanceId, sender_vk: &VerifyingKey) -> MsgId {
    MsgId::new(instance, sender_vk.as_bytes(), None, ABORT_MESSAGE_TAG)
}

/// Create an Abort Message.
pub fn create_abort_message(instance: &InstanceId, ttl: Duration, signing_key: &SigningKey) -> Vec<u8> {
    let sender_vk = signing_key.verifying_key();

    let msg_id = abort_message_id(instance, &sender_vk);

    Builder::<Signed>::encode(
        &msg_id,
        ttl,
        signing_key,
        &(), // emoty message
    )
    .unwrap() // can't fail, because &() is always encodable
}
