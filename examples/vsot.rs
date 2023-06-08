use sl_mpc_mate::{traits::Round, SessionId};
use sl_oblivious::vsot::{VSOTReceiver, VSOTSender};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rng = &mut rand::thread_rng();
    let session_id = SessionId::random(rng);

    let start = std::time::Instant::now();
    let sender = VSOTSender::new(session_id, 256, rng)?;
    let receiver = VSOTReceiver::new(session_id, 256, rng)?;
    let (sender, msg1) = sender.process(());
    let (receiver, msg2) = receiver.process(msg1)?;
    let (sender, msg3) = sender.process(msg2)?;
    let (receiver, msg4) = receiver.process(msg3)?;
    let (_sender_out, msg5) = sender.process(msg4)?;
    receiver.process(msg5)?;

    println!("Time: {:?}", start.elapsed());

    Ok(())
}
