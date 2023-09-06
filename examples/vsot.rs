use sl_mpc_mate::SessionId;
use sl_oblivious::vsot::{VSOTReceiver, VSOTSender};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let session_id = SessionId::random(&mut rng);

    let start = std::time::Instant::now();

    let (sender, msg1) = VSOTSender::new(session_id, &mut rng);

    let rec = VSOTReceiver::new(session_id, &mut rng);

    let (rec, msg2) = rec.process(msg1).unwrap();

    let (sender, msg3) = sender.process(msg2).unwrap();

    let (rec, msg4) = rec.process(msg3).unwrap();

    let (_sender_output, msg5) = sender.process(msg4).unwrap();

    rec.process(msg5)?;

    println!("Time: {:?}", start.elapsed());

    Ok(())
}
