// Times the pure Rust MJPEG encoder on a 1080p frame.
mod jpeg;
use std::time::Instant;

fn main() {
    let width = 1920usize;
    let height = 1080usize;
    let y: Vec<u8> = (0..width * height).map(|i| ((i * 7) % 251) as u8).collect();
    let u = vec![100u8; width * height / 4];
    let v = vec![160u8; width * height / 4];
    for round in 0..3 {
        let start = Instant::now();
        let out = jpeg::encode_yuv420(width, height, 75, &y, width, &u, width / 2, &v, width / 2);
        let bytes = out.map(|data| data.len()).unwrap_or(0);
        println!(
            "round {round}: {:?} bytes={bytes}",
            start.elapsed()
        );
    }
}
