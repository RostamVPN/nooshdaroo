//! Bidirectional TCP relay between two AsyncRead+AsyncWrite streams.

use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

/// Copy data bidirectionally between two streams until one side closes.
/// Returns total bytes transferred in each direction.
pub async fn relay<A, B>(mut a: A, mut b: B) -> anyhow::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = io::split(&mut a);
    let (mut br, mut bw) = io::split(&mut b);

    let a_to_b = io::copy(&mut ar, &mut bw);
    let b_to_a = io::copy(&mut br, &mut aw);

    let (ab_result, ba_result) = tokio::join!(a_to_b, b_to_a);

    let up = ab_result.unwrap_or(0);
    let down = ba_result.unwrap_or(0);
    log::debug!("relay done: a→b={} b→a={}", up, down);

    // Shut down write sides.
    let _ = aw.shutdown().await;
    let _ = bw.shutdown().await;

    Ok((up, down))
}
