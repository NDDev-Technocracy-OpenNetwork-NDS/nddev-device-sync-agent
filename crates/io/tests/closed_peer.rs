#![cfg(unix)]

use nddev_device_sync_adapter_io::{CancellationToken, LocalChannel};
use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    time::Duration,
};

#[test]
fn a_payload_written_before_the_peer_closes_stays_readable() {
    let timeout = Duration::from_secs(5);
    // Keep the Unix socket address short even on hosts with a long TMPDIR.
    let directory = tempfile::Builder::new()
        .prefix("nds-io-peer-")
        .tempdir_in("/tmp")
        .unwrap();
    let path = directory.path().join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut channel =
        LocalChannel::connect(&path, timeout, 65_536, CancellationToken::new()).unwrap();
    // Connect has completed, so this listener already has its owned peer.
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(timeout)).unwrap();
    peer.set_write_timeout(Some(timeout)).unwrap();

    let request = b"{\"op\":\"status\"}";
    channel.send_frame(request).unwrap();
    let mut received = [0; 16];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"{\"op\":\"status\"}\n");
    peer.write_all(b"{\"bytes\":5}\n").unwrap();
    assert_eq!(channel.read_frame().unwrap(), b"{\"bytes\":5}");

    // Agent #130 / browser-use c369818: the payload cannot be in BufReader
    // yet. Write it only after read_frame, then fully close the peer before
    // read_payload. No sleeps or unjoined server thread decide the ordering.
    peer.write_all(b"hello").unwrap();
    drop(peer);
    let payload = channel.read_payload(5);
    drop(channel);

    // Observe the native timeout call separately from LocalChannel's typed
    // Transport mapping. Configure a bounded read before closing this peer;
    // the second call's outcome is evidence, not an assumed errno or fallback.
    let (mut client, mut peer) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(timeout)).unwrap();
    peer.set_write_timeout(Some(timeout)).unwrap();
    peer.write_all(b"hello").unwrap();
    drop(peer);
    let set_timeout = client.set_read_timeout(Some(timeout));
    let mut native_payload = [0; 5];
    let read = client.read_exact(&mut native_payload);
    eprintln!(
        "closed_peer_std os={} set_read_timeout_ok={} kind={:?} raw_os_error={:?}",
        std::env::consts::OS,
        set_timeout.is_ok(),
        set_timeout.as_ref().err().map(std::io::Error::kind),
        set_timeout
            .as_ref()
            .err()
            .and_then(std::io::Error::raw_os_error),
    );
    eprintln!(
        "closed_peer_std read_exact_ok={} kind={:?} raw_os_error={:?}; local_payload={:?}",
        read.is_ok(),
        read.as_ref().err().map(std::io::Error::kind),
        read.as_ref().err().and_then(std::io::Error::raw_os_error),
        payload.as_ref().map(Vec::len),
    );
    read.expect("std socket buffered payload after peer close");
    assert_eq!(&native_payload, b"hello");
    assert_eq!(
        payload.expect("LocalChannel buffered payload after peer close"),
        b"hello"
    );
}
