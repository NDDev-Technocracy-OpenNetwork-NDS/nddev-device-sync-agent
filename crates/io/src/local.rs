use crate::{CancellationToken, IoError, transport, valid_timeout};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

struct TimedSocket {
    socket: Socket,
    deadline: Instant,
    cancellation: CancellationToken,
}

impl TimedSocket {
    fn remaining(&self) -> std::io::Result<Duration> {
        if self.cancellation.is_cancelled() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}

impl Read for TimedSocket {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Err(setup_error) = self.socket.set_read_timeout(Some(self.remaining()?)) {
            // A closed peer can leave readable bytes even when timeout setup
            // fails. This socket has no clones: probe once in nonblocking mode,
            // then check restoring blocking mode before returning any bytes.
            self.socket.set_nonblocking(true)?;
            let result = self.remaining().and_then(|_| (&self.socket).read(buffer));
            self.socket.set_nonblocking(false)?;
            return match result {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(setup_error),
                result => result,
            };
        }
        (&self.socket).read(buffer)
    }
}

impl Write for TimedSocket {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        (&self.socket).write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A single bounded local protocol exchange. The deadline covers connect,
/// requests and all response frames; a slow peer cannot extend it byte by byte.
pub struct LocalChannel {
    stream: BufReader<TimedSocket>,
    frame_limit: usize,
}

impl LocalChannel {
    pub fn connect(
        path: &Path,
        timeout: Duration,
        frame_limit: usize,
        cancellation: CancellationToken,
    ) -> Result<Self, IoError> {
        if !path.is_absolute() || !valid_timeout(timeout) || !(1..=65_536).contains(&frame_limit) {
            return Err(IoError::InvalidConfiguration);
        }
        if cancellation.is_cancelled() {
            return Err(IoError::Cancelled);
        }
        let deadline = Instant::now() + timeout;
        let address = SockAddr::unix(path).map_err(transport)?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(transport)?;
        socket
            .connect_timeout(&address, timeout)
            .map_err(transport)?;
        Ok(Self {
            stream: BufReader::with_capacity(
                4096,
                TimedSocket {
                    socket,
                    deadline,
                    cancellation,
                },
            ),
            frame_limit,
        })
    }

    fn check(&self) -> Result<(), IoError> {
        let state = self.stream.get_ref();
        if state.cancellation.is_cancelled() {
            return Err(IoError::Cancelled);
        }
        if Instant::now() >= state.deadline {
            return Err(IoError::Timeout);
        }
        Ok(())
    }

    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), IoError> {
        self.check()?;
        if frame.len() >= self.frame_limit || frame.contains(&b'\n') {
            return Err(IoError::InvalidFrame);
        }
        let result = self
            .stream
            .get_mut()
            .write_all(frame)
            .and_then(|()| self.stream.get_mut().write_all(b"\n"));
        self.check()?;
        result.map_err(transport)
    }

    pub fn read_frame(&mut self) -> Result<Vec<u8>, IoError> {
        self.check()?;
        let mut frame = Vec::new();
        let read = (&mut self.stream)
            .take((self.frame_limit + 1) as u64)
            .read_until(b'\n', &mut frame);
        self.check()?;
        let read = read.map_err(transport)?;
        if read > self.frame_limit {
            return Err(IoError::OutputLimit);
        }
        if frame.pop() != Some(b'\n') {
            return Err(IoError::InvalidFrame);
        }
        Ok(frame)
    }

    /// Read one explicitly sized native clipboard representation. This cap is
    /// a client policy; it does not change the provider's archive policy.
    pub fn read_payload(&mut self, bytes: usize) -> Result<Vec<u8>, IoError> {
        self.check()?;
        if bytes > 1_048_576 {
            return Err(IoError::OutputLimit);
        }
        let mut payload = vec![0; bytes];
        let result = self.stream.read_exact(&mut payload);
        self.check()?;
        result.map_err(transport)?;
        Ok(payload)
    }
}
