use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::eventfd::{eventfd, EfdFlags};
use nix::unistd::{close, write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};

pub struct EventFd {
    fd: RawFd,
}

impl EventFd {
    pub fn new() -> Self {
        EventFd {
            fd: eventfd(0, EfdFlags::empty()).unwrap(),
        }
    }

    pub fn add(&self, v: i64) -> nix::Result<usize> {
        let b = v.to_le_bytes();
        write(self.fd, &b)
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

pub struct CancellableIncoming<'a> {
    listener: &'a TcpListener,
    eventfd: &'a EventFd,
}

impl<'a> CancellableIncoming<'a> {
    pub fn new(listener: &'a TcpListener, eventfd: &'a EventFd) -> Self {
        Self { listener, eventfd }
    }
}

impl<'a> Iterator for CancellableIncoming<'a> {
    type Item = std::io::Result<TcpStream>;
    fn next(&mut self) -> Option<std::io::Result<TcpStream>> {
        let fd = self.listener.as_raw_fd();
        let evfd = self.eventfd.as_raw_fd();
        let mut poll_fds = vec![
            PollFd::new(fd, PollFlags::POLLIN),
            PollFd::new(evfd, PollFlags::POLLIN),
        ];

        loop {
            match poll(&mut poll_fds, -1) {
                Ok(_) => break,
                Err(nix::Error::EINTR) => continue,
                _ => panic!("Error polling"),
            }
        }

        if poll_fds[0].revents().unwrap() == PollFlags::POLLIN {
            Some(self.listener.accept().map(|p| p.0))
        } else if poll_fds[1].revents().unwrap() == PollFlags::POLLIN {
            None
        } else {
            panic!("Can't be!");
        }
    }
}
