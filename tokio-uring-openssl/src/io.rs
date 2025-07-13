use tokio_uring::{
    BufResult,
    buf::{BoundedBuf, BoundedBufMut},
    net::TcpStream,
};

#[allow(async_fn_in_trait)]
pub trait AsyncRead {
    async fn read<B: BoundedBufMut>(&mut self, buf: B) -> BufResult<usize, B>;
}

#[allow(async_fn_in_trait)]
pub trait AsyncWrite {
    async fn write_all<T: BoundedBuf>(&self, buf: T) -> BufResult<(), T>;
}

pub struct UTcpStream(pub TcpStream);

impl AsyncRead for UTcpStream {
    async fn read<B: BoundedBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        self.0.read(buf).await
    }
}

impl AsyncWrite for UTcpStream {
    async fn write_all<T: BoundedBuf>(&self, buf: T) -> BufResult<(), T> {
        self.0.write_all(buf).await
    }
}

// turn async stream in to sync
pub struct SyncStream {
    // buff containers saved content to be read.
    read_buf: Buffer,
    // buff contains data to be flushed.
    write_buf: Buffer,
    temp_buf: Option<Vec<u8>>, // fixed length
    eof: bool,
}

impl SyncStream {
    pub fn create() -> Self {
        Self {
            read_buf: Buffer::create(),
            write_buf: Buffer::create(),
            temp_buf: Some(vec![0; 1024]),
            eof: false,
        }
    }
}

// impl std sync apis
impl std::io::Read for SyncStream {
    // read from buffer
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        debug_assert!(!buf.is_empty());
        // assume infallible.
        let len = self.read_buf.read(buf);
        // println!("sync read {len}");
        if len == 0 {
            if self.eof {
                // signal sync api eof
                Ok(0)
            } else {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        } else {
            Ok(len)
        }
    }
}

impl std::io::Write for SyncStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.write_buf.write(buf);
        // println!("sync write {len}");
        if len == 0 {
            // This does not happen.
            // buff is filled up, caller needs to flush from lower layer.
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // does not flush directly.
        Ok(())
    }
}

impl SyncStream {
    /// read the async stream and fill the buf memory.
    pub async fn fill_read_buf(&mut self, s: &mut impl AsyncRead) -> std::io::Result<()> {
        // let pos = self.read_buf.position() as usize;
        // let data = self.read_buf.get_mut();
        // let buf = &data[pos..];
        // assert!(buf.len() != 0);

        // read into a temp vec first. tokio does not support variable write.
        let buf = self.temp_buf.take().unwrap();
        let (res, bufback) = s.read(buf).await;
        self.temp_buf = Some(bufback);
        let res = res?;
        if res == 0 {
            println!("eof read");
            self.eof = true;
            return Ok(());
        }
        // println!("filled read {res}");
        // copy the tempbuf into read buf
        let temp_slice = &self.temp_buf.as_ref().unwrap()[0..res];
        self.read_buf.write(temp_slice);
        Ok(())
    }

    // flush write buffer in to stream.
    pub async fn flush_write_buf(&mut self, s: &mut impl AsyncWrite) -> std::io::Result<usize> {
        let v = self.write_buf.read_all_data();
        let len = v.len();
        let (res, _) = s.write_all(v).await;
        res?;

        // println!("flush write {}", len);
        Ok(len)
    }
}

pub struct Buffer {
    data: Vec<u8>,
    read_pos: usize,
    capacity: usize,
    // write_pos:usize,
}

impl Buffer {
    pub fn create() -> Self {
        Self {
            data: Vec::with_capacity(1024),
            read_pos: 0,
            capacity: 1024,
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        self.shrink(self.capacity);
        self.data.extend_from_slice(buf);
        buf.len()
    }

    // copy data into buf, advance the read position.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let s = &self.data[self.read_pos..];
        let read = std::cmp::min(buf.len(), s.len());
        let src = &s[..read];
        let dest = &mut buf[..read];
        dest.copy_from_slice(src);
        self.read_pos += read;
        read
    }

    // get all remaining
    pub fn read_all_data(&mut self) -> Vec<u8> {
        let s = self.data[self.read_pos..].to_vec();
        self.read_pos = self.data.len();
        self.shrink(0);
        s
    }

    // shrink to save space
    pub(crate) fn shrink(&mut self, thresh: usize) {
        if self.read_pos > thresh {
            self.data.drain(..self.read_pos);
            self.read_pos = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use crate::io::Buffer;

    #[test]
    fn test_cursor() {
        let mut c = Cursor::new(Vec::new());
        c.write_all("hello".as_bytes()).unwrap();
        let mut buf = [0_u8; 100];
        c.set_position(0);
        let len = c.read(buf.as_mut_slice()).unwrap();
        assert_eq!(len, 5);
    }

    #[test]
    fn test_buffer() {
        let mut b = Buffer::create();
        let mut buf = [0_u8; 100];
        let len = b.read(buf.as_mut_slice());
        assert_eq!(len, 0);

        b.write("hello".as_bytes());
        let len = b.read(buf.as_mut_slice());
        assert_eq!(len, 5);
        assert_eq!(&buf[0..5], "hello".as_bytes());

        let v = b.read_all_data();
        assert!(v.is_empty());

        {
            let mut buf = [0_u8; 3];
            b.write("hello".as_bytes());
            let len = b.read(buf.as_mut_slice());
            assert_eq!(len, 3);
            b.shrink(1);
            let len = b.read(buf.as_mut_slice());
            assert_eq!(len, 2);
            assert_eq!(&buf[0..2], "lo".as_bytes());
        }
    }
}
