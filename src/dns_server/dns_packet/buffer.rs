pub mod buffer {
    const JUMP_MASK: u8 = 0b1100_0000;
    const MAX_JUMPS: i32 = 5;

    use std::{io};
    use std::io::{Error, ErrorKind};
    use std::mem::size_of;

    pub struct BufferParser<'a> {
        buf_view: &'a[u8],
        position : usize
    }

    impl<'a> BufferParser<'a> {
        pub fn new(buf_view: &'a [u8]) -> Self {
            BufferParser {
                buf_view,
                position: 0,
            }
        }
        pub fn seek(&mut self, pos: usize) {
            self.position = pos;
        }

        pub fn get_pos(&self) -> usize {
            self.position
        }

        pub fn get(&self, pos: usize) -> io::Result<u8> {
            if pos >= self.buf_view.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }
            Ok(self.buf_view[pos])
        }

        pub fn get_u16(&self, pos: usize) -> io::Result<u16> {
            let size_of_type = size_of::<u16>();
            if pos + size_of_type > self.buf_view.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }
            let slice = &self.buf_view[pos..pos + size_of_type];
            Ok(u16::from_be_bytes(slice.try_into().unwrap()))
        }

        pub fn get_u32(&self, pos: usize) -> io::Result<u32> {
            let size_of_type = size_of::<u32>();
            if pos + size_of_type > self.buf_view.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }
            let slice = &self.buf_view[pos..pos + size_of_type];
            Ok(u32::from_be_bytes(slice.try_into().unwrap()))
        }

        pub fn get_u128(&self, pos: usize) -> io::Result<u128> {
            let size_of_type = size_of::<u128>();
            if pos + size_of_type > self.buf_view.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }
            let slice = &self.buf_view[pos..pos + size_of_type];
            Ok(u128::from_be_bytes(slice.try_into().unwrap()))
        }

        pub fn get_range(&self, begin: usize, len: usize) -> io::Result<&[u8]> {
            if begin + len >= self.buf_view.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }
            Ok(&self.buf_view[begin..begin + len])
        }

        pub fn read(&mut self) -> io::Result<u8> {
            let result = self.get(self.position)?;
            self.position += 1;
            Ok(result)
        }

        pub fn read_u16(&mut self) -> io::Result<u16> {
            let result = self.get_u16(self.position)?;
            self.position += 2;
            Ok(result)
        }
        pub fn read_u32(&mut self) -> io::Result<u32> {
            let result = self.get_u32(self.position)?;
            self.position += 4;
            Ok(result)
        }

        pub fn read_u128(&mut self) -> io::Result<u128> {
            let result = self.get_u128(self.position)?;
            self.position += 16;
            Ok(result)
        }

        pub fn read_name(&mut self) -> io::Result<String> {
            let mut name = String::new();
            let mut local_pos = self.position;

            let mut jump_counter = 0;

            loop {
                if jump_counter > MAX_JUMPS {
                    return Err(Error::new(ErrorKind::InvalidInput, "reached max amount of jumps"));
                }

                let len = self.get(local_pos)?;

                if (JUMP_MASK & len) == JUMP_MASK {
                    if jump_counter == 0 {
                        self.seek(local_pos + 2);
                    }

                    let offset = self.get_u16(local_pos)? & !((JUMP_MASK as u16) << 8);
                    local_pos = offset as usize;

                    jump_counter += 1;
                    continue;
                } else {
                    local_pos += 1;

                    if len == 0 {
                        break;
                    }

                    let str_buffer = self.get_range(local_pos, len as usize)?;
                    name += &*String::from_utf8_lossy(str_buffer).to_lowercase();
                    name += ".";

                    local_pos += len as usize;
                }
            }

            if jump_counter == 0 {
                self.seek(local_pos);
            }
            if !name.is_empty() {
                name.pop();
            }
            Ok(name)
        }
    }

    pub struct BufferBuilder<'a> {
        pub(crate) buf_view: &'a mut [u8],
        position: usize,
    }

    impl<'a> BufferBuilder<'a> {
        pub fn new(buf_view: &'a mut [u8]) -> Self {
            BufferBuilder {
                buf_view,
                position: 0,
            }
        }

        pub fn seek(&mut self, pos: usize) {
            self.position = pos;
        }

        pub fn get_pos(&self) -> usize {
            self.position
        }

        fn ensure_space(&self, len: usize) -> io::Result<()> {
            if self.position + len > self.buf_view.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }
            Ok(())
        }

        pub fn write(&mut self, val: u8) -> io::Result<()> {
            self.ensure_space(1)?;
            self.buf_view[self.position] = val;
            self.position += 1;
            Ok(())
        }

        pub fn write_u16(&mut self, val: u16) -> io::Result<()> {
            self.ensure_space(2)?;
            let bytes = val.to_be_bytes();
            self.buf_view[self.position..self.position + 2].copy_from_slice(&bytes);
            self.position += 2;
            Ok(())
        }

        pub fn set_u16(&mut self, val: u16, pos: usize) -> io::Result<()> {
            self.ensure_space(2)?;
            let bytes = val.to_be_bytes();
            self.buf_view[pos..pos + 2].copy_from_slice(&bytes);
            Ok(())
        }

        pub fn write_u32(&mut self, val: u32) -> io::Result<()> {
            self.ensure_space(4)?;
            let bytes = val.to_be_bytes();
            self.buf_view[self.position..self.position + 4].copy_from_slice(&bytes);
            self.position += 4;
            Ok(())
        }

        pub fn write_u128(&mut self, val: u128) -> io::Result<()> {
            self.ensure_space(16)?;
            let bytes = val.to_be_bytes();
            self.buf_view[self.position..self.position + 16].copy_from_slice(&bytes);
            self.position += 16;
            Ok(())
        }

        pub fn write_name(&mut self, name: &str) -> io::Result<()> {
            for label in name.split('.') {
                let len = label.len();
                if len > 63 {
                    return Err(Error::new(ErrorKind::InvalidInput, "Label too long"));
                }
                self.write(len as u8)?;
                self.ensure_space(len)?;
                self.buf_view[self.position..self.position + len].copy_from_slice(label.as_bytes());
                self.position += len;
            }
            self.write(0)?; // Write null byte to terminate the name
            Ok(())
        }
    }
}


