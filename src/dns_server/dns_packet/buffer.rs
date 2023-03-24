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


    #[test]
    fn test_read_u16() {
/*        let b1: u8 = 0b1000_000;
        let b2: u8 = 0b0001_000;
        let result = b1 as u16 << 8 | b2 as u16
*/
    }

}

