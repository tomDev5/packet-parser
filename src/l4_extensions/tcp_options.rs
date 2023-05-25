use pnet::packet::tcp::{TcpOptionNumber, TcpOptionNumbers, TcpPacket};

#[derive(Debug, PartialEq)]
pub struct TcpOption<'a> {
    pub number: TcpOptionNumber,
    pub length: u8,
    pub data: &'a [u8],
}

impl<'a> TcpOption<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let number = TcpOptionNumber(bytes[0]);
        let length = match number {
            TcpOptionNumbers::EOL | TcpOptionNumbers::NOP => 0,
            _ => bytes[1],
        };
        let data = if length > 0 {
            &bytes[2..length as usize]
        } else {
            &[]
        };
        Some(TcpOption {
            number,
            length,
            data,
        })
    }
}

pub struct TcpOptionsIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> TcpOptionsIterator<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for TcpOptionsIterator<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let option = TcpOption::new(self.bytes)?;
        let total_length = match option.number {
            TcpOptionNumbers::EOL | TcpOptionNumbers::NOP => 1,
            _ => 2,
        } + option.data.len();
        self.bytes = &self.bytes[total_length..];
        Some(option)
    }
}

pub trait TcpZeroCopyOptionsIterator {
    fn get_options_zero_copy(&self) -> TcpOptionsIterator;
}

impl<'a> TcpZeroCopyOptionsIterator for TcpPacket<'a> {
    fn get_options_zero_copy(&self) -> TcpOptionsIterator {
        TcpOptionsIterator {
            bytes: self.get_options_raw(),
        }
    }
}

// todo support parsing tcp options payloads
