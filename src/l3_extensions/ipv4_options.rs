use pnet::packet::ipv4::{Ipv4OptionNumber, Ipv4OptionNumbers, Ipv4Packet};

#[derive(Debug, PartialEq)]
pub struct Ipv4Option<'a> {
    pub copied: bool,
    pub class: u8,
    pub number: Ipv4OptionNumber,
    pub length: u8,
    pub data: &'a [u8],
}

impl<'a> Ipv4Option<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let byte1 = bytes.first()?;
        let copied = (byte1 & 0x80) != 0;
        let class = (byte1 & 0x60) >> 5;
        let number = Ipv4OptionNumber(byte1 & 0x1f);
        Some(match number {
            Ipv4OptionNumbers::EOL | Ipv4OptionNumbers::NOP => Self {
                copied,
                class,
                number,
                length: 1,
                data: &[],
            },
            number => {
                let length = *bytes.get(1)?;
                Self {
                    copied,
                    class,
                    number,
                    length,
                    data: bytes.get(2..length as usize)?,
                }
            }
        })
    }
}

pub struct Ipv4OptionsIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv4OptionsIterator<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for Ipv4OptionsIterator<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let option = Ipv4Option::new(self.bytes)?;
        self.bytes = self.bytes.get(option.length.into()..)?;
        Some(option)
    }
}

pub trait Ipv4ZeroCopyOptionsIterator {
    fn get_options_zero_copy(&self) -> Ipv4OptionsIterator;
}

impl<'a> Ipv4ZeroCopyOptionsIterator for Ipv4Packet<'a> {
    fn get_options_zero_copy(&self) -> Ipv4OptionsIterator {
        Ipv4OptionsIterator {
            bytes: self.get_options_raw(),
        }
    }
}
