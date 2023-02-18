use std::net::IpAddr;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FourTuple {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}
