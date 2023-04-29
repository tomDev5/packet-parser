use std::process::Command;

use pcap::{Active, Capture};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("pcap error")]
    PcapError(#[from] pcap::Error),
    #[error("std::IO error")]
    IoError(#[from] std::io::Error),
    #[error("ethtool command failed")]
    EthtoolCommandFailed,
    #[error("ethtool returned bad output")]
    EthtoolOutputError,
    #[error("interface is not zero copy")]
    InterfaceNotZeroCopy,
}

pub fn get_zc_interface(interface_name: &str) -> Result<Capture<Active>, InterfaceError> {
    let ethtool_output = Command::new("ethtool")
        .args(&["-k", interface_name])
        .output()
        .map_err(|_| InterfaceError::EthtoolCommandFailed)?;

    let stdout_str =
        String::from_utf8(ethtool_output.stdout).map_err(|_| InterfaceError::EthtoolOutputError)?;

    if !stdout_str.contains("rx-zero-copy: on") {
        return Err(InterfaceError::InterfaceNotZeroCopy);
    }

    let capture = Capture::from_device(interface_name)?
        .promisc(true)
        .open()?
        .setnonblock()?;

    Ok(capture)
}
