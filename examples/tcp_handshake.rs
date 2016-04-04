// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pnet;

use std::iter::repeat;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpPacket};
use pnet::transport::{transport_channel, udp_packet_iter};
use pnet::transport::TransportProtocol::{Ipv4};
use pnet::transport::TransportChannelType::{Layer4};
use pnet::packet::ipv4::{Ipv4Packet,MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket,TcpPacket,TcpOptions};
use pnet::packet::{HasPseudoheader};
use pnet::packet::checksum::rfc1071_checksum;
use std::net::{Ipv4Addr,IpAddr};

pub type u16be = u16;

fn main() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));

    // Create a new transport channel, dealing with layer 4 packets
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e)
    };

    const TCP_MIN_HEADER_LEN: usize = 20;
    const IPV4_HEADER_LEN: usize = 20;

    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN];
    let ipv4_source = Ipv4Addr::new(127, 0, 0, 1);
    let ipv4_destination = Ipv4Addr::new(127, 0, 0, 1);
    let next_level_protocol = IpNextHeaderProtocols::Tcp;
    let mut csum = 0;

    {
        let mut mut_ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        mut_ip_header.set_next_level_protocol(next_level_protocol);
        mut_ip_header.set_source(ipv4_source);
        mut_ip_header.set_destination(ipv4_destination);
    }

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_checksum(0);
        tcp_header.set_source(12345);
        tcp_header.set_destination(2553);
        tcp_header.set_sequence(0);
        tcp_header.set_acknowledgement(0);
        tcp_header.set_data_offset_and_reserved(0x4a);
        tcp_header.set_control_bits(0x002); // SYN
        tcp_header.set_window(0xff);
        tcp_header.set_urgent_pointer(0x0000);
    }

    {
        let ip_header = Ipv4Packet::new(&packet[..IPV4_HEADER_LEN]).unwrap();
        let tcp_header = TcpPacket::new(&packet[IPV4_HEADER_LEN..]).unwrap();
        csum = checksum(&tcp_header, ip_header);
        println!("packet_size: {} ", ip_header.packet_size());
    }

    {
        let mut mutable_tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        mutable_tcp_header.set_checksum(csum);
    }

    {
        let mut iter = packet.into_iter();
        loop {
            match iter.next() {
                Some(x) => {
                    print!("{:x} ", x);
                },
                None => { break }
            }
        }
    }

    let mut tcp_header = MutableTcpPacket::new(&mut packet[..]).unwrap();
    tx.send_to(tcp_header, IpAddr::V4(ipv4_destination));
}

/// Calculates the checksum of a TCP packet
/// The passed in TcpPacket must have it's initial checksum value set to zero.
pub fn checksum<'a, T: HasPseudoheader>(packet: &TcpPacket<'a>, encapsulating_packet: T) -> u16be {
    let mut sum = encapsulating_packet.pseudoheader_checksum();
    let length = packet.packet().len() as u32;
    sum = sum + length & 0xffff;
    sum = sum + length >> 16;
    return rfc1071_checksum(packet.packet(), sum);
}
