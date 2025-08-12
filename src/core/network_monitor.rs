use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, interfaces, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::{task, try_join};

pub struct PacketDetails {
    total_packets: u64,
    ipv4_packets: u64,
    ipv6_packets: u64,
    tcp_packets: u64,
    upd_packets: u64,
    syn_packets: u64,
    last_update: Instant,
}

impl PacketDetails {
    pub fn new() -> Self {
        PacketDetails {
            total_packets: 0,
            ipv4_packets: 0,
            ipv6_packets: 0,
            tcp_packets: 0,
            upd_packets: 0,
            syn_packets: 0,
            last_update: Instant::now(),
        }
    }
}

pub struct AttackDetector {
    syn_limit: u32,
    ddos_limit: u32,
    udp_limit: u32,
    time_window: Duration,
    syn_collection: HashMap<IpAddr, u32>,
    udp_collection: HashMap<IpAddr, u32>,
    tcp_collection: HashMap<IpAddr, u32>,
    window_start: Instant,
}
impl AttackDetector {
    pub fn new() -> Self {
        Self {
            syn_limit: 50,
            ddos_limit: 5,
            udp_limit: 50,
            time_window: Duration::from_secs(7),
            syn_collection: HashMap::new(),
            udp_collection: HashMap::new(),
            tcp_collection: HashMap::new(),
            window_start: Instant::now(),
        }
    }

    pub fn reset_values(&mut self) {
        self.syn_collection.clear();
        self.tcp_collection.clear();
        self.udp_collection.clear();
        self.window_start = Instant::now();
    }

    async fn check_syn_flood(&mut self, ip: IpAddr) -> bool {
        let count = self.syn_collection.entry(ip).or_insert(0);
        *count += 1;

        if *count > self.syn_limit {
            println!("Possible syn flood detected  from {:?}!!", ip);
            return true;
        }
        false
    }

    async fn check_udp_flood(&mut self, ip: IpAddr) -> bool {
        let count = self.udp_collection.entry(ip).or_insert(0);
        *count += 1;

        if *count > self.udp_limit {
            println!("Possible UDP flood detected from IP :: {:?}", ip);
            return true;
        }
        false
    }

    async fn check_ddos(&mut self, ip: IpAddr) -> bool {
        let count = self.tcp_collection.entry(ip).or_insert(0);
        *count += 1;

        if *count > self.ddos_limit {
            println!("Possible DDOS attack detected from IP :: {:?}", ip);
            return true;
        }
        false
    }

    fn should_reset(&self) -> bool {
        self.window_start.elapsed() >= self.time_window
    }
}

#[derive(Debug)]
pub enum ChannelItems {
    PacketReceived(Vec<u8>),
    ShareStats,
    TurnOff,
}

#[derive(Debug)]
pub struct ProcessedPacket {
    src_ip: IpAddr,
    packet_type: PacketType,
}

#[derive(Debug)]
enum PacketType {
    Ipv4Tcp { is_syn: bool },
    Ipv4Udp,
    Ipv6Tcp { is_syn: bool },
    Ipv6Udp,
    Other,
}

#[derive(Clone)]
pub struct AsyncNetworkMon {
    packet_stats: Arc<Mutex<PacketDetails>>,
    detect_attacks: Arc<Mutex<AttackDetector>>,
}

impl AsyncNetworkMon {
    pub fn new() -> Self {
        AsyncNetworkMon {
            packet_stats: Arc::new(Mutex::new(PacketDetails::new())),
            detect_attacks: Arc::new(Mutex::new(AttackDetector::new())),
        }
    }

    pub fn get_interface() -> Option<NetworkInterface> {
        let interfaces = interfaces();
        interfaces
            .into_iter()
            .find(|iface| iface.name == "en0" && iface.is_up() && !iface.is_loopback())
    }

    pub async fn capture_packets(
        &self,
        interface: NetworkInterface,
        sender: mpsc::UnboundedSender<ChannelItems>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send + Sync>> {
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err("Unhandled channel type.".into()),
                Err(e) => return Err(format!("An error occurred: {}", e).into()),
            };

            loop {
                match rx.next() {
                    Ok(packet) => {
                        if let Err(e) = sender.send(ChannelItems::PacketReceived(packet.to_vec())) {
                            eprintln!("Failed to send packets for processing :: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error in receiving packets !! {}", e);
                        break;
                    }
                };
            }
            Ok(())
        })
        .await?;
        Ok(())
    }

    pub async fn parse_packet(&self, packet: Vec<u8>) -> Option<ProcessedPacket> {
        if let Some(ethernet_packet) = EthernetPacket::new(&packet) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet_packet.payload()) {
                        return self.parse_ipv4_packets(&ipv4).await;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ethernet_packet.payload()) {
                        return self.parse_ipv6_packets(&ipv6).await;
                    }
                }
                _ => {}
            }
        };
        None
    }

    pub async fn parse_ipv6_packets(&self, ipv6: &Ipv6Packet<'_>) -> Option<ProcessedPacket> {
        let ip_addr = IpAddr::V6(ipv6.get_source());
        match ipv6.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                    let is_syn = tcp.get_flags() & TcpFlags::SYN != 0
                        && tcp.get_flags() & TcpFlags::ACK == 0;
                    return Some(ProcessedPacket {
                        src_ip: ip_addr,
                        packet_type: PacketType::Ipv6Tcp { is_syn },
                    });
                }
            }

            IpNextHeaderProtocols::Udp => {
                if let Some(_udp) = UdpPacket::new(ipv6.payload()) {
                    return Some(ProcessedPacket {
                        src_ip: ip_addr,
                        packet_type: PacketType::Ipv6Udp,
                    });
                }
            }

            _ => {}
        }
        Some(ProcessedPacket {
            src_ip: ip_addr,
            packet_type: PacketType::Other,
        })
    }

    pub async fn parse_ipv4_packets(&self, ipv4: &Ipv4Packet<'_>) -> Option<ProcessedPacket> {
        let ip_addr = IpAddr::V4(ipv4.get_source());
        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    let is_syn = tcp.get_flags() & TcpFlags::SYN != 0
                        && tcp.get_flags() & TcpFlags::ACK == 0;
                    return Some(ProcessedPacket {
                        src_ip: ip_addr,
                        packet_type: PacketType::Ipv4Tcp { is_syn },
                    });
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(_udp) = UdpPacket::new(ipv4.payload()) {
                    return Some(ProcessedPacket {
                        src_ip: ip_addr,
                        packet_type: PacketType::Ipv4Udp,
                    });
                }
            }
            _ => {}
        }
        Some(ProcessedPacket {
            src_ip: ip_addr,
            packet_type: PacketType::Other,
        })
    }

    pub async fn process_packet(
        &self,
        mut receiver: UnboundedReceiver<ChannelItems>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        while let Some(events) = receiver.recv().await {
            match events {
                ChannelItems::PacketReceived(packet) => {
                    //parse it
                    if let Some(processed_packet) = self.parse_packet(packet).await {
                        self.update_and_check_for_attacks(processed_packet).await;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub async fn update_and_check_for_attacks(&self, processed: ProcessedPacket) {
        {
            let mut stats = self.packet_stats.lock();
            stats.total_packets += 1;
            stats.last_update = Instant::now();
        }
    }

    pub async fn start_network_monitor(
        &self,
        interface: NetworkInterface,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (sender, receiver) = mpsc::unbounded_channel::<ChannelItems>();
        try_join!(
            self.capture_packets(interface, sender),
            self.process_packet(receiver),
            // self.display_stats()
        )?;
        Ok(())
    }
}
