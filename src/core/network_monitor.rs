use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use pnet::datalink::{self, interfaces, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Debug)]
struct PacketDetail {
    total_packets: u64,
    ipv4_packets: u64,
    ipv6_packets: u64,
    tcp_packets: u64,
    udp_packets: u64,
    syn_packets: u64,
    time_stamp: Instant,
}

impl PacketDetail {
    fn new() -> Self {
        PacketDetail {
            total_packets: 0,
            ipv4_packets: 0,
            ipv6_packets: 0,
            tcp_packets: 0,
            udp_packets: 0,
            syn_packets: 0,
            time_stamp: Instant::now(),
        }
    }
}

#[derive(Debug)]
struct DetectAttacks {
    syn_collection: HashMap<IpAddr, u32>,
    packet_collection: HashMap<IpAddr, u32>,
    udp_collection: HashMap<IpAddr, u32>,
    syn_limit: u32,
    ddos_limit: u32,
    udp_limit: u32,
    time_limit: Duration,
    start_time_limit: Instant,
}

impl DetectAttacks {
    fn new() -> Self {
        DetectAttacks {
            syn_collection: HashMap::new(),
            packet_collection: HashMap::new(),
            udp_collection: HashMap::new(),
            syn_limit: 10000,
            ddos_limit: 10000,
            udp_limit: 10000,
            time_limit: Duration::from_secs(5),
            start_time_limit: Instant::now(),
        }
    }

    fn reset_values(&mut self) {
        self.syn_collection.clear();
        self.packet_collection.clear();
        self.start_time_limit = Instant::now();
    }

    fn can_reset(&mut self) -> bool {
        self.start_time_limit.elapsed() >= self.time_limit
    }

    fn is_udp_flood(&mut self, ip: IpAddr) -> bool {
        let udp_count = self.udp_collection.entry(ip).or_insert(0);
        *udp_count += 1;
        if *udp_count > self.udp_limit {
            println!(
                "============\nUDP Flood detected from :: {:?} in time :: {:?}\n============",
                ip, self.time_limit
            );
            return true;
        }
        false
    }

    fn is_syn_flood(&mut self, ip: IpAddr) -> bool {
        let syn_count = self.syn_collection.entry(ip).or_insert(0);
        *syn_count += 1;

        if *syn_count > self.syn_limit {
            println!(
                "============\nSyn Flood detected from :: {:?} in time :: {:?}\n============",
                ip, self.time_limit
            );
            return true;
        }
        false
    }

    fn is_ddos(&mut self, ip: IpAddr) -> bool {
        let ddos_count = self.packet_collection.entry(ip).or_insert(0);
        *ddos_count += 1;

        if *ddos_count > self.ddos_limit {
            println!(
                "Ddos Attack detected by IP :: {:?} in time :: {:?}",
                ip, self.time_limit
            );
            return true;
        }
        false
    }
}

pub struct NetworkMonitor {
    packet_stats: Arc<Mutex<PacketDetail>>,
    detect_attack: Arc<Mutex<DetectAttacks>>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        NetworkMonitor {
            packet_stats: Arc::new(Mutex::new(PacketDetail::new())),
            detect_attack: Arc::new(Mutex::new(DetectAttacks::new())),
        }
    }

    //interfaces > processed hte packets > processed the tcp/udp protocols > data
    pub fn get_interface(&self) -> Option<NetworkInterface> {
        let interfaces = interfaces();
        interfaces
            .into_iter()
            .find(|iface| iface.name == "en0" && iface.is_up() && !iface.is_loopback())
    }

    pub fn start_scanning_network(&self) -> Result<(), Box<dyn Error>> {
        println!("Welcome to network scan center!!");
        let mut monitor = NetworkMonitor::new();
        monitor.show_alerts();

        let interface = match monitor
            .get_interface()
            .ok_or("WARNING :: No interface found !!")
        {
            Ok(res) => res,
            Err(e) => {
                println!("Error in getting the interfaces :: {:?}", e);
                panic!()
            }
        };

        println!("::: INTERFACE FOUND :::");
        println!("interface name :: {:?}", interface.name);
        println!("interface description :: {:?}", interface.description);

        monitor.start_monitoring(interface);

        Ok(())
    }

    pub fn process_udp_packet(&self, udp: &UdpPacket, ip: IpAddr) {
        let mut stats = self.packet_stats.lock().unwrap();
        stats.udp_packets += 1;
        drop(stats);

        let mut detector = self.detect_attack.lock().unwrap();
        detector.is_udp_flood(ip);
    }

    pub fn process_tcp_packet(&self, tcp: &TcpPacket, ip: IpAddr) {
        let mut stats = self.packet_stats.lock().unwrap();
        stats.tcp_packets += 1;


        if tcp.get_flags() & TcpFlags::SYN != 0 && tcp.get_flags() & TcpFlags::ACK == 0 {
            stats.syn_packets += 1;
            drop(stats);
            let mut detector = self.detect_attack.lock().unwrap();
            detector.is_syn_flood(ip);
        }
    }

    pub fn process_ipv6_packets(&mut self, ipv6: &Ipv6Packet) {
        let ip_addr = IpAddr::V6(ipv6.get_source());
        {
            let mut stats = self.packet_stats.lock().unwrap();
            stats.total_packets += 1;
            stats.ipv4_packets += 1;
            stats.time_stamp = Instant::now();
        }

        {
            //ddos attacks
            let mut detector = self.detect_attack.lock().unwrap();
            if detector.can_reset() {
                detector.reset_values();
            }
            detector.is_ddos(ip_addr);
        }
        match ipv6.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                    self.process_tcp_packet(&tcp, ip_addr);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                    self.process_udp_packet(&udp, ip_addr);
                }
            }
            _ => {}
        }
    }

    pub fn process_ipv4_packets(&mut self, ipv4: &Ipv4Packet) {
        let ip_addr = IpAddr::V4(ipv4.get_source());
        {
            let mut stats = self.packet_stats.lock().unwrap();
            stats.total_packets += 1;
            stats.ipv4_packets += 1;
            stats.time_stamp = Instant::now();
        }

        {
            //ddos attacks
            let mut detector = self.detect_attack.lock().unwrap();
            if detector.can_reset() {
                detector.reset_values();
            }
            detector.is_ddos(ip_addr);
        }

        match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    self.process_tcp_packet(&tcp, ip_addr);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    self.process_udp_packet(&udp, ip_addr);
                }
            }
            _ => {}
        }
    }

    pub fn process_packets(&mut self, packet: &[u8]) {
        if let Some(ethernet_packet) = EthernetPacket::new(packet) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet_packet.payload()) {
                        self.process_ipv4_packets(&ipv4);
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ethernet_packet.payload()) {
                        self.process_ipv6_packets(&ipv6);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn start_monitoring(&mut self, interface: NetworkInterface) {
        println!("Network scanning in progress!!");
        println!("press ctrl+c to stop!!");

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type."),
            Err(e) => panic!("An error occurred: {}", e),
        };

        loop {
            match rx.next() {
                Ok(packet) => self.process_packets(packet),
                Err(e) => {
                    eprintln!("Error in receiving packets !! {}", e);
                }
            }
        }
    }

    pub fn show_alerts(&self) {
        let cloned_stat = Arc::clone(&self.packet_stats);

        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(5));
            let stats = cloned_stat.lock().unwrap();
            println!(
                "\n Statistics from last 5 Seconds :: \n\
                Total Packets :: {}\n\
                IPV4 Packets :: {}\n\
                IPV6 Packets :: {}\n\
                TCP Packets :: {}\n\
                UDP Packets :: {}\n\
                SYN Packets :: {}\n\
                {}\n 
                ",
                stats.total_packets,
                stats.ipv4_packets,
                stats.ipv6_packets,
                stats.tcp_packets,
                stats.udp_packets,
                stats.syn_packets,
                "--".repeat(30)
            );
        });
    }
}
