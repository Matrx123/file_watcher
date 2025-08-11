use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet::datalink::{interfaces, NetworkInterface};
use tokio::sync::mpsc;
use tokio::try_join;

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
pub struct ProcessedPacket {
    src_ip: IpAddr,
    packet_type: PacketType,
}

#[derive(Debug)]
enum PacketType {
    Ipv4Tcp,
    Ipv4Udp,
    Ipv6Tcp,
    Ipv6Udp,
    Other,
}

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

    // pub async fn capture_packets(interface: NetworkInterface, sender: mpsc::UnboundedSender<>)

    pub async fn start_network_monitor(
        &self,
        interface: NetworkInterface,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (sender, receiver) = mpsc::unbounded_channel::<Vec<u8>>();
        try_join!(
            self.capture_packets(interface, sender),
            self.process_packet(receiver),
            self.display_stats()
        )?;
        Ok(())
    }
}

