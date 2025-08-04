use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;

pub struct NetworkMonitor;

impl NetworkMonitor {
    pub fn new() -> Self {
        Self
    }

    pub fn check_status(&self) {
        let interfaces = datalink::interfaces();

        let interface = interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback())
            .expect("No avalaible interface found!!");
        println!("Interface :: {:?}", interface);

        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type."),
            Err(e) => panic!("An error occurred: {}", e),
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                        println!("New packet:");
                        println!("{:?}", ethernet_packet);
                    }
                }
                Err(e) => {
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    }
}
