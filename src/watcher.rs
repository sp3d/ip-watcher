#[derive(Debug, Clone)]
pub enum IpChange {
	IpAdded(IpAddr),
	IpRemoved(IpAddr),
}

use pnetlink::tokio::{NetlinkSocket, NetlinkCodec};
use tokio_io::codec::Framed;
use futures::{Sink,Stream,Future};

pub enum IpWatcher {
	Initial(futures::sink::Send<Framed<NetlinkSocket, NetlinkCodec>>),
	Steady(Framed<NetlinkSocket, NetlinkCodec>),
}

impl IpWatcher {
	pub fn new(handle: &Handle) -> Result<Self, std::io::Error> {
		/* connect the socket, listening to ipv4 and ipv6 address changes */
		let socket = NetlinkSocket::bind(socket::NetlinkProtocol::Route,
			(route::MulticastGroup::RTMGRP_IPV4_IFADDR | route::MulticastGroup::RTMGRP_IPV6_IFADDR).bits(),
			&handle)?;
		let framed = tokio_io::AsyncRead::framed(socket, pnetlink::tokio::NetlinkCodec {});
		/* send a packet requesting current addresses for initialization */
		let pkt = NetlinkRequestBuilder::new(RTM_GETADDR as u16, NetlinkMsgFlags::NLM_F_DUMP).append({
			let len = MutableIfInfoPacket::minimum_packet_size();
			let mut data = vec![0; len];
			MutableIfInfoPacket::owned(data).unwrap()
		}).build();
		Ok(IpWatcher::Initial(framed.send(pkt)))
	}
}

fn extract_ip(msg: &NetlinkPacket) -> Option<IpAddr> {
	use std::io::Cursor;
	let ifa = IfAddrPacket::new(&msg.payload()[0..])?;
	let payload = &ifa.payload()[0..];
	let iter = RtAttrIterator::new(payload);
	for rta in iter {
		if rta.get_rta_type() == IFA_ADDRESS {
			let mut cur = Cursor::new(rta.payload());
			match ifa.get_family() {
				2 => {
					use byteorder::ReadBytesExt;
					use byteorder::BigEndian;
					if let Ok(data) = cur.read_u32::<BigEndian>() {
						return Some(Ipv4Addr::from(data).into());
					} else {
						return None
					}
				},
				10 => {
					let mut ip6addr: [u8;16] = [0;16];
					&mut ip6addr[..].copy_from_slice(rta.payload());
					return Some(Ipv6Addr::from(ip6addr).into());
				},
				_ => {},
			};
		}
	}
	None
}

impl futures::stream::Stream for IpWatcher {
	type Item=IpChange;
	type Error=std::io::Error;

	fn poll(&mut self) -> futures::Poll<Option<IpChange>, std::io::Error> {
		/* first, send a message to query current interface addresses */
		let new_framed = if let &mut IpWatcher::Initial(ref mut framed) = self {
			match framed.poll() {
				Ok(Ready(framed)) => {
					Some(framed)
				},
				Ok(NotReady) => return Ok(NotReady),
				Err(e) => return Err(e),
			}
		} else {
			None
		};
		if let Some(framed) = new_framed {
			*self = IpWatcher::Steady(framed);
		}

		/* monitor for new interface changes */
		use IpChange::*;
		match self {
			&mut IpWatcher::Initial(_) => unreachable!(),
			&mut IpWatcher::Steady(ref mut framed) => loop { match framed.poll() {
				Ok(Ready(Some(frame))) => {
					//println!("RECEIVED FRAME: {:?}", frame);
					//let fake = "0.0.0.0".parse().unwrap();
					if frame.get_kind() == RTM_NEWLINK as u16 {
						if let Some(ip) = extract_ip(&frame) {
							return Ok(Ready(Some(IpAdded(ip))))
						}
					} else if frame.get_kind() == RTM_DELLINK as u16 {
						if let Some(ip) = extract_ip(&frame) {
							return Ok(Ready(Some(IpRemoved(ip))))
						}
					} else if frame.get_kind() == RTM_NEWADDR as u16 {
						if let Some(ip) = extract_ip(&frame) {
							return Ok(Ready(Some(IpAdded(ip))))
						}
					} else if frame.get_kind() == RTM_DELADDR as u16 {
						if let Some(ip) = extract_ip(&frame) {
							return Ok(Ready(Some(IpRemoved(ip))))
						}
					}
					continue
				},
				Ok(Ready(None)) => return Ok(Ready(None)),
				Ok(NotReady) => return Ok(NotReady),
				Err(e) => return Err(e),
			} }
		}
	}
}
