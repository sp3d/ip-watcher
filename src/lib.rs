extern crate byteorder;
extern crate futures;
extern crate pnetlink;
extern crate pnet_macros_support;
extern crate tokio;
extern crate tokio_util;

use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

use pnetlink::tokio::*;
use pnetlink::socket;
use pnetlink::packet::netlink::{NetlinkMsgFlags, NetlinkPacket};
use pnetlink::packet::route::*;
use pnetlink::packet::route::link::{RTM_NEWLINK, RTM_DELLINK};
use pnetlink::packet::route::addr::{RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR, IFA_ADDRESS};

use pnet_macros_support::packet::Packet;

use futures::task::Poll::{self, *};
use futures::stream::Stream;

/** A notification of a change to the set of available IP addresses. */
#[derive(Debug, Clone)]
pub enum IpChange {
	IpAdded(IpAddr),
	IpRemoved(IpAddr),
}

use pnetlink::tokio::{NetlinkSocket, NetlinkCodec};
use tokio_util::codec::Framed;
use std::pin::Pin;
use std::task::Context;

use futures::sink::Sink;

/** A watcher for changes to the IP addresses bound to network interfaces on a Linux system.

Notifications will not necessarily be balanced; for example, it is possible to receive multiple
IpAdded notifications for the same address in a row. */
#[derive(PartialEq)]
pub enum IpWatcherState {
	/// has not sent request for packets yet
	Initial,
	/// is waiting for packets
	Steady,
}


pub struct IpWatcher(IpWatcherState, Box<Framed<NetlinkSocket, NetlinkCodec>>);

impl IpWatcher {
	/** create a new watcher for IP changes */
	pub fn new() -> Result<Self, std::io::Error> {
		/* connect the socket, listening to ipv4 and ipv6 address changes */
		const RTMGRP_IPV4_IFADDR: u32 = 0x10;
		const RTMGRP_IPV6_IFADDR: u32 = 0x100;
		let socket = NetlinkSocket::bind(socket::NetlinkProtocol::Route,
			RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR)?;
		let framed = Framed::new(socket, pnetlink::tokio::NetlinkCodec {});
		Ok(IpWatcher(IpWatcherState::Initial, Box::new(framed)))
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
					ip6addr[..].copy_from_slice(rta.payload());
					return Some(Ipv6Addr::from(ip6addr).into());
				},
				_ => {},
			};
		}
	}
	None
}

impl Stream for IpWatcher {
	type Item=Result<IpChange, std::io::Error>;

	fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Result<IpChange, std::io::Error>>> {
		use IpChange::*;

		match self.get_mut() {
			IpWatcher(ref mut state, ref mut framed) => {
				if *state == IpWatcherState::Initial {
					/* send a packet requesting current addresses for initialization */
					let pkt = NetlinkRequestBuilder::new(RTM_GETADDR as u16, NetlinkMsgFlags::NLM_F_DUMP).append({
						let len = MutableIfInfoPacket::minimum_packet_size();
						let data = vec![0; len];
						MutableIfInfoPacket::owned(data).unwrap()
					}).build();
					*state = IpWatcherState::Steady;
					let pinned = Pin::new(&mut *framed);
					match pinned.start_send(&pkt) {
						Ok(()) => {
							let pinned = Pin::new(&mut *framed);
							let _ = pinned.poll_flush(cx); /* flush for netlink sockets always succeeds */
						},
						Err(e) => return Poll::Ready(Some(Err(e))),
					};
				}

				loop {
					match Pin::new(&mut *framed).poll_next(cx) {
						Ready(Some(Ok(frame))) => {
							if frame.get_kind() == RTM_NEWLINK as u16 {
								if let Some(ip) = extract_ip(&frame) {
									return Ready(Some(Ok(IpAdded(ip))))
								}
							} else if frame.get_kind() == RTM_DELLINK as u16 {
								if let Some(ip) = extract_ip(&frame) {
									return Ready(Some(Ok(IpRemoved(ip))))
								}
							} else if frame.get_kind() == RTM_NEWADDR as u16 {
								if let Some(ip) = extract_ip(&frame) {
									return Ready(Some(Ok(IpAdded(ip))))
								}
							} else if frame.get_kind() == RTM_DELADDR as u16 {
								if let Some(ip) = extract_ip(&frame) {
									return Ready(Some(Ok(IpRemoved(ip))))
								}
							}
						},
						Ready(None) => return Poll::Ready(None),
						Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
						Pending => return Poll::Pending,
					}
				}
			},
		}
	}
}

#[test]
fn main() {
	use futures::StreamExt;
	let runtime = tokio::runtime::Runtime::new().unwrap();
	//let mut runtime = tokio_crate::runtime::Builder::new().enable_io().build().unwrap();
	let _guard = runtime.enter();
	let ips = IpWatcher::new().expect("could not set up IP watcher");
	let f = ips.map(|i| println!("{:?}", i)).collect::<()>();
	runtime.block_on(f);
}
