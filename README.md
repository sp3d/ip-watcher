## ip-watcher-rs - watch for changes to system IP addresses via the Linux netlink kernel interface

Provides a `futures::Stream<Item=IpChange>` that provides dynamic notifications of added and removed system IP addresses.

See the test `main` function for a demonstration of usage.

Released under WTFPL.
