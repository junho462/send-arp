# send-arp

ARP spoofing assignment implementation based on the header layout used in `gilgil/send-arp-test`.

## Build

```sh
make
```

## Run

```sh
sudo ./send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]
```

Example:

```sh
sudo ./send-arp wlan0 192.168.10.2 192.168.10.1
```

## What it does

- Reads attacker MAC and IP from the given interface.
- Sends a normal ARP request to discover each sender MAC automatically.
- Receives the ARP reply with `pcap_next_ex`.
- Sends forged ARP replies so the sender maps the target IP to the attacker MAC.

## Verification

- On victim: `arp -an`
- Or run continuous ping on victim and confirm ICMP reaches attacker in Wireshark.

## Submission note

The assignment still requires a real test video recorded in your own lab environment. That part cannot be produced from this container alone.
