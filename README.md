# stun_client_udpport_check

Small utility that sends a STUN Binding Request to a remote IP:port and detects whether
the remote UDP port is open, closed (ICMP Port Unreachable), or silently filtered by a
firewall.

Key behavior
- Sends a STUN Binding Request (20-byte STUN header) via UDP.
- Waits up to 2 seconds for a normal STUN response → reports PORT OPEN.
- If no UDP response, inspects the socket error queue (requires `IP_RECVERR`) for an
	ICMP "Destination Unreachable (Port Unreachable)" → reports PORT CLOSED.
- If neither a UDP response nor an ICMP error is observed → reports UNKNOWN (likely
	filtered/dropped by a firewall).

Important: this program reads ICMP errors from the socket error queue using
`recvmsg(..., MSG_ERRQUEUE)` and relies on Linux-specific headers (`linux/errqueue.h`).
It is therefore Linux-only and will not compile or behave the same on other OSes.

Building

Requires a C compiler (tested with `gcc`). From the repository root run:

```bash
gcc -O2 -Wall -Wextra -o stun_client stun_client.c
```

Usage

```bash
./stun_client <server_ip> <port>
```

Example

1. Check a public STUN server on port 3478:

```bash
./stun_client 1.2.3.4 3478
```

Possible outputs
- "🎉 Received N bytes → PORT OPEN (STUN response)": server replied to the STUN request.
- "❌ ICMP Port Unreachable detected → PORT CLOSED": an ICMP Port Unreachable was received
	for the sent UDP packet.
- "⚠️  No STUN response and no ICMP error → UNKNOWN (maybe firewall drop)": no response and
	no ICMP error — often indicates the packet was dropped by a firewall.

Notes & troubleshooting
- The program enables `IP_RECVERR` with `setsockopt`. If that call fails, the program
	prints an error but still attempts the probe; without `IP_RECVERR` ICMP port unreachable
	messages will not be observable via the socket error queue.
- ICMP may be filtered upstream (e.g., by routers or provider) — lack of ICMP does not
	necessarily mean the port is open.
- To observe network-level traffic while testing, use tcpdump (requires root):

```bash
sudo tcpdump -n icmp or udp and host <server_ip>
```

- The STUN timeout is implemented via `SO_RCVTIMEO` (set to 2 seconds in source).
	You can change that value in `stun_client.c` if needed.

License

This repository contains a small example utility — use and modify as you like.
