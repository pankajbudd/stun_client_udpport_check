/*
 * STUN Binding Request + ICMP Port Unreachable Detector
 * ------------------------------------------------------
 * This program sends a STUN Binding Request to a remote IP:port.
 * Then it checks:
 *   1. If a normal STUN response is received → PORT OPEN
 *   2. If an ICMP "Destination Unreachable (Port Unreachable)" arrives
 *         → PORT CLOSED
 *   3. If no ICMP and no STUN response → UNKNOWN (maybe firewall drop)
 *
 * Why is ICMP hard to detect in C?
 *   Linux does NOT deliver ICMP errors to normal UDP sockets.
 *   You MUST enable:  setsockopt(..., IP_RECVERR)
 *
 * ICMP errors arrive through the "error queue" using recvmsg() + MSG_ERRQUEUE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>

#define STUN_BINDING_REQUEST 0x0001
#define STUN_MAGIC_COOKIE 0x2112A442

/*
 * STUN header format (20 bytes):
 * ---------------------------------
 * 0-1   Message Type        (Binding Request = 0x0001)
 * 2-3   Message Length      (no attributes → 0)
 * 4-7   Magic Cookie        (0x2112A442)
 * 8-19  Transaction ID      (random 96 bits)
 */
struct stun_header {
    uint16_t msg_type;
    uint16_t msg_length;
    uint32_t magic_cookie;
    uint8_t transaction_id[12];
} __attribute__((packed));

/*
 * Fill the 12-byte STUN Transaction ID with random bytes.
 * Its purpose is to match responses to requests.
 */
void generate_tid(uint8_t *tid) {
    for (int i = 0; i < 12; i++)
        tid[i] = rand() & 0xFF;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    /*
     * Create a normal IPv4 UDP socket.
     */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    /*
     * Enable receiving asynchronous ICMP errors.
     *
     * This is CRITICAL.
     * Without this, Linux will drop ICMP Port Unreachable messages silently.
     *
     * With IP_RECVERR enabled:
     *   - ICMP errors go to the "error queue".
     *   - We can read them using recvmsg(... MSG_ERRQUEUE)
     */
    int opt = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_RECVERR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt IP_RECVERR");
    }

    /*
     * Add receive timeout for normal UDP packets (STUN responses).
     */
    struct timeval tv = { 2, 0 };   // 2 seconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /*
     * Prepare the remote server address.
     */
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);

    /*
     * Build the STUN Binding Request.
     * Length = 0, we send only the header (20 bytes).
     */
    struct stun_header stun;
    stun.msg_type = htons(STUN_BINDING_REQUEST);
    stun.msg_length = htons(0);
    stun.magic_cookie = htonl(STUN_MAGIC_COOKIE);
    generate_tid(stun.transaction_id);

    printf("Sending STUN Binding Request to %s:%d\n", server_ip, server_port);

    /*
     * Send the STUN packet over UDP.
     */
    sendto(sock, &stun, sizeof(stun), 0, (struct sockaddr *)&addr, sizeof(addr));

    /*
     * Try receiving a normal STUN response.
     */
    char buf[1024];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    int ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);

    if (ret >= 0) {
        /*
         * If recvfrom() succeeds, we got a normal UDP packet.
         * That means the port is open and accepted the STUN request.
         */
        printf("🎉 Received %d bytes → PORT OPEN (STUN response)\n", ret);
        close(sock);
        return 0;
    }

    /*
     * No STUN response → Now check the ICMP error queue.
     *
     * recvmsg(... MSG_ERRQUEUE) receives ICMP errors associated with
     * previous UDP packets sent on this socket.
     */

    struct msghdr msg = {};
    struct iovec iov;
    char cbuf[512];
    char data;

    /*
     * We don't care about actual data, but recvmsg() needs a buffer.
     */
    iov.iov_base = &data;
    iov.iov_len = sizeof(data);

    /*
     * Prepare msghdr to receive:
     *   - source address
     *   - control messages (ICMP info)
     */
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    int e = recvmsg(sock, &msg, MSG_ERRQUEUE);

    /*
     * If e >= 0 → we got an ICMP error
     */
    if (e >= 0) {
        struct cmsghdr *cmsg;

        /*
         * Iterate through all control messages.
         */
        for (cmsg = CMSG_FIRSTHDR(&msg);
             cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {

            /*
             * We are looking for:
             *   cmsg_level = IPPROTO_IP
             *   cmsg_type  = IP_RECVERR
             */
            if (cmsg->cmsg_level == IPPROTO_IP &&
                cmsg->cmsg_type == IP_RECVERR) {

                struct sock_extended_err *err =
                    (struct sock_extended_err *)CMSG_DATA(cmsg);

                /*
                 * Check if the error is ICMP Port Unreachable.
                 */
                if (err->ee_origin == SO_EE_ORIGIN_ICMP &&
                    err->ee_type == ICMP_DEST_UNREACH &&
                    err->ee_code == ICMP_PORT_UNREACH) {

                    printf("❌ ICMP Port Unreachable detected → PORT CLOSED\n");
                    close(sock);
                    return 0;
                }
            }
        }
    }

    /*
     * No STUN response and no ICMP error.
     * This usually means the firewall silently dropped packets.
     */
    printf("⚠️  No STUN response and no ICMP error → UNKNOWN (maybe firewall drop)\n");

    close(sock);
    return 0;
}
