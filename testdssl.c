#include <stdint.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <dssl/dssl_defs.h>
#include <dssl/ssl_ctx.h>
#include <dssl/errors.h>
#include <dssl/session.h>

void callback(NM_PacketDir dir, void *userdata, u_char *data, uint32_t len, DSSL_Pkt *pkt)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        if (isprint(data[i])) {
            printf("%c", data[i]);
        } else {
            printf(" %02x ", data[i]);
        }
    }
}

void errorcallback(void *data, int errorcode)
{
    printf("error code %d\n", errorcode);
}

int main(int argc, char *argv[])
{
    int rc;
    DSSL_Env *env;
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *payload;
    struct in_addr addr, addr_client;
    struct ether_header *ehdr;
    struct iphdr *iphdr;
    struct tcphdr *thdr;
    char errbuf[PCAP_ERRBUF_SIZE];
    DSSL_Session *session;
    DSSL_Session *sessions[65535] = {0};

    SSL_library_init();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    handle = pcap_open_offline("./test1.cap", errbuf); 

    if (!handle) {
        fprintf(stderr, "Failed to open dump file: %s\n", errbuf);
        return -1;
    }

    addr.s_addr = inet_addr("10.0.0.1");
    addr_client.s_addr = inet_addr("192.168.1.238");

    env = DSSL_EnvCreate(65535, 1);

    rc = DSSL_EnvSetServerInfo(env, &addr, 443,
            "./test1.pem", 0);
    if (rc != DSSL_RC_OK) {
        fprintf(stderr, "Failed to set env server!\n");
        return -1;
    }

    while (1) {
        off_t payload_offset;
        payload = pcap_next(handle, &header);

        if (payload) {
        } else {
            break;
        }
        ehdr = (struct ether_header*)payload;

        if (ntohs(ehdr->ether_type) != ETHERTYPE_IP) {
            continue;
        }

        iphdr = (struct iphdr*)(payload + sizeof(*ehdr));

        if (iphdr->protocol != IPPROTO_TCP) {
            continue;
        }

        thdr = (struct tcphdr*)(payload + sizeof(*iphdr) + sizeof(*ehdr));


        payload_offset = sizeof(*ehdr) + iphdr->ihl * 4 + thdr->th_off * 4;


        uint16_t client_port;

        if (ntohs(thdr->th_sport) == 443) {
            if (!sessions[ntohs(thdr->th_dport)]) {
                sessions[ntohs(thdr->th_dport)] = DSSL_EnvCreateSession(env, addr,
                        443, addr_client, ntohs(thdr->th_dport));

                session = sessions[ntohs(thdr->th_dport)];
                DSSL_SessionSetCallback(session, callback, errorcallback, 0);
            }
            client_port = ntohs(thdr->th_dport);
            session = sessions[ntohs(thdr->th_dport)];
        } else if (ntohs(thdr->th_dport) == 443) {
               if (!sessions[ntohs(thdr->th_sport)]) {
                sessions[ntohs(thdr->th_sport)] = DSSL_EnvCreateSession(env, addr,
                        443, addr_client, ntohs(thdr->th_sport));

                session = sessions[ntohs(thdr->th_sport)];
                DSSL_SessionSetCallback(session, callback, errorcallback, 0);
            }
            client_port = ntohs(thdr->th_sport);
            session = sessions[ntohs(thdr->th_sport)];
        }

        if (session == (void*)1) {
            continue;
        }

        if ((thdr->th_flags & TH_FIN) && (thdr->th_flags & TH_ACK)) {
            DSSL_SessionDeInit(session);
            sessions[client_port] = (void*)1;
            continue;
        }

        if (header.caplen - payload_offset == 0) {
            continue;
        }

        printf("> %02x %02x %02x\n", (payload + payload_offset)[0],
                (payload + payload_offset)[1], (payload + payload_offset)[2]);

        if (ntohs(thdr->th_dport) == 443) {
            printf("from client %d\n", (int)(header.caplen - payload_offset));

            rc = DSSL_SessionProcessData(session, ePacketDirFromClient,
                    payload + payload_offset, header.caplen - payload_offset);
            if (rc != DSSL_RC_OK) {
                printf("Failed to process data: %d\n", rc);
            }
        } else {
            printf("from server %d\n", (int)(header.caplen - payload_offset));
            rc = DSSL_SessionProcessData(session, ePacketDirFromServer,
                    payload + payload_offset, header.caplen - payload_offset);

            if (rc != DSSL_RC_OK) {
                printf("Failed to process data: %d\n", rc);
            }
        }
    }

    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    pcap_close(handle);

    return 0;
}
