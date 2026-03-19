#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string>
#include <set>
#include <cstring>

#pragma pack(push, 1)
struct EthernetHeader
{
  uint8_t  dst[6];
  uint8_t  src[6];
  uint16_t type;
};

struct ArpHeader
{
  uint16_t htype;
  uint16_t ptype;
  uint8_t  hlen;
  uint8_t  plen;
  uint16_t oper;
  uint8_t  sha[6];
  uint8_t  spa[4];
  uint8_t  tha[6];
  uint8_t  tpa[4];
};
#pragma pack(pop)

int main(int argc, char** argv)
{
  std::set<std::string> filter ;

  if (argc < 2)
  {
    filter.emplace("*");
  }
  else if (argc == 2 && (strcasecmp(argv[1], "-h") == 0 || strcasecmp(argv[1], "--help") == 0))
  {
    std::cout << "Usage: " << argv[0] << " [ip filters|\"*\"]" << std::endl;
    exit(EXIT_SUCCESS);
  }
  else
  {
    for (int i = 1; i < argc; ++i)
      filter.emplace(argv[i]);
  }

  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (sock < 0)
  {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  constexpr auto bufferSize = 2048;
  uint8_t buffer[bufferSize]{};
  char fromIP[INET_ADDRSTRLEN]{};
  char toIP[INET_ADDRSTRLEN]{};

  std::cout << "Listening for ARP packets (Linux raw socket)...\n"
    << "Filters:";

  for (const auto& ip : filter)
    std::cout << " " << ip;
  std::cout << std::endl;

  while (true)
  {
    if (const auto len = recv(sock, buffer, sizeof(buffer), 0); len < 0)
      continue;

    if (const auto* eth = reinterpret_cast<EthernetHeader*>(buffer); ntohs(eth->type) != ETH_P_ARP)
      continue;

    const auto* arp = reinterpret_cast<const ArpHeader*>(&buffer[sizeof(EthernetHeader)]);

    inet_ntop(AF_INET, arp->spa, fromIP, sizeof(fromIP));
    inet_ntop(AF_INET, arp->tpa, toIP, sizeof(toIP));

    if (filter.contains(fromIP) || filter.contains(toIP) || filter.contains("*"))
    {
      std::cout << "ARP " << (ntohs(arp->oper) == 1 ? "Send" : "Receive") << " from " << fromIP << " -> " << toIP <<
          std::endl;
    }
  }
}
