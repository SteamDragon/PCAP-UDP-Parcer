#include <arpa/inet.h>
#include <cstdlib>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

#include "optionparser.h"
enum optionIndex { ADDRESS,
    PORT,
    UNKNOWN,
    HELP };
std::string ipFilter = "0.0.0.0";
int portFilter;
const option::Descriptor usage[] = {
    { UNKNOWN, 0, "", "", option::Arg::None, "USAGE: pcap_parce [options]\n\n"
                                             "Options:" },
    { HELP, 0, "", "help", option::Arg::None,
        "  --help  \tPrint usage and exit." },
    { ADDRESS, 0, "a", "", option::Arg::Optional,
        "-a  \tFilters PCAP PRINT by adress." },
    { PORT, 0, "p", "", option::Arg::Optional,
        "-p  \tFilters PCAP PRINT by Port." },
    { UNKNOWN, 0, "", "", option::Arg::None,
        "\nExamples:\n"
        "pcap_parcer -a 192.168.0.1 -p 1992 dump.pcap\n" },
    { 0, 0, 0, 0, 0, 0 }
};
std::string parseOptions(int argc, char* argv[]);
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr,
    const u_char* packet);

int main(int argc, char* argv[])
{
    std::string filename = (parseOptions(argc, argv) + '\0').c_str();
    const char* fileName_cchar = filename.c_str();
    std::cout << ipFilter << std::endl;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t* pcapFile = pcap_open_offline(fileName_cchar, errorBuffer);
    if (pcapFile == NULL) {
        std::cout << "pcapOpenOffline() failed: " << errorBuffer << std::endl;
        return 4;
    }

    if (pcap_loop(pcapFile, 0, packetHandler, NULL) < 0) {
        std::cout << "pcap_loop() failed: " << pcap_geterr(pcapFile);
        return 1;
    }

    return 0;
}

std::string parseOptions(int argc, char* argv[])
{
    argc -= (argc > 0);
    argv += (argc > 0);
    option::Stats stats(usage, argc, argv);
    option::Option options[stats.options_max], buffer[stats.buffer_max];
    option::Parser parse(usage, argc, argv, options, buffer);
    if (parse.error()) {
        std::cout << "Failed to parce command line arguments" << std::endl;
        std::exit(1);
    }

    if (options[HELP] || argc == 0) {
        option::printUsage(std::cout, usage);
        std::exit(0);
    }

    std::cout << parse.optionsCount();
    for (int i = 0; i < parse.optionsCount(); i++) {
        option::Option& opt = buffer[i];
        switch (opt.index()) {
        case ADDRESS:
            if (opt.arg) {
                ipFilter = std::string(opt.arg);
            }
            else {
                ipFilter = "0.0.0.0";
            }
            break;

        case PORT:
            if (opt.arg) {
                portFilter = atoi(opt.arg);
            }
            else {
                portFilter = 0;
            }
            break;
        }
    }

    std::string fileArg = std::string(argv[argc - 1]);
    if (fileArg.find("pcap") == std::string::npos) {
        std::cout << "Failed to find \"PCAP\" file format" << std::endl;
        std::exit(3);
        ;
    }
    else {
        return fileArg;
    }
}

void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr,
    const u_char* packet)
{
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    u_char* data;
    int dataLength = 0;
    std::string dataStr = "";
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_UDP) {

            udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(udpHeader->source);
            destPort = ntohs(udpHeader->dest);
            data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            char fmt[64], buf[64];
            struct tm* tm;
            tm = localtime(&(pkthdr->ts.tv_sec));
            strftime(fmt, sizeof fmt, "%Y-%m-%d %H:%M:%S.%%06u %z", tm);
            snprintf(buf, sizeof buf, fmt, pkthdr->ts.tv_usec);

            if (ipFilter == destIp || ipFilter == "0.0.0.0") {
                if (portFilter == destPort || portFilter == 0) {
                    // print the results
                    std::cout << buf << " " << destIp << ":"
                              << destPort << " " << dataLength << std::endl;
                }
            }
        }
    }
}
