#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define DNS_SERVER "8.8.8.8"   // 默认用Google的公共DNS
#define DNS_PORT 53
#define BUF_SIZE 512

// DNS报文头部结构（简化）
typedef struct {
    unsigned short id;         // 事务ID
    unsigned short flags;      // 标志位
    unsigned short qdcount;    // 问题数
    unsigned short ancount;    // 回答数
    unsigned short nscount;   // 授权数
    unsigned short arcount;   // 附加数
} DNSHeader;

// 构造DNS查询问题部分（域名部分）
void build_domain_name(const char *domain, unsigned char *buf, int *len) {
    char *part = strdup(domain);
    char *token = strtok(part, ".");
    while (token) {
        int len_part = strlen(token);
        buf[(*len)++] = len_part;
        memcpy(buf + *len, token, len_part);
        *len += len_part;
        token = strtok(NULL, ".");
    }
    buf[(*len)++] = 0; // 域名结束符
    free(part);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <domain>\n", argv[0]);
        return 1;
    }
    const char *domain = argv[1];

    // 1. 创建UDP套接字
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // 2. 设置DNS服务器地址
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DNS_SERVER, &dns_addr.sin_addr);

    // 3. 构造DNS查询报文
    unsigned char query[BUF_SIZE] = {0};
    DNSHeader *header = (DNSHeader *)query;
    header->id = htons(0x1234);
    header->flags = htons(0x0100); // 标准查询
    header->qdcount = htons(1);    // 1个问题
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    int qlen = sizeof(DNSHeader);
    build_domain_name(domain, query, &qlen);

    // 查询类型（A记录：1）+ 查询类（IN：1）
    unsigned short qtype = htons(1);
    unsigned short qclass = htons(1);
    memcpy(query + qlen, &qtype, 2);
    memcpy(query + qlen + 2, &qclass, 2);
    qlen += 4;

    // 4. 发送查询请求
    sendto(sockfd, query, qlen, 0,
           (struct sockaddr *)&dns_addr, sizeof(dns_addr));

    // 5. 接收响应
    unsigned char response[BUF_SIZE] = {0};
    socklen_t addr_len = sizeof(dns_addr);
    recvfrom(sockfd, response, BUF_SIZE, 0,
             (struct sockaddr *)&dns_addr, &addr_len);

    // 6. 解析响应（简化，只提取A记录IP）
    DNSHeader *resp_header = (DNSHeader *)response;
    unsigned char *ptr = response + sizeof(DNSHeader);

    // 跳过问题部分
    for (int i = 0; i < ntohs(resp_header->qdcount); i++) {
        while (*ptr != 0) ptr++;
        ptr++; // 跳过0
        ptr += 4; // 跳过type和class
    }

    // 遍历回答部分
    printf("nslookup %s result:\n", domain);
    for (int i = 0; i < ntohs(resp_header->ancount); i++) {
        // 跳过名字（可能是压缩指针）
        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2;
        } else {
            while (*ptr != 0) ptr++;
            ptr++;
        }

        unsigned short type, class;
        unsigned int ttl;
        unsigned short rdlength;
        memcpy(&type, ptr, 2); ptr += 2;
        memcpy(&class, ptr, 2); ptr += 2;
        memcpy(&ttl, ptr, 4); ptr += 4;
        memcpy(&rdlength, ptr, 2); ptr += 2;

        if (ntohs(type) == 1) { // A记录
            struct in_addr addr;
            memcpy(&addr.s_addr, ptr, 4);
            printf("Address: %s\n", inet_ntoa(addr));
        }
        ptr += rdlength;
    }

    close(sockfd);
    return 0;
}
