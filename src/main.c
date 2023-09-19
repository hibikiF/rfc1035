#include <stdio.h>
#include "rfc1035.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int client_socket = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in server_addr = { 0 };
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("1.1.1.1");
    server_addr.sin_port = htons(53);

    if (connect(client_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
        printf("connect fail");
        return -1;
    }

    PRFC1035_Request rfc1035_request = (PRFC1035_Request) calloc(1,sizeof(RFC1035_Request));
    create_rfc1035_request(rfc1035_request, "hibiki.uk");
    send_rfc1035_request(client_socket, rfc1035_request);

    PRFC1035_Response rfc1035_response = (PRFC1035_Response) calloc(1, sizeof(RFC1035_Response));
    recv_rfc1035_response(client_socket, rfc1035_response);

    for (int i = 0; i < rfc1035_response->header->AN_COUNT; ++i) {
        PRFC1035_Answer answer = rfc1035_response->answers[i];
        if (answer->TYPE == RR_TYPE_A && answer->CLASS == RR_CLASS_IN) {
            struct in_addr addr = { 0 };
            addr.s_addr = *((uint32_t*)answer->RD_ATA);
            printf("IP:%s\n", inet_ntoa(addr));
        }
    }

    free_rfc1035_request(rfc1035_request);
    free_rfc1035_response(rfc1035_response);
    close(client_socket);
    return 0;
}
