#include <stdlib.h>

#ifndef RFC1035_RFC1035_H
#define RFC1035_RFC1035_H

#define RR_TYPE_A 1
#define RR_TYPE_NS 2
#define RR_TYPE_CNAME 2

#define RR_CLASS_IN 1

typedef struct {
    uint16_t    ID;
    uint16_t    FLAGS;
    uint16_t    QD_COUNT;
    uint16_t    AN_COUNT;
    uint16_t    NS_COUNT;
    uint16_t    AR_COUNT;
}RFC1035_Header, *PRFC1035_Header;

typedef struct {
    uint8_t     Q_NAME[256];
    uint16_t    Q_TYPE;
    uint16_t    Q_CLASS;
}RFC1035_Query, *PRFC1035_Query;

typedef struct {
    uint8_t     NAME[256];
    uint16_t    TYPE;
    uint16_t    CLASS;
    uint32_t    TTL;
    uint16_t    RD_LENGTH;
    uint8_t*    RD_ATA;
}RFC1035_Answer, *PRFC1035_Answer;

typedef struct {
    PRFC1035_Header header;
    PRFC1035_Query  query;
    size_t          qname_size;
    size_t          total_size;
}RFC1035_Request, *PRFC1035_Request;

void create_rfc1035_request(PRFC1035_Request rfc1035_request, char* domain);
void free_rfc1035_request(PRFC1035_Request rfc1035_request);
void send_rfc1035_request(int client_socket, PRFC1035_Request rfc1035_request);

typedef struct {
    PRFC1035_Header header;
    PRFC1035_Answer answers[16];
}RFC1035_Response, *PRFC1035_Response;

void recv_rfc1035_response(int client_socket, PRFC1035_Response rfc1035_request);
void free_rfc1035_response(PRFC1035_Response rfc1035_response);

#endif
