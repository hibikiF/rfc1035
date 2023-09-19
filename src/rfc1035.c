#include "rfc1035.h"
#include <memory.h>

#include <unistd.h>
#include <stdbool.h>

#define DNS_POINTER_FLAG_VALUE 0xc0
#define DNS_POINTER_FLAG_MASK (0b11 << 14)

size_t name_ascii_to_wire(char *domainName, uint8_t *wireBuf)
{
    char* namePtr = domainName;
    uint8_t* wirePtr = wireBuf;
    size_t totalLength = 0;
    while (1) {
        uint8_t labelLen = 0;
        char *labelPtr = namePtr;
        while (*labelPtr != '.' && *labelPtr != '\0') {
            labelLen++;
            labelPtr++;
        }

        *wirePtr++ = labelLen;
        totalLength++;

        while (namePtr != labelPtr) {
            *wirePtr++ = (unsigned char) *namePtr;
            namePtr++;
            totalLength++;
        }

        if (*namePtr == '\0') {
            break;
        }

        namePtr++;
    }
    *wirePtr = 0;
    totalLength++;
    return totalLength;
}

void create_rfc1035_request(PRFC1035_Request rfc1035_request, char* domain) {
    rfc1035_request->header = (PRFC1035_Header) malloc(sizeof(RFC1035_Header));
    memset(rfc1035_request->header, 0, sizeof(RFC1035_Header));

    rfc1035_request->query = (PRFC1035_Query) malloc(sizeof(RFC1035_Query));
    memset(rfc1035_request->query, 0, sizeof(RFC1035_Query));

    rfc1035_request->header->ID       = htons(0xdb42);
    rfc1035_request->header->FLAGS    = htons(0x0100);
    rfc1035_request->header->QD_COUNT = htons(0x0001);

    rfc1035_request->qname_size     = name_ascii_to_wire(domain, rfc1035_request->query->Q_NAME);
    rfc1035_request->query->Q_CLASS = htons(RR_CLASS_IN);
    rfc1035_request->query->Q_TYPE  = htons(RR_TYPE_A);

    rfc1035_request->total_size = sizeof(RFC1035_Header) + rfc1035_request->qname_size + sizeof(uint16_t) * 2;
}

void free_rfc1035_request(PRFC1035_Request rfc1035_request) {
    free(rfc1035_request->header);
    free(rfc1035_request->query);
    free(rfc1035_request);
    rfc1035_request = NULL;
}


void send_rfc1035_request(int client_socket, PRFC1035_Request rfc1035_request) {
    uint8_t* request = calloc(sizeof(uint8_t), rfc1035_request->total_size);

    void* first = request;
    void* end  = request + rfc1035_request->total_size;

    memcpy(first, rfc1035_request->header, sizeof(RFC1035_Header));
    first += sizeof(RFC1035_Header);

    memcpy(first, rfc1035_request->query->Q_NAME, rfc1035_request->qname_size);
    first += rfc1035_request->qname_size;

    memcpy(first, &rfc1035_request->query->Q_TYPE, sizeof(uint16_t));
    first += sizeof(uint16_t);

    memcpy(first, &rfc1035_request->query->Q_CLASS, sizeof(uint16_t));
    first += sizeof(uint16_t);

    if (first != end) {
        goto EXIT;
    }

    write(client_socket, request, rfc1035_request->total_size);

    EXIT:
    free(request);
}

void recv_rfc1035_response(int client_socket, PRFC1035_Response rfc1035_response) {
    rfc1035_response->header = malloc(sizeof(RFC1035_Header));
    memset(rfc1035_response->header, 0, sizeof(RFC1035_Header));

    uint8_t response[256] = { 0 };
    read(client_socket, response, 256);

    uint16_t* header_first = ((uint16_t*)(&response));

    rfc1035_response->header->ID       = (*header_first++);
    rfc1035_response->header->FLAGS    = ntohs(*header_first++);
    rfc1035_response->header->QD_COUNT = ntohs(*header_first++);
    rfc1035_response->header->AN_COUNT = ntohs(*header_first++);
    rfc1035_response->header->NS_COUNT = ntohs(*header_first++);
    rfc1035_response->header->AR_COUNT = ntohs(*header_first++);

    uint8_t* first = ((uint8_t*)header_first);

    // skip Question
    for (int i = 0; i < rfc1035_response->header->QD_COUNT; ++i) {
        while (true) {
            if (*first == 0x00) {
                break;
            }
            first += (*first) + 1;
        }

        first += 5;
    }

    memset(rfc1035_response->answers, 0, sizeof(rfc1035_response->answers));

    for (int i = 0; i < rfc1035_response->header->AN_COUNT; ++i) {
        if (i >= 16) {
            break;
        }

        PRFC1035_Answer answer = (PRFC1035_Answer)calloc(1, sizeof(RFC1035_Answer));
        rfc1035_response->answers[i] = answer;

        uint8_t* name_first = (uint8_t*)&answer->NAME;
        memset(name_first, 0 , 256);

        if (*first >= DNS_POINTER_FLAG_VALUE) {
            uint32_t firstByte = *first << 8;
            uint32_t nextByte = *(first + 1);

            size_t offset = (firstByte + nextByte) - DNS_POINTER_FLAG_MASK;
            uint8_t* base = ((uint8_t*)&response) + offset;

            while (true) {
                if (*base == 0x00) {
                    break;
                }
                size_t size = (*base) + 1;

                memcpy(name_first, base, size);
                name_first += size;
                base += size;
            }
            first += 2;
        } else {
            while (true) {
                if (*first == 0x00) {
                    first += 1;
                    break;
                }

                size_t size = (*first) + 1;

                memcpy(name_first, first, size);
                name_first += size;
                first += size;
            }
        }

        uint16_t* answer_first = ((uint16_t*)(first));

        answer->TYPE  = ntohs(*answer_first++);
        answer->CLASS = ntohs(*answer_first++);
        answer->TTL   = ntohl(*((uint32_t*)answer_first));
        answer_first += 2;
        answer->RD_LENGTH = ntohs(*answer_first++);

        answer->RD_ATA = calloc(answer->RD_LENGTH, sizeof(uint8_t));
        memcpy(answer->RD_ATA, answer_first, answer->RD_LENGTH);

        first = (((uint8_t*)answer_first) + answer->RD_LENGTH);
    }
}

void free_rfc1035_response(PRFC1035_Response rfc1035_response) {
    for (int i = 0; i < rfc1035_response->header->AN_COUNT; ++i) {
        free(rfc1035_response->answers[i]->RD_ATA);
        free(rfc1035_response->answers[i]);
    }

    free(rfc1035_response->header);
    free(rfc1035_response);
    rfc1035_response = NULL;
}
