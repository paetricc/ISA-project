//
// Created by bartu on 11.10.22.
//

#ifndef ISA_PROJECT_STRUCTURES_H
#define ISA_PROJECT_STRUCTURES_H

#include <stdint.h>

typedef	uint32_t tcp_seq;

struct tcphdr
{
    __extension__ union
    {
        struct
        {
            uint16_t th_sport{};	/* source port */
            uint16_t th_dport{};	/* destination port */
            tcp_seq th_seq{};		/* sequence number */
            tcp_seq th_ack{};		/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
            uint8_t th_x2:4;	/* (unused) */
            uint8_t th_off:4;	/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
            uint8_t th_off:4;	/* data offset */
            uint8_t th_x2:4;	/* (unused) */
# endif
            uint8_t th_flags{};
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
            uint16_t th_win{};	/* window */
            uint16_t th_sum{};	/* checksum */
            uint16_t th_urp{};	/* urgent pointer */
        };
        struct
        {
            uint16_t source;
            uint16_t dest;
            uint32_t seq;
            uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t res1:4;
            uint16_t doff:4;
            uint16_t fin:1;
            uint16_t syn:1;
            uint16_t rst:1;
            uint16_t psh:1;
            uint16_t ack:1;
            uint16_t urg:1;
            uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
            uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
            uint16_t window;
            uint16_t check;
            uint16_t urg_ptr;
        };
    };
};

struct udphdr
{
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_ulen;
    u_int16_t uh_sum;
};

#endif //ISA_PROJECT_STRUCTURES_H
