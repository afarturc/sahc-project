#ifndef _SAHC_FRAMING_H_
#define _SAHC_FRAMING_H_

#include <stddef.h>
#include <stdint.h>

// Wire frame: [type(1) | len(4 BE) | payload(len)]
//
// Sends a full frame. payload may be NULL iff len == 0.
// Returns 0 on success, -1 on error.
int frame_send(int fd, uint8_t type, const uint8_t* payload, uint32_t len);

// Reads a full frame into caller-provided buffer. On success, writes the
// message type to *type_out and payload length to *len_out (may be 0), and
// the first *len_out bytes of buf are the payload.
//
// Returns:
//   0 on success
//  -1 on I/O error or oversize payload (> buf_cap or > FRAME_MAX_PAYLOAD)
//   1 on clean peer EOF before any bytes received
int frame_recv(int fd,
               uint8_t* type_out,
               uint8_t* buf, uint32_t buf_cap,
               uint32_t* len_out);

#endif
