//
//  HelperDaemon-Bridging-Header.h
//  HelperDaemon
//
//  Bridging header aggregato per il target HelperDaemon.
//  Include i wrapper C per libpcap e raw socket.
//

#ifndef HelperDaemon_Bridging_Header_h
#define HelperDaemon_Bridging_Header_h

#include "pcap_bridge.h"
#include "raw_socket.h"

#include <sys/ioctl.h>
#include <termios.h>

// Wrapper non-variadic per ioctl(TIOCSWINSZ): Swift non può chiamare ioctl variadica.
static inline int pty_set_winsize(int fd, unsigned short rows, unsigned short cols) {
    struct winsize ws;
    ws.ws_row = rows;
    ws.ws_col = cols;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    return ioctl(fd, TIOCSWINSZ, &ws);
}

#endif /* HelperDaemon_Bridging_Header_h */
