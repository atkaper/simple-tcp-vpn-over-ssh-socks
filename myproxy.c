/*
 *  ---------------------------------------------------------------------------------------------------------
 *  Taken some TCP tunneling code from Christophe Devine, and turned it into a transparent socks proxy.
 *  This serves as a lightweight / poor-man's VPN connection, to combine firewalled networks into one.
 *  Requirements; use linux on your end, and you need to be able to connect to an SSH server on the
 *  network you want to reach. And the local and remote network IP-ranges should NOT overlap ;-)
 *  Note: this proxy ONLY works with TCP packets, not with UDP. So your DNS server won't work accross it.
 *
 *  --
 *  Created somewhere between 2002 and 2014. Feel free to use and modify to suit your needs.
 *  Thijs Kaper, 3 feb 2018.
 *  ---------------------------------------------------------------------------------------------------------
 *
 *  Compile using gcc (c-compiler):
 *
 *  gcc myproxy.c -o myproxy
 *
 *
 *  Use linux iptables to send traffic for certain network ranges to this proxy code.
 *  You can choose to send specific ranges to the proxy, and leave the rest of your traffic default:
 *
 *  # send single IP 172.29.29.20 to the proxy
 *  sudo iptables -t nat -A OUTPUT -p tcp -d 172.29.29.20 -j DNAT --to-destination 127.0.0.1:6021
 *
 *  # send IP range 172.30.*.* to the proxy
 *  sudo iptables -t nat -A OUTPUT -p tcp -d 172.30.0.0/16 -j DNAT --to-destination 127.0.0.1:6021
 *
 *
 *  Or you can send ALL traffic, except some ranges to the proxy like this:
 *  Note: make sure you add an exclude line for the ip address to which you are tunneling ;-)
 *  Or better; make sure your complete local network is excluded (DNS+gateway will be on there).
 *
 *  # Exclude ranges (10.*, localhost, and virtualbox 192.168.3.*, tunnel-host):
 *  sudo iptables -t nat -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
 *  sudo iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT
 *  sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.3.0/24 -j ACCEPT
 *  sudo iptables -t nat -A OUTPUT -p tcp -d <TUNNELHOSTIP> -j ACCEPT
 *
 *  # default other traffic to proxy:
 *  sudo iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:6021
 *
 *
 *  # start SSH socks tunnel to your tunnelhost:
 *  ssh -fN -D6020 youruser@TUNNELHOSTIP
 *
 *  # start tunnel software (port 6021 listens for iptables traffic, and 127.0.0.1 6020 is ssh socks tunnel):
 *  myproxy 6021 127.0.0.1 6020
 *
 *
 *  Note: before you start messing with iptables, you could make a backup of your current rules using:
 *
 *  sudo iptables-save >iptables-backup.rules
 *
 *  This can be restored using:
 *
 *  sudo iptales-restore <iptables-backup.rules
 *
 *  Or if you want to clear all rules (not recommended when you are using iptables rules, for example when
 *  running docker locally, or when using some sort of firewall package):
 *
 *  sudo iptables -t nat -F
 *  sudo iptables -t nat -X
 *  sudo iptables -t nat -L
 *
 *
 *  Knowledge about networking, ssh-keys, and c-programming helps a lot in understanding this tunnel ;-)
 *
 *  If you are in the unlucky situation where local and remote networks overlap, you can try just using single
 *  IP numbers in the connect and forwards, or... you can modify this C-code to change the network range
 *  just before sending the data on. For example, if both local and remote use 10.0.*.*, you can translate
 *  a virtual address of 192.168.*.* to the remote's 10.0.*.*, and then forward all 192.168.*.* using this
 *  proxy. Of course any DNS entries won't work anymore, so you should add entries to your /etc/hosts file in
 *  that case.
 *
 *  DISCLAIMER: I have not tried writing beautiful code ;-) It's just a hacked together M.V.P. (Minimal
 *  Viable Product). It works quite nicely, but possibly can be improved much. I do use it in this form quite
 *  regularly (many years already), and have not seen the need for more functionality/fixes yet.
 *
 *  You might also want to take a look at SSHUTTLE https://github.com/sshuttle/sshuttle it's sort of similar,
 *  but is more developed, and has more features. It can be started quite simple, for example like this:
 *
 *  # tunnel ALL traffic using sshuttle (just change the 0.0.0.0/0 into a smaller range if needed):
 *  sshuttle -r youruser@TUNNELHOSTIP 0.0.0.0/0 -v
 *
 *  It handles setting up your iptables rules for you.
 *
 *  ---------------------------------------------------------------------------------------------------------
 *  Original comment:
 *  ---------------------------------------------------------------------------------------------------------
 *
 *  Small yet efficient TCP tunneling program
 *
 *  Copyright (C) 2002  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <errno.h>

#include <time.h>

int DEBUG = 1;

void mylogf(char *fmt, ...) {
    if(!DEBUG) return;

    // START timestamp //
    char timestr[80];
    time_t t;
    struct tm *tmp;
    t = time(NULL);
    tmp = localtime(&t);
    strftime(timestr, sizeof(timestr), "%d/%B/%Y:%X", tmp);
    // END timestamp //

    char p[2000];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p, sizeof(p), fmt, ap);
    va_end(ap);

    printf("%s - %d - %s\n", timestr, getpid(), p);  
}


int main( int argc, char *argv[] )
{
    unsigned char buffer[1024];
    int pid, client, tunnel, server, n;
    struct sockaddr_in tunnel_addr, client_addr, server_addr;

    /* first, check the arguments */

    if( argc != 4 )
    {
        printf( "usage: %s <local port> <remote IP> <remote port>\n", argv[0] );
        return( 1 );
    }

    /* fork into background */

    if( !DEBUG && ( pid = fork() ) < 0 )
    {
        return( 1 );
    }

    if( !DEBUG && pid ) return( 0 );

    /* create a new session */
    if (!DEBUG) {
       if( setsid() < 0 )
       {
           return( 1 );
       }
    }

    /* close all file descriptors */
    if (!DEBUG) {
       for( n = 0; n < 1024; n++ )
       {
        close( n );
       }
    }

    /* create a socket */

    tunnel_addr.sin_family      = AF_INET;
    tunnel_addr.sin_port        = htons( atoi( argv[1] ) );
    tunnel_addr.sin_addr.s_addr = INADDR_ANY;

    if( ( tunnel = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
    {
        return( 1 );
    }

    /* bind the tunnel on the local port and listen */

    n = 1;

    if( setsockopt( tunnel, SOL_SOCKET, SO_REUSEADDR,
                    (void *) &n, sizeof( n ) ) < 0 )
    {
        return( 1 );
    }

    if( bind( tunnel, (struct sockaddr *) &tunnel_addr,
              sizeof( tunnel_addr ) ) < 0 )
    {
        return( 1 );
    }

    if( listen( tunnel, 5 ) != 0 )
    {
        return( 1 );
    }

    if(DEBUG) mylogf("bind/listen port %d", atoi( argv[1] ) );

    while( 1 )
    {
        n = sizeof( client_addr );

        /* wait for inboud connections */

        //if(DEBUG) mylogf("wait for connection...");

        if( ( client = accept( tunnel, (struct sockaddr *)
                                &client_addr, &n ) ) < 0 )
        {
            return( 1 );
        }

        /* fork a child to handle the connection */

        if( ( pid = fork() ) < 0 )
        {
            close( client );
            continue;
        }

        if( pid )
        {
            /* in father - wait for the child to terminate */

            close( client );
            waitpid( pid, NULL, 0 );
            continue;
        }

        /* the child forks and then exits so that the grand-child's
         * father becomes init (this to avoid becoming a zombie) */

        if( ( pid = fork() ) < 0 )
        {
            return( 1 );
        }

        if( pid ) return( 0 );

//        if(DEBUG) printf("got a connection, ended up in a forked process... start handling it...");


        /////////// get original destination ip/port from kernel //////////////
        struct sockaddr_in peer;
        socklen_t SLen = sizeof(peer);
        memset(&peer, 0, SLen);
        getsockopt(client, SOL_IP, SO_ORIGINAL_DST, &peer, &SLen);
        mylogf( "Connection request for: %s:%hu", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
        ////////////////////////////////////////////////////////////////////////


        /* now connect to the remote server */

        server_addr.sin_family          = AF_INET;
        server_addr.sin_addr.s_addr     = inet_addr( argv[2] );
        server_addr.sin_port            = htons( atoi( argv[3] ) );

        if( ( server = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
        {
            return( 1 );
        }


        /////////// timeout stuff ///////////////////
        struct timeval tv;
        int timeouts = 0;
        tv.tv_sec = 15;
        tv.tv_usec = 0;
        if (setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,  sizeof tv))
        {
          perror("setsockopt timeout");
          return -1;
        }
        ////////////////


        //if(DEBUG) mylogf("start connection to remote server %s:%s", argv[2], argv[3]);

        if( connect( server, (struct sockaddr *) &server_addr,
                     sizeof( server_addr ) ) < 0 )
        {
            if(DEBUG) mylogf("connection failed err %d", errno);
            return( 1 );
        }

        //if(DEBUG) mylogf("connected");


        //////////////////////////////////////////////////////////////////////
        // For socks proxying, send socks request header, and read response
        // Only after this "negotiation" start tunneling...
        // On error, immediately disconnect.
        //////////////////////////////////////////////////////////////////////

#pragma pack(1)
        struct {
		char version; /* must be 4 */
		char mode; /* connect must be 1 */
                uint16_t port;
                in_addr_t address;
                char user_zero; /* zero terminated user id... (just the zero here...)*/
        } sock4_request;

        struct {
        	char version; /* will be 0 */
		char status; /* should be 90 for OK, any other = fail */
		uint16_t port;
		in_addr_t address;
	} sock4_response;
#pragma pack()

        // Note: if networks overlap, change peer.sin_addr.s_addr to remap the ip-ranges.
        // For example if both networks are 10.0.*, you could replace a virtual 192.168.* by 10.0.*
//      // NEXT LINES ARE PSEUDO-CODE; you can not use peer.sin_addr.s_addr[#] like this, sorry ;-)
//      if (peer.sin_addr.s_addr[0] == 192 && peer.sin_addr.s_addr[1] == 168) {
//         peer.sin_addr.s_addr[0] = 10; peer.sin_addr.s_addr[1] = 0;
//      }

        sock4_request.version = 4;
        sock4_request.mode = 1;
        sock4_request.port = peer.sin_port;
        sock4_request.address = peer.sin_addr.s_addr;
        sock4_request.user_zero = 0;

//        char *px;
//        px = (char *) &sock4_request;
//        int x;
//        for(x=0; x<9; x++) {
//           printf("%d - %u", x, *px);
//           px++;
//        }

        if (sizeof(sock4_request)!=9) {
           mylogf("!!! SOCK4 STRUCT not 9 ?? !!!!!! PROBLEM !");
           exit(1);
        }
//        if(DEBUG) printf("going to send sock4 request of %lu bytes...", sizeof(sock4_request));
        int s4n = send(server, &sock4_request, sizeof(sock4_request), 0);
//        if(DEBUG) printf("send result %u", s4n);

	//mylogf("wait for sock result");

	// now get response
	s4n = recv( server, &sock4_response, sizeof(sock4_response) , 0 );
	if (s4n != sizeof(sock4_response)) {
		mylogf("Wrong reponse length %d.", s4n);
		exit(1);
	}

//	px = (char *) &sock4_response;
//	for(x=0; x<9; x++) {
//           printf("%d - %u", x, *px);
//           px++;
//        }

	if (sock4_response.status != 90) {
		mylogf("Wrong socks status code. Must be 90, is %d", sock4_response.status);
		exit(1);
	}

        //////////////////////////////////////////////////////////////////////

        //if(DEBUG) mylogf("connected, start raw proxying...");

        /* start tunneling the data between the client and the server */

        int dataLogged = 0; // flag for logging first packet

        while( 1 )
        {
            fd_set rd;

            FD_ZERO( &rd );
            FD_SET( server, &rd );
            FD_SET( client, &rd );
   
            n = ( client > server ) ? client : server;

            if( select( n + 1, &rd, NULL, NULL, NULL ) < 0 )
            {
                if(DEBUG) mylogf("end connection: main select");
                return( 1 );
            }

            if( FD_ISSET( server, &rd ) )
            {
                if( ( n = recv( server, buffer, 1024, 0 ) ) < 0 )
                {
                    if(DEBUG) mylogf("end connection: server receive exit");
                    return( 1 );
                }
                if( n == 0 )
                {
                    if(DEBUG) mylogf("end connection: server receive end");
                    return( 0 );
                }
                if( send( client, buffer, n, 0 ) != n )
                {
                    if(DEBUG) mylogf("end connection: client send incomplete / closed");
                    return( 1 );
                }
            }

            if( FD_ISSET( client, &rd ) )
            {
                if( ( n = recv( client, buffer, 1024, 0 ) ) < 0 )
                {
                    if(DEBUG) mylogf("end connection: client receive exit");
                    return( 1 );
                }
                if( n == 0 )
                {
                    if(DEBUG) mylogf("end connection: client receive end");
                    return( 0 );
                }
                // log first data packet (example, first line of http get)
                if (dataLogged == 0) {
                    dataLogged=1;
                    char printData[100];
                    strncpy(printData, buffer, (n<99?n:99));
                    printData[99]=0;
                    int px;
                    for(px=0;px<(n<99?n:99);px++) {
                       if (printData[px]<' ' || printData[px]>127) printData[px]='.';
                    }
                    mylogf("Data: %s", printData);
                }
                if( send( server, buffer, n, 0 ) != n )
                {
                    if(DEBUG) mylogf("end connection: send server incomplete / closed");
                    return( 1 );
                }
            }
        }
    }

    /* not reached */

    return( 0 );
}

