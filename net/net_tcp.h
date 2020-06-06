/*
 * Copyright (C) 2015 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * history:
 * ---------
 *  2015-01-xx  created (razvanc)
 */

#ifndef _NET_TCP_H_
#define _NET_TCP_H_

#include "../mi/mi.h"
#include "tcp_conn_defs.h"
#include "net_tcp_dbg.h"

#define TCP_PARTITION_SIZE 32

/**************************** Control functions ******************************/

/* initializes the TCP structures */
int tcp_init(void);

/* destroys the TCP data */
void tcp_destroy(void);

/* checks if the TCP layer may provide async write support */
int tcp_has_async_write(void);

/* creates the communication channel between a generic OpenSIPS process
   and the TCP MAIN process - TO BE called before forking */
int tcp_pre_connect_proc_to_tcp_main( int proc_no );

/* same as above, but to be called after forking, both in child and parent */
void tcp_connect_proc_to_tcp_main( int proc_no, int chid );

/* tells how many processes the TCP layer will create */
int tcp_count_processes(void);

/* starts all TCP worker processes */
int tcp_start_processes(int *chd_rank, int *startup_done);

/* starts the TCP listening process */
int tcp_start_listener(void);

/* MI function to list all existing TCP connections */
struct mi_root *mi_tcp_list_conns(struct mi_root *cmd, void *param);


/************************* TCP net helper functions **************************/

/* initializes an already defined TCP listener */
int tcp_init_listener(struct socket_info *si);

/* helper function to set all TCP related options to a socket */
int tcp_init_sock_opt_dbg(int s, const char *file, unsigned int line, const char *func);
#define tcp_init_sock_opt(s) tcp_init_sock_opt_dbg((s),__FILE__,__LINE__,__FUNCTION__)

/* blocking connect on a non-blocking socket */
int tcp_connect_blocking(int s, const struct sockaddr *servaddr,
		socklen_t addrlen);

/* blocking connect on a non-blocking socket with timeout */
int tcp_connect_blocking_timeout(int s, const struct sockaddr *servaddr,
		socklen_t addrlen, int timeout);

/********************** TCP conn management functions ************************/

/* returns the connection identified by either the id or the destination to */
int tcp_conn_get_dbg(int id, struct ip_addr* ip, int port, enum sip_protos proto,
		struct tcp_connection** conn, int* conn_fd, const char *file, unsigned int line, const char *func);

#define tcp_conn_get(id,ip,port,proto,conn,conn_fd) \
	tcp_conn_get_dbg((id),(ip),(port),(proto),(conn),(conn_fd), __FILE__,__LINE__,__FUNCTION__)

/* creates a new tcp conn around a newly connected socket
 * and sends it to the master */
struct tcp_connection* tcp_conn_create_dbg(int sock, union sockaddr_union* su,
		struct socket_info* si, int state, const char *file, unsigned int line, const char  *func);
#define tcp_conn_create(sock,su,si,state) tcp_conn_create_dbg((sock),(su),(si),(state),__FILE__,__LINE__,__FUNCTION__)

/* creates a new tcp conn around a newly connected socket */
#define tcp_conn_new(sock,su,si,state) tcp_conn_new_dbg((sock),(su),(si),(state),__FILE__,__LINE__,__FUNCTION__)
struct tcp_connection* tcp_conn_new_dbg(int sock, union sockaddr_union* su,
		struct socket_info* si, int state, const char *file, unsigned int line, const char *func);

/* sends a connected connection to the master */
int tcp_conn_send(struct tcp_connection *con);

/* release a connection acquired via tcp_conn_get() or tcp_conn_create() */
#define tcp_conn_release(c,pending_data) tcp_conn_release_dbg((c),(pending_data),__FILE__,__LINE__,__FUNCTION__)
void tcp_conn_release_dbg(struct tcp_connection* c, int pending_data, const char *file, unsigned int line, const char *func);

/* destroys a connection before sending it to main */
void tcp_conn_destroy_dbg(struct tcp_connection* tcpconn, const char *file, unsigned int line, const char *func);
#define tcp_conn_destroy(tcpconn) tcp_conn_destroy_dbg((tcpconn), __FILE__,__LINE__,__FUNCTION__)

/* used to tune the connection attributes */
int tcp_conn_fcntl(struct receive_info *rcv, int attr, void *value);

/* returns the correlation ID of a TCP connection */
int tcp_get_correlation_id( int id, unsigned long long *cid);

extern int last_outgoing_tcp_id;

#endif /* _NET_TCP_H_ */
