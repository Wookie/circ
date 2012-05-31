/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with main.c; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301,  USA
 */

#ifndef __IRC_CONN_H__
#define __IRC_CONN_H__

#include <cutil/socket.h>
#include <cutil/array.h>

#define IRC_READ_BUF (4 * IRC_MSG_SIZE)

typedef struct irc_conn_s irc_conn_t;

typedef struct irc_conn_ops_s
{
	irc_ret_t (*message_in)(irc_conn_t * const conn, 
							irc_msg_t * const msg, 
							void * user_data );
	irc_ret_t (*message_out)(irc_conn_t * const conn, 
							 irc_msg_t * const msg, 
							 void * user_data );
	irc_ret_t (*connected)(irc_conn_t * const conn, 
						   void * user_data);
	irc_ret_t (*disconnected)(irc_conn_t * const conn, 
							  void * user_data);

} irc_conn_ops_t;


/* these function allocate/deallocate the opaque handle */
irc_conn_t* irc_conn_new( irc_conn_ops_t * const ops,	/* callbacks for irc messages */
						  evt_loop_t * const el,	/* event loop to use */
						  void * user_data);		/* user data passed back to callbacks */

/* delete an irc cx */
void irc_conn_delete( void * c );

/* these functions handle connecting/disconnecting to/from servers */
irc_ret_t irc_conn_connect( irc_conn_t* const irc,
							int8_t const * const server_host,
							uint16_t const server_port );
irc_ret_t irc_conn_disconnect( irc_conn_t* const irc, int do_wait );

/* send the specified IRC command to the server */
irc_ret_t irc_conn_send_msg( irc_conn_t* const irc, irc_msg_t* const msg );

#endif /*__IRC_CONN_H__*/
 
