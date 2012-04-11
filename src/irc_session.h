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

#ifndef __IRC_SESSION_H__
#define __IRC_SESSION_H__

#include "irc_modes.h"
#include "hashtable.h"

#define IRC_PARAM_LEN	(512)

#define SERVER_PORT_KEY (T("server port"))
#define SERVER_PORT_HASH (0xea1146cd)
#define SERVER_HOST_KEY (T("server host"))
#define SERVER_HOST_HASH (0x602099fa)
#define NICK_NAME_KEY (T("nick name"))
#define NICK_NAME_HASH (0x1606207d)
#define USER_NAME_KEY (T("user name"))
#define USER_NAME_HASH (0x20d80d65)
#define REAL_NAME_KEY (T("real name"))
#define REAL_NAME_HASH (0x4215b8fe)
#define SERVER_PASS_KEY (T("server pass"))
#define SERVER_PASS_HASH (0x01026017)
#define NICKSERV_PASS_KEY (T("nickserv pass"))
#define NICKSERV_PASS_HASH (0xcfcd5833)
#define QUIT_MSG_KEY (T("quit msg"))
#define QUIT_MSG_HASH (0xcc785413)
#define HOST_NAME_KEY (T("host name"))
#define HOST_NAME_HASH (0x42eceb90)
#define USER_MODES_KEY (T("user modes"))
#define USER_MODES_HASH (0x27d18a34)
#define USER_MODES_PARAM_KEY (T("user modes param"))
#define USER_MODES_PARAM_HASH (0xdb4324d7)
#define CHANNEL_MODES_KEY (T("channel modes"))
#define CHANNEL_MODES_HASH (0x9b5b9912)
#define CHANNEL_MODES_PARAM_KEY (T("channel modes param"))
#define CHANNEL_MODES_PARAM_HASH (0xff946081)
#define SERVER_MODES_KEY (T("server modes"))
#define SERVER_MODES_HASH (0xf4efe58c)
#define SERVER_MODES_PARAM_KEY (T("server modes param"))
#define SERVER_MODES_PARAM_HASH (0xc8500f7f)
#define SERVER_VERSION_KEY (T("server version"))
#define SERVER_VERSION_HASH (0xa73860b0)

typedef enum irc_session_state_e
{
	IRC_SESSION_DISCONNECTED,
	IRC_SESSION_CONNECTED,
	IRC_SESSION_PASS,
	IRC_SESSION_NICK,
	IRC_SESSION_USER,
	IRC_SESSION_ACTIVE,
	IRC_SESSION_QUIT,
	IRC_SESSION_PENDING_DISCONNECT

} irc_session_state_t;

typedef struct irc_session_ops_s irc_session_ops_t;
typedef struct irc_session_s irc_session_t;

struct irc_session_s
{
	irc_session_state_t state;					/* session state */

	evt_loop_t*			el;						/* event loop */

	struct irc_session_ops_s
	{
		irc_ret_t (*command)(irc_session_t * const session, 
							 irc_msg_t * const msg, 
							 void * user_data);
		irc_ret_t (*reply)(irc_session_t * const session, 
						   irc_msg_t * const msg, 
						   void * user_data);
		irc_ret_t (*error)(irc_session_t * const session, 
						   irc_msg_t * const msg, 
						   void * user_data);
		irc_ret_t (*connected)(irc_session_t * const session, void * user_data);
		irc_ret_t (*disconnected)(irc_session_t * const session, void * user_data);

	}					ops;					/* session callbacks */
	void *				user_data;				/* callback context */

	irc_conn_t			conn;							/* irc connection */
	ht_t*				settings;						/* hashtable of settings */
};

void irc_session_initialize( irc_session_t * const session,
							 irc_session_ops_t * const ops,
							 evt_loop_t * const evt,
							 void * user_data );
void irc_session_deinitialize( irc_session_t * const session );

irc_session_t * irc_session_new( irc_session_ops_t * const ops,
								 evt_loop_t * const evt,
								 void * user_data );
void irc_session_delete( void * s );

/* get/set functions */
irc_ret_t irc_session_set( irc_session_t * const session,
						   int8_t * const key,
						   void * const value );
irc_ret_t irc_session_set_prehash( irc_session_t * const session,
								   uint32_t const hash,
								   int8_t * const key,
								   void * const value );
void * irc_session_get( irc_session_t * const session,
					    int8_t const * const key );
void * irc_session_get_prehash( irc_session_t * const session,
						  	    uint32_t const hash,
								int8_t const * const key );

irc_ret_t irc_session_connect( irc_session_t * const session );
irc_ret_t irc_session_disconnect( irc_session_t * const session, int do_quit );

#endif//__IRC_SESSION__H__

