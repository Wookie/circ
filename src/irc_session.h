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

#include <limits.h>

#include <cutil/hashtable.h>

#include "irc_modes.h"

#define IRC_PARAM_LEN	(512)

typedef enum irc_session_setting_e
{
	SERVER_PORT			= 0xea1146cd,
	SERVER_HOST			= 0x602099fa,
	NICK_NAME			= 0x1606207d,
	USER_NAME			= 0x20d80d65,
	REAL_NAME			= 0x4215b8fe,
	SERVER_PASS			= 0x01026017,
	NICKSERV_PASS		= 0xcfcd5833,
	QUIT_MSG			= 0xcc785413,
	HOST_NAME			= 0x42eceb90,
	USER_MODES			= 0x27d18a34,
	USER_MODES_PARAM	= 0xdb4324d7,
	CHANNEL_MODES		= 0x9b5b9912,
	CHANNEL_MODES_PARAM = 0xff946081,
	SERVER_MODES		= 0xf4efe58c,
	SERVER_MODES_PARAM	= 0xc8500f7f,
	SERVER_VERSION		= 0xa73860b0

} irc_session_setting_t;

typedef enum irc_session_state_e
{
	IRC_SESSION_DISCONNECTED,
	IRC_SESSION_CONNECTED,
	IRC_SESSION_ACTIVE,
	IRC_SESSION_QUIT,
	IRC_SESSION_PENDING_DISCONNECT

} irc_session_state_t;

#define HANDLER_FIRST (INT_MAX)
#define HANDLER_LAST (INT_MIN)

typedef struct irc_session_s irc_session_t;

typedef irc_ret_t (*event_handler_fn)(irc_session_t * const session, 
									  irc_msg_t * const msg, 
									  void * user_data);
#define HANDLER_FN(x) irc_ret_t session_##x##_handler( irc_session_t * const session, \
													   irc_msg_t * const msg, \
													   void * user_data )
#define SET_HANDLER(x, y) irc_session_set_handler( session, x, &session_##x##_handler, y )

#define HANDLER(x) session_##x##_handler

/* create/destroy session */
irc_session_t * irc_session_new( evt_loop_t * const evt,
								 void * user_data );
void irc_session_delete( void * s );

/* get/set functions for session settings */
irc_ret_t irc_session_set( irc_session_t * const session,
						   irc_session_setting_t const setting,
						   void * const value );
void * irc_session_get( irc_session_t * const session,
					    irc_session_setting_t const setting );

/* add a handler for an IRC event
 *
 * event_name - a string name for an IRC event, for the full list*/
irc_ret_t irc_session_set_handler( irc_session_t * const session,
								   irc_command_t const cmd,
								   event_handler_fn event_handler,
								   int const priority );

/* connect/disconnect from the server */
irc_ret_t irc_session_connect( irc_session_t * const session );
irc_ret_t irc_session_disconnect( irc_session_t * const session, int do_quit );

#endif//__IRC_SESSION__H__

