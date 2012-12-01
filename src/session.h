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

#include <cutil/events.h>
#include <cutil/hashtable.h>

#include "commands.h"
#include "modes.h"
#include "msg.h"
#include "conn.h"

#define IRC_PARAM_LEN	(512)

typedef enum irc_session_setting_e
{
	SERVER_PORT			= 0xea1146cd,
	SERVER_HOST			= 0x602099fa,
	NICK_NAME			= 0x1606207d,
	USER_NAME			= 0x20d80d65,
	REAL_NAME			= 0x4215b8fe,
	SERVER_PASS			= 0x01026017,
	QUIT_MSG			= 0xcc785413,

} irc_session_setting_t;

typedef enum irc_session_state_e
{
	IRC_SESSION_DISCONNECTED,
	IRC_SESSION_CONNECTED,
	IRC_SESSION_ACTIVE,
	IRC_SESSION_QUIT,
	IRC_SESSION_PENDING_DISCONNECT

} irc_session_state_t;

typedef struct irc_session_s irc_session_t;
typedef struct irc_event_cb_s irc_event_cb_t;

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

/* add a callback function for the given command at a certain priority */
irc_ret_t irc_session_set_handler( irc_session_t * const session,
								   irc_event_cb_t * const cb );
irc_ret_t irc_session_clear_handler( irc_session_t * const session,
									 uint8_t const * const name );

/* connect/disconnect from the server */
irc_ret_t irc_session_connect( irc_session_t * const session );
irc_ret_t irc_session_disconnect( irc_session_t * const session, int do_quit );

/* send the specified IRC command to the server */
irc_ret_t irc_session_send_msg( irc_session_t * const session, irc_msg_t * const msg );


#endif//__IRC_SESSION__H__

