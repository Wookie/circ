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

#ifndef IRC_EVENT_CB_H
#define IRC_EVENT_CB_H

typedef struct irc_event_cb_s irc_event_cb_t;

/* the type of the callback function */
typedef irc_ret_t (*event_cb_fn)( irc_session_t * const session, 
								  irc_msg_t * const msg, 
								  void * user_data );

#define HANDLER(x, y) fn_##x##_##y##_fn
#define HANDLER_FN(x, y) irc_ret_t HANDLER(x,y)( irc_session_t * const session, \
												 irc_msg_t * const msg, \
												 void * user_data )

#define HANDLER_NAME( x, y ) #x "-" #y
#define NEW_HANDLER( x, y, z ) irc_event_cb_new( HANDLER_NAME(z,x), y, x, HANDLER(z,x), z )

/* new/delete irc_event_cb_t structs */
irc_event_cb_t* irc_event_cb_new( uint8_t const * const name,
								  irc_session_t * const session,
								  irc_command_t const cmd,
								  event_cb_fn fn,
								  void * user_data );
void irc_event_cb_delete( void * c );

/* get the command for the event cb */
irc_command_t irc_event_cb_get_cmd( irc_event_cb_t * const cb );

/* used to call the callback function */
irc_ret_t irc_event_cb_call_fn( irc_event_cb_t * const cb, irc_msg_t * const msg );

/* helpers for storing irc_event_cb_t structs in a hash table */
ht_itr_t irc_event_cb_ht_find( ht_t * const ht, uint8_t const * const name );
uint_t irc_event_cb_hash( void const * const key );
int irc_event_cb_match( void const * const l, void const * const r );

#endif/*IRC_EVENT_CB_H*/

