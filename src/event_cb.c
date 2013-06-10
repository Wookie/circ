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

#define DEBUG_ON

#include <cutil/debug.h>
#include <cutil/macros.h>

#include "commands.h"
#include "msg.h"
#include "session.h"
#include "event_cb.h"

struct irc_event_cb_s
{
	uint8_t const *		name;
	irc_session_t *		session;
	irc_command_t		cmd;
	event_cb_fn			fn;
	void *				user_data;

};

irc_event_cb_t* irc_event_cb_new( uint8_t const * const name,
								  irc_session_t * const session,
								  irc_command_t const cmd,
								  event_cb_fn fn,
								  void * user_data )
{
	irc_event_cb_t * cb = NULL;

	CHECK_PTR_RET( session, NULL );
	CHECK_RET( IS_VALID_COMMAND( cmd ), NULL );
	CHECK_PTR_RET( fn, NULL );

	cb = CALLOC( 1, sizeof( irc_event_cb_t ) );
	CHECK_PTR_RET( cb, NULL );

	cb->name = strdup( name );
	CHECK_PTR_GOTO( cb->name, irc_event_cb_new_fail );

	cb->session = session;
	cb->cmd = cmd;
	cb->fn = fn;
	cb->user_data = user_data;

	return cb;

irc_event_cb_new_fail:
	FREE( cb );
	return NULL;
}


void irc_event_cb_delete( void * c )
{
	irc_event_cb_t * cb = (irc_event_cb_t*)c;
	CHECK_PTR( cb );

	FREE( cb );
}

irc_command_t irc_event_cb_get_cmd( irc_event_cb_t * const cb )
{
	CHECK_PTR_RET( cb, NOCMD );
	return cb->cmd;
}

irc_ret_t irc_event_cb_call_fn( irc_event_cb_t * const cb, irc_msg_t * const msg )
{
	CHECK_PTR_RET( cb, IRC_BADPARAM );
	CHECK_PTR_RET( cb->fn, IRC_ERR );

	return (*(cb->fn))( cb->session, msg, cb->user_data );
}

ht_itr_t irc_event_cb_ht_find( ht_t * const ht, uint8_t const * const name )
{
	irc_event_cb_t cb;
	CHECK_PTR_RET( ht, ht_itr_end( ht ) );
	CHECK_PTR_RET( name, ht_itr_end( ht ) );

	MEMSET( &cb, 0, sizeof( irc_event_cb_t ) );

	cb.name = name;

	return ht_find( ht, &cb );
}

#define FNV_PRIME (0x01000193)
static uint32_t fnv_string_hash(void const * const key)
{
    uint32_t hash = 0x811c9dc5;
	uint8_t const * p = (uint8_t const *)key;
	while ( (*p) != '\0' )
	{
		hash *= FNV_PRIME;
		hash ^= *p++;
	}
	return hash;
}

uint_t irc_event_cb_hash( void const * const key )
{
	irc_event_cb_t * cb = (irc_event_cb_t*)key;
	return fnv_string_hash( cb->name );
}

static int string_eq( void const * const l, void const * const r )
{
	return ( 0 == strcmp(C(l), C(r)) );
}

int irc_event_cb_match( void const * const l, void const * const r )
{
	irc_event_cb_t * lcb = (irc_event_cb_t*)l;
	irc_event_cb_t * rcb = (irc_event_cb_t*)r;
	return string_eq( lcb->name, rcb->name );
}


