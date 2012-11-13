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
#include <cutil/list.h>

#include "commands.h"
#include "msg.h"
#include "conn.h"
#include "channel.h"
#include "session.h"

HANDLER_FN( RPL_NAMREPLY )
{
	uint8_t * name = NULL;
	uint8_t * nick = NULL;
	uint8_t * s = NULL;
	uint8_t * f = NULL;
	ht_itr_t itr;
	irc_channel_t * chan = NULL;
	chan = (irc_channel_t*)irc_session_get_channel( session, msg->parameters[0] );
	CHECK_PTR_RET( chan, IRC_ERR );

	name = msg->parameters[0];
	if ( (name[0] == '@') || (name[0] == '*') || (name[0] == '=') )
		name++;

	s = f = msg->trailing;
	while ( *f != '\0' )
	{
		if ( *f == ' ' )
		{
			/* trim flag */
			if ( (*s == '@') || (*s == '+') )
			{
				s++;
			}
			strncpy( nick, s, (f - s) );
			f++;
			s = f;
			list_push_tail( chan->clients, nick );

			/* TODO: call user hook */
		}
		else
		{
			f++;
		}
	}

	return IRC_OK;
}

HANDLER_FN( RPL_ENDOFNAMES )
{
	ht_itr_t itr;
	list_itr_t nitr, nend;
	uint8_t * name = NULL;
	irc_channel_t * chan = NULL;
	chan = (irc_channel_t*)irc_session_get_channel( session, msg->parameters[0] );
	CHECK_PTR_RET( chan, IRC_ERR );

	nitr = list_itr_begin( chan->clients );
	nend = list_itr_end( chan->clients );
	DEBUG( "Channel %s users:\n", chan->name );
	for ( ; nitr != nend; nitr = list_itr_next( chan->clients, nitr ) )
	{
		name = (uint8_t*)list_get_head( chan->clients );
		DEBUG( "\t%s\n", name );
	}

	return IRC_OK;
}


irc_channel_t * irc_channel_new( uint8_t const * const name, 
								 uint8_t const * const pass,
								 uint8_t const * const part_msg )
{
	irc_channel_t * ch = NULL;
	CHECK_PTR_RET( name, NULL );
	
	ch = (irc_channel_t*)CALLOC( 1, sizeof(irc_channel_t) );
	CHECK_PTR_RET( ch, NULL );

	/* store the name */
	ch->name = STRDUP( name );
	CHECK_PTR_GOTO( ch->name, irc_channel_new_fail );

	/* store the channel password */
	if ( pass != NULL )
	{
		ch->pass = STRDUP( pass );
		CHECK_PTR_GOTO( ch->pass, irc_channel_new_fail );
	}

	/* store the part message */
	if ( part_msg != NULL )
	{
		ch->part_msg = STRDUP( part_msg );
		CHECK_PTR_GOTO( ch->part_msg, irc_channel_new_fail );
	}

	/* create the client list */
	ch->clients = list_new( 0, FREE );
	CHECK_PTR_GOTO( ch->clients, irc_channel_new_fail );

	return ch;

irc_channel_new_fail:
	irc_channel_delete( ch );
	return NULL;
}

void irc_channel_delete( void * c )
{
	irc_channel_t * ch = (irc_channel_t*)c;
	CHECK_PTR( ch );

	if ( ch->name != NULL )
		FREE( ch->name );

	if ( ch->pass != NULL )
		FREE( ch->pass );

	if ( ch->part_msg != NULL )
		FREE( ch->part_msg );

	if ( ch->clients != NULL )
		list_delete( (void*)ch->clients );

	FREE( ch );
}

uint8_t * irc_channel_get_name( irc_channel_t * const c )
{
	CHECK_PTR_RET( c, NULL );
	return c->name;
}

uint8_t * irc_channe_get_topic( irc_channel_t * const c )
{
	CHECK_PTR_RET( c, NULL );
	return c->topic;
}

irc_ret_t irc_channel_join( irc_channel_t * const c, irc_conn_t * const conn )
{
	irc_msg_t * join = NULL;

	CHECK_PTR_RET( c, IRC_BADPARAM );
	CHECK_PTR_RET( conn, IRC_BADPARAM );
	CHECK_RET( c->pending == FALSE, IRC_BADPARAM );

	/* set the pending flag to TRUE */
	c->pending = TRUE;

	/* send the JOIN command */
	join = irc_msg_new();
	if ( c->pass != NULL )
	{
		irc_msg_initialize( join, JOIN, NULL, 2, c->name, c->pass );
	}
	else
	{
		irc_msg_initialize( join, JOIN, NULL, 1, c->name );
	}

	/* send the JOIN command */
	irc_conn_send_msg( conn, join );

	return IRC_OK;
}

irc_ret_t irc_channel_part( irc_channel_t * const c, irc_conn_t * const conn )
{
	irc_msg_t * part = NULL;

	CHECK_PTR_RET( c, IRC_BADPARAM );
	CHECK_PTR_RET( conn, IRC_BADPARAM );

	/* send the PART command */
	part = irc_msg_new();
	irc_msg_initialize( part, PART, NULL, 1, c->name );
	if ( c->part_msg != NULL )
	{
		irc_msg_set_trailing( part, c->part_msg );
	}

	/* send the PART command */
	irc_conn_send_msg( conn, part );

	return IRC_OK;
}


