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
#include <cutil/events.h>
#include <cutil/btree.h>

#include "irc_commands.h"
#include "irc_msg.h"
#include "irc_channel.h"

struct irc_channel_s
{
    int8_t*     name;           /* name of the channel */
    int8_t*     pass;           /* the channel password */
    int8_t*     topic;          /* channel topic */
    /*int32_t     mode[MODE_WORDS];*//* mode flags */
    array_t*    clients;        /* array of clients in the channel (irc_client_t*) */
};


irc_channel_t * irc_channel_new( int8_t * const name, 
								 int8_t * const topic )
{
	irc_channel_t * ch = NULL;
	CHECK_PTR_RET( name, NULL );
	CHECK_PTR_RET( topic, NULL );
	
	ch = (irc_channel_t*)CALLOC( 1, sizeof(irc_channel_t) );
	CHECK_PTR_RET( ch, NULL );

	/* store the name */
	if ( name != NULL )
		ch->name = STRDUP( name );

	/* store the topic */
	if ( topic != NULL )
		ch->topic = STRDUP( topic );

	return ch;
}

void irc_channel_delete( void * c )
{
	irc_channelt_t * ch = (irc_channel_t*)c;
	CHECK_PTR( ch );

	if ( ch->name != NULL )
		FREE( ch->name );

	if ( ch->pass != NULL )
		FREE( ch->pass );

	if ( ch->topic != NULL )
		FREE( ch->topic );

	if ( ch->clients != NULL )
		array_delete( (void*)ch->clients );

	FREE( ch );
}


