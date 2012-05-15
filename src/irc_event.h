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
 
#ifndef __IRC_EVENT_H__
#define __IRC_EVENT_H__

#include "irc_commands.h"

#define IS_VALID_EVENT(x) (IS_ERROR(x) || IS_REPLY(x))

typedef struct event_name_s
{
	int8_t const * const name;
	uint32_t hash;
} event_name_t;

/* the event names for 000 IRC msg codes */
extern event_name_t const irc_events_h_000[];
/* the event names for 200 IRC msg codes */
extern event_name_t const irc_events_h_200[];
/* the event names for 300 IRC msg codes */
extern event_name_t const irc_events_h_300[];
/* the event names for 400 IRC msg codes */
extern event_name_t const irc_events_h_400[];
/* the event names for 500 IRC msg codes */
extern event_name_t const irc_events_h_500[];

/* translate a command into an event_name */
int8_t const * irc_event_get_name_from_cmd( irc_command_t const cmd );
uint32_t irc_event_get_hash_from_cmd( irc_command_t const cmd );


#endif/*__IRC_EVENT_H__*/

