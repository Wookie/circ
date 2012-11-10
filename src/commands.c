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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <cutil/debug.h>
#include <cutil/macros.h>

#include "commands.h"

/* the message commands map to these strings */
int8_t const * const irc_commands[NUM_COMMANDS] =
{
    /* RFC 2812, Section 3.1 -- Connection Registration */
    T("PASS"),
    T("NICK"),
    T("USER"),
    T("OPER"),
    T("MODE"),
    T("SERVICE"),
    T("QUIT"),
    T("SQUIT"),

    /* RFC 2812, Section 3.2 -- Channel Operations */
    T("JOIN"),
    T("PART"),
    /* MODE */  /* also a connection registration command */
    T("TOPIC"),
    T("NAMES"),
    T("LIST"),
    T("INVITE"),
    T("KICK"),
    
    /* RFC 2812, Section 3.3 -- Sending Messages */
    T("PRIVMSG"),
    T("NOTICE"),
    
    /* RFC 2812, Section 3.4 -- Server Queries and Commands */
    T("MOTD"),
    T("LUSERS"),
    T("VERSION"),
    T("STATS"),
    T("LINKS"),
    T("TIME"),
    T("CONNECT"),
    T("TRACE"),
    T("ADMIN"),
    T("INFO"),
        
    /* RFC 2812, Section 3.5 -- Service Query and Commands */
    T("SERVLIST"),
    T("SQUERY"),
    
    /* RFC 2812, Section 3.6 -- User Based Queries */
    T("WHO"),
    T("WHOIS"),
    T("WHOWAS"),
    
    /* RFC 2812, Section 3.7 -- Misc Messages */
    T("KILL"),
    T("PING"),
    T("PONG"),
    T("ERROR"),
    
    /* RFC 2812, Section 4 -- Optional Features */
    T("AWAY"),
    T("REHASH"),
    T("DIE"),
    T("RESTART"),
    T("SUMMON"),
    T("USERS"),
    T("WALLOPS"),
    T("USERHOST"),
    T("ISON")
};

/* session event strings */
int8_t const * const irc_session_events[NUM_SESSION_EVENTS] =
{
	T("CONNECTED"),
	T("DISCONNECTED")
};

int8_t const * const irc_any_cmd = T("ANYCMD");
int8_t const * const irc_no_cmd = T("NOCMD");

/* translate a command into a string */
int8_t const * irc_cmd_get_string(irc_command_t const cmd)
{
    static int8_t code[4];
    CHECK_RET(IS_VALID_COMMAND(cmd), NULL);
    if(IS_COMMAND(cmd))
    {
        return irc_commands[cmd - CMD_BASE];   
    }
	else if (IS_SESSION_EVENT(cmd))
	{
		return irc_session_events[cmd - SESSION_BASE];
	}
	else if ( cmd == ANYCMD )
	{
		return irc_any_cmd;
	}
	else if ( cmd == NOCMD )
	{
		return irc_no_cmd;
	}
    else
    {
        sprintf(C(code), "%03d", cmd);
        return code;
    }
    
    return NULL;
}

int8_t const * irc_cmd_get_type_string( irc_command_t const cmd )
{
	static int8_t const * const ERROR = T("ERROR");
	static int8_t const * const REPLY = T("REPLY");
	static int8_t const * const COMMAND = T("COMMAND");
	static int8_t const * const SESSION_EVENT = T("SESSION_EVENT");
	static int8_t const * const RESERVED = T("RESERVED");
	static int8_t const * const UNKNOWN = T("UNKNOWN");

	if ( IS_ERROR( cmd ) )
	{
		return ERROR;
	}
	else if ( IS_REPLY( cmd ) )
	{
		return REPLY;
	}
	else if ( IS_COMMAND( cmd ) )
	{
		return COMMAND;
	}
	else if ( IS_SESSION_EVENT( cmd ) )
	{
		return SESSION_EVENT;
	}
	else if ( IS_RESERVED( cmd ) )
	{
		return RESERVED;
	}
	
	return UNKNOWN;
}

/* get the command in the message */
irc_command_t irc_cmd_get_command_from_string(int8_t const * const str)
{
    irc_command_t cmd = NOCMD;
    CHECK_PTR_RET(str, IRC_BADPARAM);
    
    /* check for numeric response code instead of command */
    if(isdigit(str[0]))
    {
        return atoi(C(str));
    }
    else
    {
        /* scan through the command strings looking for a match */
        for(cmd = FIRST_COMMAND; cmd < LAST_COMMAND; cmd++)
        {
            if(strcmp(C(str), C(irc_cmd_get_string(cmd))) == 0)
                return cmd;
        }
		
		/* scan through the session event strings looking for a match */
		for(cmd = FIRST_SESSION_EVENT; cmd < LAST_SESSION_EVENT; cmd++)
		{
			if(strcmp(C(str), C(irc_cmd_get_string(cmd))) == 0)
				return cmd;
		}
	}
        
    /* no match so return no command */
    return NOCMD;
}

