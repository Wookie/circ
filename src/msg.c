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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/uio.h>

#define DEBUG_ON
#include <cutil/debug.h>
#include <cutil/macros.h>

#include "commands.h"
#include "msg.h"

static int8_t colon = ':';
static int8_t space = ' ';
static int8_t const * const msgend = "\r\n";

/* create a new message */
irc_msg_t* irc_msg_new()
{
	irc_msg_t* msg = NULL;
	
	/* allocate the msg */
	msg = CALLOC(1, sizeof(irc_msg_t));
	CHECK_PTR_RET(msg, NULL);
	
	return msg;
}


/* function for deleting irc messages */
void irc_msg_delete(void * m)
{
	int i;
	irc_msg_t* msg = (irc_msg_t*)m;
	CHECK_PTR(msg);

	/* was this a message that was compiled? */
	if ( msg->out.iov != NULL )
	{
		if ( msg->prefix != NULL )
			FREE( msg->prefix );

		if ( msg->num_params > 0 )
		{
			for ( i = 0; i < msg->num_params; ++i )
			{
				FREE( msg->parameters[i] );
			}
		}

		if ( msg->trailing != NULL )
			FREE( msg->trailing );

		FREE( msg->out.iov );
	}

	/* free the message memory */
	FREE(msg);	  
}

static int is_letter( int8_t const c )
{
	return ( ( (c >= 'a') && (c <= 'z') ) ||
			 ( (c >= 'A') && (c <= 'Z') ) );
}

static int is_digit( int8_t const c )
{
	return ( (c >= '0') && (c <= '9') );
}

static int is_hex( int8_t const c )
{
	return ( is_digit(c) ||
			 ( (c >= 'A') && (c <= 'F') ) ||
			 ( (c >= 'a') && (c <= 'f') ) );
}

static int is_special( int8_t const c )
{
	return ( ( (c >= 0x5B) && (c <= 0x60) ) ||
			 ( (c >= 0x7B) && (c <= 0x7D) ) );
}

static int is_user_octet( int8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x09) ) ||
			 ( (c >= 0x0B) && (c <= 0x0C) ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x3F) ) ||
			 ( ((uint8_t)c >= 0x41) && ((uint8_t)c <= 0xFF) ) );
}

static int check_ipv4_part( int8_t * pstart, int8_t *pend )
{
	int value;
	int8_t buf[4];
	CHECK_PTR_RET( pstart, FALSE );
	CHECK_PTR_RET( pend, FALSE );
	CHECK_RET( ((void*)pend - (void*)pstart) > 3, FALSE );
	MEMCPY( buf, pstart, 3 );
	buf[3] = '\0';
	value = atoi( buf );
	return ( (value >= 0) && (value <= 255) );
}

static int parse_ipv4( irc_msg_t * const msg, int8_t ** pcur )
{
	int parts = 0;
	int8_t * p = NULL;
	int8_t * part = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( pcur, FALSE );
	p = (*pcur);
	part = p;

	while ( *p != '\0' )
	{
		if ( *p == '.' )
		{
			if ( !check_ipv4_part( part, p ) )
			{
				WARN( "invalid IPv4 octet\n" );
				return FALSE;
			}
			p++;
			parts++;
			part = p;

			if ( parts > 3 )
			{
				WARN( "too many IPv4 octets\n" );
				return FALSE;
			}

			continue;
		}

		if ( is_digit( *p ) )
		{
			p++;
			continue;
		}

		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
		return FALSE;
	}

	/* check the last part */
	if ( !check_ipv4_part( part, p ) )
	{
		WARN( "invalid IPv4 octet\n" );
		return FALSE;
	}

	/* make sure we saw the correct number of '.' */
	if ( parts != 3 )
	{
		WARN( "invalid number of IPv4 octets\n" );
		return FALSE;
	}

	/* set the IPv4 pointer */
	msg->ipv4 = (*pcur);

	(*pcur) = p;
	return TRUE;
}

static int parse_ipv6( irc_msg_t * const msg, int8_t ** pcur )
{
	int first = TRUE;
	int parts = 0;
	int ipv4trailer = TRUE;
	int8_t * p = NULL;
	int8_t * part = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( pcur, FALSE );
	p = (*pcur);
	part = p;

	while( *p != '\0' )
	{
		if ( first )
		{
			if ( is_hex(*p) || (*p == ':') )
			{
				first = FALSE;
				p++;
				continue;
			}
			
			WARN( "invalid IPv6 address\n" );
			return FALSE;
		}

		if ( *p == '.' )
		{
			/* we've got an embedded IPv4 address */
			p = part;
			if ( ! parse_ipv4( msg, &p ) )
			{
				WARN( "invalid embedded IPv4 address\n" );
				return FALSE;
			}

			/* it's an embedded IPv4 address so clear out the IPv4 pointer */
			msg->ipv4 = NULL;
			continue;
		}

		if ( is_hex(*p) || (*p == ':') )
		{
			p++;
			continue;
		}
	}

	/* TODO: make this check the number of parts while being smart about zero compression */

	/* set the IPv6 pointer */
	msg->ipv6 = (*pcur);

	(*pcur) = p;
	return TRUE;
}

static int parse_hostname( irc_msg_t * const msg, int8_t ** pcur )
{
	int first = TRUE;
	int8_t * p = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( pcur, FALSE );
	p = (*pcur);

	while ( *p != '\0' )
	{
		if ( first )
		{
			if ( is_letter(*p) || is_digit(*p) )
			{
				first = FALSE;
				p++;
				continue;
			}

			WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
			return FALSE;
		}

		if ( *p == '.' )
		{
			first = TRUE;
			p++;
			continue;
		}

		if ( is_letter(*p) || is_digit(*p) || (*p == '-') )
		{
			p++;
			continue;
		}

		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
		return FALSE;
	}

	/* found the end of the hostname */
	(*pcur) = p;
	return TRUE;
}

static int parse_host( irc_msg_t * const msg, int8_t ** pcur )
{
	int ipv4 = TRUE;
	int first = TRUE;
	int8_t * p = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( pcur, FALSE );
	p = (*pcur);

	while( *p != '\0' )
	{
		if ( first )
		{
			if ( is_letter(*p) && !is_hex(*p) ) 
			{
				/* we know this is a hostname */
				return parse_hostname( msg, pcur );
			}

			if ( is_hex( *p ) )
			{
				first = FALSE;
				ipv4 = FALSE;
				p++;
				continue;
			}

			WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
			return FALSE;
		}

		if ( *p == ':' )
		{
			/* we know it is an IPv6 address */
			return parse_ipv6( msg, pcur );
		}

		if ( *p == '-' )
		{
			/* we know it is a hostname */
			return parse_hostname( msg, pcur );
		}

		if ( is_letter(*p) )
		{
			ipv4 = FALSE;
			if ( !is_hex(*p) )
			{
				/* we know it is a hostname */
				return parse_hostname( msg, pcur );
			}

			p++;
			continue;
		}
	}

	if ( ipv4 )
	{
		/* we know it looks like an IPv4 address */
		return parse_ipv4( msg, pcur );
	}

	/* must have been a hostname of hex digits */
	(*pcur) = p;
	return TRUE;
}

static int parse_user( irc_msg_t * const msg, int8_t ** pcur )
{
	int8_t * p = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( pcur, FALSE );
	p = (*pcur);

	while( (*p != '\0') && (*p != '@') )
	{
		if ( is_user_octet( *p ) )
		{
			p++;
			continue;
		}

		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
		return FALSE;
	}

	/* we got a valid user */
	(*pcur) = p;
	return TRUE;
}

static int parse_nick( irc_msg_t * const msg, int8_t ** pcur )
{
	int first = TRUE;
	int8_t * p = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( pcur, FALSE );
	p = (*pcur);

	while( (*p != '\0') && (*p != '!') && (*p != '@') )
	{
		if ( first )
		{
			if ( is_letter( *p ) || is_special( *p ) )
			{
				first = FALSE;
				p++;
				continue;
			}

			WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
			return FALSE;
		}

		if ( ((void*)p - (void*)msg->prefix) > 9 )
		{
			WARN( "invalid nickname is too long > 9 characters" );
			return FALSE;
		}

		if ( is_letter( *p ) || is_digit( *p ) || is_special( *p ) || (*p == '-') )
		{
			p++;
			continue;
		}

		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
		return FALSE;
	}

	/* we got a valid nick */
	(*pcur) = p;
	return TRUE;
}

static int parse_nickuserhost( irc_msg_t * const msg )
{
	int ret = FALSE;
	int8_t * pcur = msg->prefix;
	int8_t * p = msg->prefix;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( msg->prefix, FALSE );

	msg->nick = NULL;
	msg->user = NULL;
	msg->host = NULL;
	msg->ipv4 = NULL;
	msg->ipv6 = NULL;

	if ( !parse_nick( msg, &p ) )
		return FALSE;

	/* set nick pointer */
	msg->nick = pcur;

	switch ( *p )
	{
		case '\0':
			return TRUE;
		case '!':
			p++;
			pcur = p;
			if ( !parse_user( msg, &p ) )
				return FALSE;
			msg->user = pcur;
			if ( *p != '@' )
			{
				WARN( "received nick!user without @host\n" );
				return FALSE;
			}
			*p = '\0';
		case '@':
			p++;
			pcur = p;
			if ( !parse_host( msg, &p ) )
				return FALSE;
			msg->host = pcur;
	}
	return TRUE;
}

static int parse_prefix( irc_msg_t * const msg )
{
	int first = TRUE;
	int8_t * p = msg->prefix;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( msg->prefix, FALSE );

	while ( *p != '\0' )
	{
		if ( first )
		{
			if ( is_special( *p ) )
			{
				/* we know it is a nickname */
				return parse_nickuserhost( msg );
			}
			
			if ( is_digit( *p ) )
			{
				/* we know it is a hostname */
				p = msg->prefix;
				if ( !parse_hostname( msg, &p ) )
					return FALSE;
				msg->host = msg->prefix;
			}

			if ( is_letter( *p ) )
			{
				first = FALSE;
				p++;
				continue;
			}

			WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
			return FALSE;
		}

		if ( is_special( *p ) || (*p == '!') || (*p == '@') )
		{
			/* we know it is a nickname */
			return parse_nickuserhost( msg );
		}

		if ( *p == '.' )
		{
			/* we know it is a hostname */
			p = msg->prefix;
			if ( !parse_hostname( msg, &p ) )
				return FALSE;
			msg->host = msg->prefix;
			return TRUE;
		}

		if ( is_letter( *p ) || is_digit( *p ) || (*p == '-') )
		{
			p++;
			continue;
		}

		WARN( "prefix failed to parse at position %d (%#x)\n", (int)((void*)p - (void*)msg->prefix), *p );
		return FALSE;
	}

	/* if we get here, we assume it was a hostname */
	p = msg->prefix;
	if ( !parse_hostname( msg, &p ) )
		return FALSE;
	msg->host = msg->prefix;
}


/* parse the prefix into servername or nick[ [user] host] */
static irc_ret_t irc_msg_parse_prefix(irc_msg_t* const msg)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_PTR_RET(msg->prefix, IRC_OK);

	return ( parse_prefix( msg ) ? IRC_OK : IRC_ERR );
}

/* 
 * RFC 2812, Section 2.3 -- Messages
 *
 * Servers and clients send each other messages, which may or may not
 * generate a reply.  If the message contains a valid command, as
 * described in later sections, the client should expect a reply as
 * specified but it is not advised to wait forever for the reply; client
 * to server and server to server communication is essentially
 * asynchronous by nature.
 *
 * Each IRC message may consist of up to three main parts: the prefix
 * (OPTIONAL), the command, and the command parameters (maximum of
 * fifteen (15)).  The prefix, command, and all parameters are separated
 * by one ASCII space character (0x20) each.
 *
 * The presence of a prefix is indicated with a single leading ASCII
 * colon character (':', 0x3b), which MUST be the first character of the
 * message itself.	There MUST be NO gap (whitespace) between the colon
 * and the prefix.	The prefix is used by servers to indicate the true
 * origin of the message.  If the prefix is missing from the message, it
 * is assumed to have originated from the connection from which it was
 * received from.  Clients SHOULD NOT use a prefix when sending a
 * message; if they use one, the only valid prefix is the registered
 * nickname associated with the client.
 *
 * The command MUST either be a valid IRC command or a three (3) digit
 * number represented in ASCII text.
 *
 * IRC messages are always lines of characters terminated with a CR-LF
 * (Carriage Return - Line Feed) pair, and these messages SHALL NOT
 * exceed 512 characters in length, counting all characters including
 * the trailing CR-LF. Thus, there are 510 characters maximum allowed
 * for the command and its parameters.	There is no provision for
 * continuation of message lines.  See section 6 for more details about
 * current implementations.
 */
irc_ret_t irc_msg_parse(irc_msg_t* const msg)
{
	int8_t* ptr = NULL;
	int8_t* space = NULL;
	int8_t* end = NULL;
	int8_t* cmd = NULL;
	
	CHECK_PTR_RET(msg, IRC_BADPARAM);

	/* reset the msg pointers */
	msg->prefix = NULL;
	msg->command = NULL;
	MEMSET( (void*)msg->parameters, 0, IRC_NUM_PARAMS );
	msg->trailing = NULL;
		
	/* start by initializing the ptr to the first byte in the buffer */
	ptr = &msg->in.data[0];
	
	/* 
	 * figure out where the end of the buffer is, the - 2 cuts off the
	 * \r\n at the end of the message
	 */
	end = (&msg->in.data[0] + msg->in.size) - 2;

	/* zero out the last two bytes so that we end in null byte */
	end[0] = '\0';
	end[1] = '\0';
 
	/**** PREFIX ****/

	/* first check for a prefix that start with a ":" */
	if((*ptr) == ':')
	{
		/* move to the first character after the ":" */
		ptr++;
		
		/* parse out the prefix */
		space = ptr;
		while(((*space) != ' ') && (space < end))
			space++;
			  
		/* check to see if we ran to the end of the buffer */
		CHECK_RET((space < end), IRC_BAD_MESSAGE);
		
		/* make the ptr point to a valid C string of the prefix */
		*space = '\0';
		msg->prefix = ptr;
		
		/* move ptr */
		ptr = space + 1;
	}
   
	/**** COMMAND ****/

	/* now parse out the command */
	space = ptr;
	while(((*space) != ' ') && (space < end))
		space++;
	
	/* check to see if we ran to the end of the buffer */
	CHECK_RET((space < end), IRC_BAD_MESSAGE);
   
	/* make the command a valid C-string */
	*space = '\0';
	msg->command = ptr;

	/* convert the command string to an irc_command_t */
	msg->cmd = irc_cmd_get_command_from_string( msg->command );
	
	/* check the command */
	if(!IS_VALID_COMMAND(msg->cmd) || (msg->cmd == NOCMD))
		return IRC_BAD_MESSAGE;
	
	/* move ptr */
	ptr = space + 1;
   
	/**** PARAMS ****/

	/* lastly parse out all of the parameters */
	while(ptr < end)
	{
		/* check to see if the parameter starts with a ":" */
		if((*ptr) == ':')
		{
			/* move to the first character after the ":" */
			ptr++;
			
			/* the last parameter goes from ptr to end */
			space = end;

			/* point the trailing pointer to the beginning of trailing string */
			msg->trailing = ptr;
		}
		else
		{
			/* parse out the parameter */
			space = ptr;
			while(((*space) != ' ') && (space < end))
				space++;

			*space = '\0';

			/* make the parameter pointer point at the param string */
			msg->parameters[msg->num_params] = ptr;

			/* increment the number of params */
			msg->num_params++;
		}
		
		/* move ptr */
		ptr = space + 1;
	}
	
	/* parse out the prefix */
	irc_msg_parse_prefix(msg);
	
	return IRC_OK;
}

irc_ret_t irc_msg_compile(irc_msg_t* const msg)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	return IRC_OK;
}
	
void irc_msg_log( irc_msg_t const * const msg )
{
	int i;
	LOG( "%20s:%-5d -- (%s", __FILE__, __LINE__, irc_cmd_get_type_string( msg->cmd ) );
	if ( msg->prefix != NULL )
	{
		/* prefix can be nick!user@host */
		if ( (msg->nick != NULL) && (msg->user != NULL) && (msg->host != NULL) )
		{
			LOG( " ( (%s ! %s @ %s) %s", msg->nick, msg->user, msg->host, msg->command );
		}

		/* or it can be just nick@host */
		else if ( (msg->nick != NULL) && (msg->host != NULL) )
		{
			LOG( " ( (%s @ %s) %s", msg->nick, msg->host, msg->command );
		}

		/* or just nick */
		else if ( msg->nick != NULL )
		{
			LOG( " ( (%s) %s", msg->nick, msg->command );
		}

		/* or just host */
		else if ( msg->host != NULL )
		{
			LOG( " ( (%s) %s", msg->host, msg->command );
		}

		/* or an error */
		else
		{
			LOG( " ( (ERR!) %s", msg->command );
		}
	}
	else
	{
		LOG( " (%s", msg->command );
	}

	if ( msg->num_params > 0 )
	{
		LOG(" (");
		for ( i = 0; i < msg->num_params; i++ )
		{
			if ( i > 0 )
				LOG(" ");
			LOG( "%s", msg->parameters[i] );
		}
		LOG(")");
	}
	
	if ( msg->trailing != NULL )
	{
		LOG( " %s", msg->trailing );
	}
	LOG("))");
	LOG("\n");
}

/* initialize the message in one pass */
irc_ret_t irc_msg_initialize(
	irc_msg_t* const msg,
	irc_command_t const cmd,
	int8_t* const prefix,
	int32_t const num_params,
	...
)
{
	va_list va;
	int32_t i;
	
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_RET(IS_VALID_COMMAND(cmd), IRC_BADPARAM);
	
	/* store the prefix if there is one */
	if(prefix != NULL)
	{
		/* dup the prefix into place */
		msg->prefix = T(strndup(C(prefix), IRC_MSG_SIZE));
	}

	/* store the command string */
	if(IRC_OK != irc_msg_set_command(msg, cmd))
	{
		return IRC_ERR;
	}
	
	/* append the parameters */
	va_start(va, num_params);
	for(i = 0; i < num_params; i++)
	{
		irc_msg_add_parameter(msg, va_arg(va, int8_t*));
	}
	va_end(va);

	return IRC_OK;
}

/* add a parameter */
irc_ret_t irc_msg_add_parameter(irc_msg_t* const msg, int8_t const * const param)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_PTR_RET(param, IRC_BADPARAM);
	
	/* dup the string into the next param slot */
	msg->parameters[msg->num_params] = T(strndup(C(param), IRC_MSG_SIZE));
	
	if(msg->parameters[msg->num_params] == NULL)
	{
		WARN("failed to allocate parameter buffer\n");
		return IRC_ERR;
	}
	
	/* increment the number of params */
	msg->num_params++;

	return IRC_OK;
}

/* set the trailing parameter */
irc_ret_t irc_msg_set_trailing( irc_msg_t* const msg, int8_t const * const trailing)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_PTR_RET(trailing, IRC_BADPARAM);

	/* dup the string into the trailing place */
	msg->trailing = T(strndup(C(trailing), IRC_MSG_SIZE));

	if ( msg->trailing == NULL )
	{
		WARN( "failed to store trailing parameter\n" );
		return IRC_ERR;
	}

	return IRC_OK;
}

irc_ret_t irc_msg_finalize( irc_msg_t * const msg )
{
	int i;
	struct iovec * vec;
	size_t newsize = 0;

	CHECK_PTR_RET(msg, IRC_BADPARAM);

	if ( msg->out.iov != NULL )
		FREE( msg->out.iov );

	/* add three for the prefix, (: prefix <space>)  */
	if ( msg->prefix != NULL )
		newsize += 3;

	/* add one for the command */	
	newsize++;

	/* add two for each parameter (<space> param) */
	newsize += (msg->num_params * 2);

	/* add two for trailing parameter (<space> : trailing) */
	if ( msg->trailing != NULL )
		newsize += 3;

	/* add one more for the \r\n at the end */
	newsize++;

	/* now allocate the new iovec struct array */
	msg->out.iov = CALLOC( newsize, sizeof(struct iovec) );
	CHECK_PTR_RET_MSG( msg->out.iov, IRC_ERR, "failed to allocate iovec struct array\n" );

	/* store the array length */
	msg->out.nvec = newsize;

	/* now fill in the iovec structs */
	vec = msg->out.iov;

	if ( msg->prefix != NULL )
	{
		/* add colon */
		vec->iov_base = &colon;
		vec->iov_len = 1;
		vec++;

		/* add prefix */
		vec->iov_base = msg->prefix;
		vec->iov_len = strnlen( msg->prefix, IRC_MSG_SIZE );
		vec++;

		/* add space */
		vec->iov_base = &space;
		vec->iov_len = 1;
		vec++;
	}

	/* add command */
	vec->iov_base = msg->command;
	vec->iov_len = strnlen( msg->command, IRC_MSG_SIZE );
	vec++;

	/* add the params */
	for( i = 0; i < msg->num_params; i++ )
	{
		/* add space */
		vec->iov_base = &space;
		vec->iov_len = 1;
		vec++;

		/* add param */
		vec->iov_base = msg->parameters[ i ];
		vec->iov_len = strnlen( msg->parameters[i], IRC_MSG_SIZE );
		vec++;
	}

	if ( msg->trailing != NULL )
	{
		/* add space */
		vec->iov_base = &space;
		vec->iov_len = 1;
		vec++;

		/* add colon */
		vec->iov_base = &colon;
		vec->iov_len = 1;
		vec++;

		/* add trailing */
		vec->iov_base = msg->trailing;
		vec->iov_len = strnlen( msg->trailing, IRC_MSG_SIZE );
		vec++;
	}

	/* finish with \r\n */
	vec->iov_base = (void*)msgend;
	vec->iov_len = 2;

	return IRC_OK;
}

/* set the command */
irc_ret_t irc_msg_set_command(irc_msg_t* const msg, irc_command_t const cmd)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_RET(IS_VALID_COMMAND(cmd), IRC_BADPARAM);
	
	if((cmd != NOCMD) && IS_COMMAND(cmd))
	{
		/* store the command */
		msg->cmd = cmd;

		/* we can just copy the pointer because these are statically allocated strings */
		msg->command = (int8_t*)irc_cmd_get_string( cmd );

		return IRC_OK;
	}
	
	return IRC_ERR;
}

#if 0

/* functions for appending a string to a message */
irc_ret_t irc_msg_vappend(irc_msg_t * const msg, char const * const format, va_list va)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_PTR_RET(format, IRC_BADPARAM);
	
	/* append the string */
	msg->buffer.data_size += vsprintf((char * const)&msg->buffer.data[msg->buffer.data_size], 
									  format, va);

	return IRC_OK;
}

irc_ret_t irc_msg_append(irc_msg_t * const msg, char const * const format, ...)
{
	irc_ret_t ret = IRC_OK;
	va_list va;

	va_start(va, format);
	ret = irc_msg_vappend(msg, format, va);
	va_end(va);

	return ret;
}


void irc_msg_copy(irc_msg_t * const lhs, irc_msg_t const * const rhs)
{
	int32_t i;
	
	CHECK_PTR(lhs);
	CHECK_PTR(rhs);

	/* clean up any internal memory in the lhs */
	irc_msg_deinitialize(lhs);

	/* copy the message data */
	lhs->cmd = rhs->cmd;
	if(rhs->prefix != NULL)
		lhs->prefix = T(strndup(C(rhs->prefix), IRC_MSG_SIZE));
	if(rhs->nick != NULL)
		lhs->nick = T(strndup(C(rhs->nick), IRC_MSG_SIZE));
	if(rhs->user != NULL)
		lhs->user = T(strndup(C(rhs->nick), IRC_MSG_SIZE));
	if(rhs->host != NULL)
		lhs->host = T(strndup(C(rhs->host), IRC_MSG_SIZE));
	for(i = 0; i < IRC_NUM_PARAMS; i++)
	{
		if(rhs->parameters[i] != NULL)
			lhs->parameters[i] = T(strndup(C(rhs->parameters[i]), IRC_MSG_SIZE));
	}
	lhs->num_params = rhs->num_params;

	/* copy the buffer and set the r/n pointer correctly */
	MEMCPY(lhs->buffer.data, rhs->buffer.data, IRC_MSG_SIZE);
	lhs->buffer.data_size = rhs->buffer.data_size;
	if(rhs->buffer.r != NULL)
		lhs->buffer.r = &lhs->buffer.data[0] + (rhs->buffer.r - &rhs->buffer.data[0]);
	if(rhs->buffer.n != NULL)
		lhs->buffer.n = &lhs->buffer.data[0] + (rhs->buffer.n - &rhs->buffer.data[0]);
}



/* deinitialize the message */
irc_ret_t irc_msg_deinitialize(irc_msg_t* const msg)
{
	int32_t i = 0;
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	
	if (msg->out != NULL)
	{
		/* free up the internal memory */
		if(msg->prefix != NULL)
		{
			FREE(msg->prefix);
			msg->prefix = NULL;
		}
		if(msg->nick != NULL)
		{
			FREE(msg->nick);
			msg->nick = NULL;
		}
		if(msg->user != NULL)
		{
			FREE(msg->user);
			msg->user = NULL;
		}
		if(msg->host != NULL)
		{
			FREE(msg->host);
			msg->host = NULL;
		}
		for(i = 0; i < IRC_NUM_PARAMS; i++)
		{
			if(msg->parameters[i] != NULL)
				FREE(msg->parameters[i]);
			
			msg->parameters[i] = NULL;
		}
		msg->num_params = 0;
		
	/* clean up the buffer too */
	msg->buffer.r = NULL;
	msg->buffer.n = NULL;
	msg->buffer.data_size = 0;
	MEMSET(msg->buffer.data, 0, IRC_MSG_SIZE);
	
	return IRC_OK;
}


/* compile the message into a string buffer for sending */
irc_ret_t irc_msg_compile(irc_msg_t* const msg)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	
	DEBUG("irc_msg_compile(%s)\n", irc_cmd_get_string(msg->cmd));
	
	/* we need to clear out the compile buffer so that this can be called 
	 * multiple times on a message without bad effects */
	MEMSET(&msg->buffer, 0, sizeof(irc_msg_buf_t));
	
	/* check for prefix */
	if(msg->prefix != NULL)
	{
		/* copy it into the buffer with the leading : */
		irc_msg_append(msg, ":%s ", msg->prefix);
	}

	/* write in the command string and adjust the write pointer */
	irc_msg_append(msg, "%s ", irc_cmd_get_string(msg->cmd));

	/* write in the parameters for the message */
	switch(msg->cmd)
	{
		case PASS:
		{
			/* RFC 2812, Section 3.1.1 -- PASS command
			 * Format: PASS <password>
			 * Parameters:
			 *	<password> -- the connection password
			 *
			 * Numeric Replies:
			 *	ERR_NEEDMOREPARAMS		= 461
			 *	ERR_ALREADYREGISTERED	= 462
			 */

			/* add the parameter */
			CHECK_RET((msg->num_params == 1), IRC_BAD_MESSAGE);
			irc_msg_append(msg, "%s", msg->parameters[0]);
			break;
		}
		case NICK:
		{
			/* RFC 2812, Section 3.1.2 -- NICK command
			 * Format: NICK <nickname>
			 * Parameters:
			 *	<nickname> -- the new nick for the user
			 *
			 * Numeric Replies:
			 *	ERR_NONICKNAMEGIVEN		= 431,
			 *	ERR_ERRONEUSNCKNAME		= 432,
			 *	ERR_NICKNAMEINUSE		= 433,
			 *	ERR_NICKCOLLISION		= 436,
			 *	ERR_UNAVAILRESOURCE		= 437,
			 *	ERR_RESTRICTED			= 484
			 */
		
			/* add the parameter */
			CHECK_RET((msg->num_params == 1), IRC_BAD_MESSAGE);
			irc_msg_append(msg, "%s", msg->parameters[0]);
			break;
		}
		case USER:
		{
			/* RFC 2812, Section 3.1.3 -- USER command
			 * Format: USER <username> <mode> <unused> <real name>
			 * Parameters:
			 *	<username> -- the username of the account the client is running on
			 *	<mode> -- The <mode> parameter should be a numeric, and can be used
			 *			  to automatically set user modes when registering with the
			 *			  server.  This parameter is a bitmask, with only 2 bits 
			 *			  having any signification: if the bit 2 is set, the user 
			 *			  mode 'w' will be set and if the bit 3 is set, the user 
			 *			  mode 'i' will be set.  (See Section 3.1.5 "User Modes").
			 *	<unused> -- parameter not used, should be "*"
			 *	<real name> -- the real name of the user, must be prefixed with a ':' 
			 *				   because it can contain spaces
			 */
			
			CHECK_RET((msg->num_params == 2), IRC_BAD_MESSAGE);
			
			/* add the username provided by the caller */
			irc_msg_append(msg, "%s ", msg->parameters[0]);
			
			/* add the user modes */
			/* TODO: add support for user mode calculation */
			irc_msg_append(msg, "0 ");

			/* add the unused parameter */
			irc_msg_append(msg, "* ");
						
			/* add the real name */
			irc_msg_append(msg, ":%s", msg->parameters[1]);
			
			break;
		}
		case OPER:
		{
			break;
		}
		case MODE:
		{
			break;
		}
		case SERVICE:
		{
			break;
		}
		case QUIT:
		{
			/* RFC 2812, Section 3.1.7 -- QUIT command
			 * Format: QUIT [<quit message>]
			 * Parameters:
			 *	<quit message> -- optional parameter must be prefixed with ":"
			 *					  because it can contain spaces.
			 */

			/* add the parameter */
			DEBUG("QUIT nparams: %d\n", msg->num_params);
			CHECK_RET((msg->num_params == 1), IRC_BAD_MESSAGE);
			irc_msg_append(msg, ":%s", msg->parameters[0]);
			break;
		}
		case SQUIT:
		{
			break;
		}
		case JOIN:
		{
			int32_t params = 0;
			int32_t chans = 0;
			int32_t keys = 0;
			int8_t* param = NULL;
			/* RFC 2812, Section 3.2.1 -- JOIN command
			 * Format: JOIN ( <channel> *("," <channel> ) [ <key> *("," <key>) ] ) / "0"
			 * Parameters:
			 *	<channel> --
			 *	<key> --
			 */
						
			/* the channel list */
			while(params < msg->num_params)
			{
				/* get the next param */
				param = msg->parameters[params];
				
				/* check to see if the param is a channel name */
				if((param[0] == '&') ||
				   (param[0] == '#') ||
				   (param[0] == '+') ||
				   (param[0] == '!'))
				{
					if(chans > 0)
						irc_msg_append(msg, ",");

					irc_msg_append(msg, "%s", param);
					params++;
					chans++;
				}
				else
					break; /* move to handling the keys */
			}
			
			
			/* add a space */
			irc_msg_append(msg, " ");
			
			while(params < msg->num_params)
			{
				if(keys > 0)
					irc_msg_append(msg, ",");
				
				/* add the key */
				irc_msg_append(msg, "%s", param);
				params++;
				keys++;
				
				/* get the next param */
				param = msg->parameters[params];
			}
			break;
		}
		case PART:
		{
			int32_t params = 0;
			int32_t chans = 0;
			int8_t* param = NULL;
			/* RFC 2812, Section 3.2.1 -- PART command 
			 * Format: PART <channel> *( "," <channel> ) [ <Part Message> ]
			 * Parameters: 
			 *	<channel> --
			 *	<Part Message> --
			 * Replies:
			 *	ERR_NEEDMOREPARAMS
			 *	ERR_NOSUCHCHANNEL
			 *	ERR_NOTONCHANNEL
			 */

			/* the channel list */
			while(params < msg->num_params)
			{
				/* get the next param */
				param = msg->parameters[params];
				
				/* check to see if the param is a channel name */
				if((param[0] == '&') ||
				   (param[0] == '#') ||
				   (param[0] == '+') ||
				   (param[0] == '!'))
				{
					if(chans > 0)
						irc_msg_append(msg, ",");

					irc_msg_append(msg, "%s", param);
					params++;
					chans++;
				}
				else
					break; /* move to handling the part message */
			}
			
			/* check for and add part message */
			if(params == (msg->num_params - 1))
			{
				irc_msg_append(msg, " :%s", param);
			}
			break;
		}
		case TOPIC:
		{
			break;
		}
		case NAMES:
		{
			break;
		}
		case LIST:
		{
			break;
		}
		case INVITE:
		{
			break;
		}
		case KICK:
		{
			break;
		}
		case PRIVMSG:
		{
			int32_t j = 0;
			/* RFC 2812, Section 3.2.1 -- PRIVMSG command 
			 * Format: PRIVMSG <msgtarget> <text to be sent>
			 * Parameters: 
			 *	<msgtarget> -- message recipient
			 *	<text to be sent> -- message body
			 * Replies:
			 *	ERR_NORECIPIENT
			 *	ERR_NOTEXTTOSEND
			 *	ERR_CANNOTSENDTOCHAN
			 *	ERR_NOTOPLEVEL
			 *	ERR_WILDTOPLEVEL
			 *	ERR_TOOMANYTARGETS
			 *	ERR_NOSUCHNICK
			 *	RPL_AWAY
			 */
			DEBUG("PRIVMSG compile\n");
			DEBUG("num params: %d\n", msg->num_params);
			for(j = 0; j < msg->num_params; j++)
			{
				DEBUG("param[%d] = %s\n", j, msg->parameters[j]);
			}
			
			CHECK_RET((msg->num_params == 2), IRC_BAD_MESSAGE);
			DEBUG("adding params\n");
			
			/* add in the msgtarget */
			irc_msg_append(msg, "%s ", msg->parameters[0]);
			
			/* add in the message */
			irc_msg_append(msg, ":%s", msg->parameters[1]);

			break;
		}
		case NOTICE:
		{
			break;
		}
		case MOTD:
		{
			break;
		}
		case LUSERS:
		{
			break;
		}
		case VERSION:
		{
			break;
		}
		case STATS:
		{
			break;
		}
		case LINKS:
		{
			break;
		}
		case TIME:
		{
			break;
		}
		case CONNECT:
		{
			break;
		}
		case TRACE:
		{
			break;
		}
		case ADMIN:
		{
			break;
		}
		case INFO:
		{
			break;
		}
		case SERVLIST:
		{
			break;
		}
		case SQUERY:
		{
			break;
		}
		case WHO:
		{
			break;
		}
		case WHOIS:
		{
			break;
		}
		case WHOWAS:
		{
			break;
		}
		case KILL:
		{
			break;
		}
		case PING:
		{
			break;
		}
		case PONG:
		{
			int32_t params = 0;
			
			/* RFC 2812, Section 3.7.3 -- PONG command
			 * Format: PONG <server> [<server2>]
			 * Parameters:
			 *	<server> -- the originator of the PING command this is a response to
			 * Replies:
			 *	ERR_NOORIGIN
			 *	ERR_NOSUCHSERVERIRC_NUM_PARAMS
			 */

			while(params < msg->num_params)
			{
				/* add a space */
				if(params > 0)
					irc_msg_append(msg, " ");
				
				/* add the server */
				irc_msg_append(msg, "%s", msg->parameters[params]);
				
				params++;				 
			}
			break;
		}
		case ERROR:
		{
			break;
		}
		case AWAY:
		{
			break;
		}
		case REHASH:
		{
			break;
		}
		case DIE:
		{
			break;
		}
		case RESTART:
		{
			break;
		}
		case SUMMON:
		{
			break;
		}
		case USERS:
		{
			break;
		}
		case WALLOPS:
		{
			break;
		}
		case USERHOST:
		{
			break;
		}
		case ISON:
		{
			break;
		}
		default:
		{
			break;
		}
	}
	
	/* add the \r\n to the end */
	irc_msg_append(msg, "\r\n");
	
	return IRC_OK;
}


/* clear the parameters */
irc_ret_t irc_msg_clear_parameters(irc_msg_t* const msg)
{
	int32_t i = 0;
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	
	/* free the params */
	for(i = 0; i < msg->num_params; i++)
	{
		if(msg->parameters[i] != NULL)
		{
			FREE(msg->parameters[i]);
			msg->parameters[i] = NULL;
		}
	}
	
	/* reset the number of parameters */
	msg->num_params = 0;
	
	return IRC_OK;
}

/* set a parameter */
irc_ret_t irc_msg_set_parameter(irc_msg_t* const msg, int32_t const index, int8_t const * const param)
{
	CHECK_PTR_RET(msg, IRC_BADPARAM);
	CHECK_RET(((index >= 0) && (index < IRC_NUM_PARAMS)), IRC_BADPARAM);
	CHECK_PTR_RET(param, IRC_BADPARAM);
	
	if(index < msg->num_params)
	{
		/* replace the current param at that index with the new param */
		if(msg->parameters[index] != NULL)
			FREE(msg->parameters[index]);
		
		/* dup the parameter into the array */
		msg->parameters[index] = T(strndup(C(param), IRC_MSG_SIZE));
	}
	else if(index == msg->num_params)
	{
		/* this is the special case where we can just append the value to the end */
		return irc_msg_add_parameter(msg, param);
	}
	else
	{
		/* dup the parameter into the array */
		msg->parameters[index] = T(strndup(C(param), IRC_MSG_SIZE));
		
		/* adjust the num_params accordingly */
		msg->num_params = index + 1;
	}
	
	return IRC_OK;
}

#endif


