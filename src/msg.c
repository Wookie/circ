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

static uint8_t colon = ':';
static uint8_t space = ' ';
static uint8_t const * const msgend = "\r\n";

/* create a new message */
irc_msg_t* irc_msg_new()
{
	irc_msg_t* msg = NULL;
	
	/* allocate the msg */
	msg = CALLOC(1, sizeof(irc_msg_t));
	CHECK_PTR_RET(msg, NULL);

	/* initialize the params list */
	CHECK_GOTO( list_initialize( &(msg->params), IRC_NUM_PARAMS, NULL ), _irc_msg_new_fail );
	
	return msg;

_irc_msg_new_fail:
	irc_msg_delete( msg );
	return NULL;
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
	uint8_t* ptr = NULL;
	uint8_t* space = NULL;
	uint8_t* end = NULL;
	uint8_t* cmd = NULL;
	
	CHECK_PTR_RET(msg, IRC_BADPARAM);

	/* reset the msg pointers */
	msg->prefix = NULL;
	msg->command = NULL;
	msg->parameters = NULL;
		
	/* start by initializing the ptr to the first byte in the buffer */
	ptr = &msg->in.data[0];
	
	/* 
	 * figure out where the end of the buffer is, the - 2 cuts off the
	 * \r\n at the end of the message
	 */
	end = (&msg->in.data[0] + msg->in.size) - 2;
	CHECK_RET( end[0] == '\r', IRC_ERR );
	CHECK_RET( end[1] == '\n', IRC_ERR );

	/* zero out the last two bytes so that we end in null byte */
	end[0] = '\0';
	end[1] = '\0';
 
	/***** PREFIX *****/

	/* first check for a prefix that start with a ":" */
	if((*ptr) == ':')
	{
		/* move to the first character after the ":" */
		ptr++;

		/* parse the prefix and move ptr to the character after the prefix */
		CHECK_RET( parse_prefix( msg, &ptr, end ), IRC_ERR );

		/* check to see if we ran to the end of the buffer */
		CHECK_RET((space < end), IRC_BAD_MESSAGE);
	}
   
	/***** COMMAND *****/
	CHECK_RET( parse_command( msg, &ptr, end ), IRC_ERR );

	/* check to see if we ran to the end of the buffer */
	CHECK_RET((space < end), IRC_BAD_MESSAGE);
   
	/**** PARAMS ****/
	CHECK_RET( parse_params( msg, &ptr, end ), IRC_ERR );

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
	LOG( "(%s\n", irc_cmd_get_type_string( msg->cmd ) );
	if ( msg->prefix != NULL )
	{
		/* prefix can be nick!user@host */
		if ( (msg->nick != NULL) && (msg->user != NULL) && (msg->host != NULL) )
		{
			LOG( "  (%s ! %s @ %s) %s\n", msg->nick, msg->user, msg->host, msg->command );
		}

		/* or it can be just user@host */
		else if ( (msg->user != NULL) && (msg->host != NULL) )
		{
			LOG( "  (%s @ %s) %s\n", msg->user, msg->host, msg->command );
		}

		/* or just nick */
		else if ( msg->nick != NULL )
		{
			LOG( "  (%s) %s\n", msg->nick, msg->command );
		}

		/* or just host */
		else if ( msg->host != NULL )
		{
			LOG( "  (%s) %s\n", msg->host, msg->command );
		}

		/* or an error */
		else
		{
			LOG( "  (ERR!) %s\n", msg->command );
		}
	}
	else
	{
		LOG( "  (%s\n", msg->command );
	}

	if ( msg->num_params > 0 )
	{
		LOG("  (\n");
		for ( i = 0; i < msg->num_params; i++ )
		{
			LOG( "    %s\n", msg->parameters[i] );
		}
		LOG("  )\n");
	}
	
	if ( msg->trailing != NULL )
	{
		LOG( "  (%s)\n", msg->trailing );
	}
	LOG(")\n");
}

/* initialize the message in one pass */
irc_ret_t irc_msg_initialize(
	irc_msg_t* const msg,
	irc_command_t const cmd,
	uint8_t* const prefix,
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
		irc_msg_add_parameter(msg, va_arg(va, uint8_t*));
	}
	va_end(va);

	return IRC_OK;
}

/* add a parameter */
irc_ret_t irc_msg_add_parameter(irc_msg_t* const msg, uint8_t const * const param)
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
irc_ret_t irc_msg_set_trailing( irc_msg_t* const msg, uint8_t const * const trailing)
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
		msg->command = (uint8_t*)irc_cmd_get_string( cmd );

		return IRC_OK;
	}
	
	return IRC_ERR;
}



/*****************************************************************************/
/********** PRIVATE FUNCTIONS ************************************************/
/*****************************************************************************/

static int is_letter( uint8_t const c )
{
	return ( ( (c >= 'a') && (c <= 'z') ) ||
			 ( (c >= 'A') && (c <= 'Z') ) );
}

static int is_digit( uint8_t const c )
{
	return ( (c >= '0') && (c <= '9') );
}

static int is_hex( uint8_t const c )
{
	return ( ( (c >= '0') && (c <= '9') ) ||
			 ( (c >= 'A') && (c <= 'F') ) ||
			 ( (c >= 'a') && (c <= 'f') ) );
}

static int is_special( uint8_t const c )
{
	return ( ( (c >= 0x5B) && (c <= 0x60) ) ||
			 ( (c >= 0x7B) && (c <= 0x7D) ) );
}

static int is_user_octet( uint8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x09) ) ||
			 ( (c >= 0x0B) && (c <= 0x0C) ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x3F) ) ||
			 ( (c >= 0x41) && (c <= 0xFF) ) );
}

static int is_key_octet( uint8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x05) ) ||
			 ( (c >= 0x07) && (c <= 0x08) ) ||
			 ( (c == 0x0C)				  ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x7F) ) );
}

static int is_chanstart( uint8_t const c )
{
	return ( ( c == '#' ) ||
			 ( c == '+' ) ||
			 ( c == '!' ) ||
			 ( c == '&' ) );
}

static int is_chanstring( uint8_t const c )
{
	return ( ( (c >= 0x01) && (c <= 0x07) ) ||
			 ( (c >= 0x08) && (c <= 0x09) ) ||
			 ( (c >= 0x0B) && (c <= 0x0C) ) ||
			 ( (c >= 0x0E) && (c <= 0x1F) ) ||
			 ( (c >= 0x21) && (c <= 0x2B) ) ||
			 ( (c >= 0x2D) && (c <= 0x39) ) ||
			 ( (c >= 0x3B) && (c <= 0xFF) ) );
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * shortname = ( letter / digit ) *( letter / digit / "-" ) *( letter / digit )
 *
 */
static int parse_shortname( uint8_t ** ptr, uint8_t **shortname, uint8_t * const end )
{
	uint8_t * p = NULL;
	uint8_t * last = NULL;

	CHECK_PTR_RET( shortname, FALSE );
	CHECK_PTR_RET( ptr, FALSE );
	CHECK_PTR_RET( *ptr, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_RET ( *ptr < end, FALSE );

	if ( (*ptr == ' ') || (*ptr == '.') )
		return FALSE;

	for ( p = *ptr; (p < end) && (*p != ' ') && (*p != '.'); ++p )
	{
		if ( p == *ptr )
		{
			if ( !is_letter(*p) && !is_digit(*p) )
				return FALSE;
		}
		else
		{
			last = p;
			if ( !is_letter(*p) && !is_digit(*p) && (*p != '-') )
				return FALSE;
		}
	}

	if ( !is_letter(*last) && !is_digit(*last) )
		return FALSE;

	(*shortname) = CALLOC( 1, (p - *ptr) + 1);
	MEMCPY( (*shortname), *ptr, (p - *ptr) );
	(*ptr) = p;

	return TRUE;
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * servername = hostname
 * hostname = shortname *( "." shortname )
 *
 * NOTE: severname cannot include IPv4 or IPv6 addresses, it must be a name.
 */
static int parse_servername( uint8_t ** servername, uint8_t **ptr, uint8_t * const end )
{
	uint8_t * p = NULL;
	uint8_t * shortname = NULL;
	uint8_t * srvrname = NULL;

	CHECK_PTR_RET( servername, FALSE );
	CHECK_PTR_RET( ptr, FALSE );
	CHECK_PTR_RET( *ptr, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_RET ( *ptr < end, FALSE );

	p = *ptr;
	while ( parse_shortname( &p, &shortname, end ) )
	{
		if ( *p == '.' )
		{
			srvrname = REALLOC( srvrname, strlen( srvrname ) + 2 );
			CHECK_PTR_RET( srvrname, FALSE );
			srvrname = strcat( srvrname, "." );
		}

		srvrname = REALLOC( srvrname, strlen( srvrname) + strlen( shortname ) + 1 );
		CHECK_PTR_RET( srvrname, FALSE );
		srvrname = strcat( srvrname, shortname );
	}

	(*servername) = srvrname;
	(*ptr) = p;

	return TRUE;
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * prefix = servername / (nickname [ [ "!" user ] "@" host ] )
 */
static int parse_prefix( irc_msg_t * const msg, uint8_t ** ptr, uint8_t * const end )
{
	uint8_t * p = NULL;
	int bang_or_at = FALSE;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( ptr, FALSE );
	CHECK_PTR_RET( *ptr, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_RET ( *ptr < end, FALSE );

	/* if there is a "!" or "@" in the prefix string, then it is NOT a server name */
	for ( p = *ptr; (p < end) && (*p != ' '); ++p )
	{
		if ( (*p == '!') || (*p == '@') )
		{
			bang_or_at = TRUE;
			break;
		}
	}

	if ( !bang_or_at )
	{
		/* it must be a servername, so parse it */
		CHECK_RET( parse_servername( &(msg->origin.servername), ptr, end ), FALSE );
	}
	else
	{
		/* it must be a nick-user-hostname, so parse it */
		CHECK_RET( parse_nuh( &(msg->origin.nuh), ptr, end ), FALSE );
	}

	return TRUE;
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * command = 1*letter / 3digit
 */
static int parse_command( irc_msg_t * const msg, uint8_t ** ptr, uint8_t * const end )
{
	uint8_t * p = NULL;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( ptr, FALSE );
	CHECK_PTR_RET( *ptr, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_RET ( *ptr < end, FALSE );

	/* find the space at the end */
	for ( p = *ptr; (p < end) && (*p != ' '); ++p ) 
	{
		if ( !(isdigit(*p) || isalpha(*p)) )
			return FALSE;
	}

	/* terminate the string */
	*p = '\0';

	/* get the command from the string */
	msg->cmd = irc_cmd_get_command_from_string( *ptr );

	/* reset the string to original state */
	*p = ' ';

	/* move the ptr to the space after the command */
	*ptr = p;

	return TRUE;
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * params = *14( SPACE middle ) [ SPACE ":" trailing ]
 *        =/ 14( SPACE middle ) [ SPACE [ ":" ] trailing ]
 * middle = nospcrlfcl *( ":" / nospcrlfcl )
 * trailing = *( ":" / " " / nospcrlfcl )
 * nospcrlfcl = 0x01-0x09 / 0x0B-0x0C / 0x0E-0x1F / 0x21-0x39 / 0x3B-0xFF
 */
static int parse_params( irc_msg_t * const msg, uint8_t ** ptr, uint8_t * const end )
{
	uint8_t * p = NULL;
	uint8_t * pstart = NULL;
	int nparams = 0;
	int state = 0;

	CHECK_PTR_RET( msg, FALSE );
	CHECK_PTR_RET( ptr, FALSE );
	CHECK_PTR_RET( *ptr, FALSE );
	CHECK_PTR_RET( end, FALSE );
	CHECK_RET ( *ptr < end, FALSE );

	p = *ptr;
	while( TRUE );
	{
		switch ( state )
		{
			case 0:  /* SPACE */
				/* all params start with a space */
				CHECK_RET( *p == ' ', FALSE );
				state = 1;
				p++;
				break;

			case 1:  /* [ ":" ] */
				if ( (*p == ':') || (nparams == 14) )
				{
					state = 4;
					p++;
					pstart = p;
				}
				else
				{
					state = 2; /* middle first char */
					pstart = p;
					p++;
				}
				break;

			case 2:  /* middle first char */
				if ( !is_nospcrlfcl( *p ) )
					return FALSE;
				state = 3; /* middle rest */
				p++;
				break;

			case 3:  /* middle rest */
				if ( *p == ' ' )
				{
					nparam++;
					state = 0;
					/* add param to list */
				}
				else if ( (*p == ':') || (is_nospcrlfcl( *p ) ) )
					p++;
				else
					return FALSE;
				break;

			case 4:  /* trailing */
				if ( p == end )
				{
					/* add param to list */
					return TRUE;
				}

	}

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
			uint8_t* param = NULL;
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
			uint8_t* param = NULL;
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
irc_ret_t irc_msg_set_parameter(irc_msg_t* const msg, int32_t const index, uint8_t const * const param)
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


