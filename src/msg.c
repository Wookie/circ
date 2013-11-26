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

#if defined(UNIT_TESTING)
#include "test_flags.h"
static int fail_alloc_bak = FALSE;
#endif

static uint8_t COLON = ':';
static uint8_t SPACE = ' ';
static uint8_t DOT = '.';
static uint8_t AT = '@';
static uint8_t BANG = '!';
static uint8_t const * const MSGEND = "\r\n";

/* forward declaration of private functions */
static void param_delete_fn(void *s);
static inline int_t is_letter( uint8_t const c );
static inline int_t is_digit( uint8_t const c );
static inline int_t is_hex( uint8_t const c );
static inline int_t is_special( uint8_t const c );
static inline int_t is_user_octet( uint8_t const c );
static inline int_t is_key_octet( uint8_t const c );
static inline int_t is_nospcrlfcl_octet( uint8_t const c );
static inline int_t is_chanstart( uint8_t const c );
static inline int_t is_chanstring( uint8_t const c );
static int_t parse_shortname( uint8_t **shortname, uint8_t ** ptr, uint8_t * const end );
static int_t parse_hostname( uint8_t ** hostname, uint8_t ** ptr, uint8_t * const end );
static int_t parse_servername( uint8_t ** servername, uint8_t **ptr, uint8_t * const end );
static int_t parse_nickname( uint8_t ** nickname, uint8_t ** ptr, uint8_t * const end );
static int_t parse_user( uint8_t ** user, uint8_t ** ptr, uint8_t * const end );
static int_t parse_hostaddr( irc_msg_h_t * host, uint8_t ** ptr, uint8_t * const end );
static int_t parse_host( irc_msg_h_t * host, uint8_t ** ptr, uint8_t * const end );
static int_t parse_nuh( irc_msg_nuh_t * nuh, uint8_t ** ptr, uint8_t * const end );
static int_t parse_prefix( irc_msg_prefix_t * const prefix, uint8_t ** ptr, uint8_t * const end );
static int_t parse_command( irc_command_t * const cmd, uint8_t ** ptr, uint8_t * const end );
static int_t parse_params( list_t * const params, uint8_t ** ptr, uint8_t * const end );

#define TRAILING(l) ( (list_count(l) == 0) ? \
                      FALSE : \
                      (NULL != strchr( STR_PTR_P((irc_str_ref_t*)list_get( &(msg->params), \
                                                 list_itr_tail( &(msg->params) ))), ' ' )))

/*****************************************************************************/
/********** PRIVATE FUNCTIONS ************************************************/
/*****************************************************************************/


static void param_delete_fn(void *s)
{
    irc_str_ref_t *sref = (irc_str_ref_t*)s;

    /* if the string is dynamically allocated and we own it, free it here */
    if ( sref->dyn )
    {
        FREE( STR_PTR_P(sref) );
    }

    /* clean up the ref struct */
    FREE( sref );
}


/* create a new message */
irc_msg_t* irc_msg_new()
{
    irc_msg_t* msg = NULL;
    
    /* allocate the msg */
    msg = CALLOC(1, sizeof(irc_msg_t));
    CHECK_PTR_RET(msg, NULL);

    /* initialize the params list */
    CHECK_GOTO( list_initialize( &(msg->params), IRC_NUM_PARAMS, &param_delete_fn ), _irc_msg_new_fail );
    
    /* initialize the out strs list */
    CHECK_GOTO( list_initialize( &(msg->out.strs), IRC_NUM_PARAMS, &param_delete_fn ), _irc_msg_new_fail );

    return msg;

_irc_msg_new_fail:
    irc_msg_delete( msg );
    return NULL;
}

/* create a new message from a buffer */
irc_msg_t* irc_msg_new_from_data( uint8_t const * const data, size_t const size )
{
    irc_msg_t* msg = NULL;
    
    /* allocate the msg */
    msg = CALLOC(1, sizeof(irc_msg_t));
    CHECK_PTR_RET(msg, NULL);

    /* initialize the params list */
    CHECK_GOTO( list_initialize( &(msg->params), IRC_NUM_PARAMS, &param_delete_fn ), _irc_msg_new_fail );

    /* initialize the out strs list */
    CHECK_GOTO( list_initialize( &(msg->out.strs), IRC_NUM_PARAMS, &param_delete_fn ), _irc_msg_new_fail );

#if defined(UNIT_TESTING)
    if ( fail_irc_msg_new_data_alloc )
    {
        fail_alloc_bak = fail_alloc;
        fail_alloc = TRUE;
    }
#endif

    /* allocate memory for the data */
    msg->in.data = CALLOC( size, sizeof(uint8_t) );

#if defined(UNIT_TESTING)
    if ( fail_irc_msg_new_data_alloc )
    {
        fail_alloc = fail_alloc_bak;
    }
#endif

    CHECK_PTR_GOTO( msg->in.data, _irc_msg_new_fail );
    msg->in.size = size;

    /* copy the data into the in buffer */
    MEMCPY( msg->in.data, data, size );

    /* now try to parse it */
    CHECK_GOTO( (IRC_OK == irc_msg_parse( msg )), _irc_msg_new_fail );

    /* check for trailing parameter */
    msg->trailing = TRAILING( &(msg->params) );
    
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

    /* clean up the params list */
    list_deinitialize( &(msg->params) );

    /* clean up the out strs list */
    list_deinitialize( &(msg->out.strs) );

    /* delete the array of iovec structs */
    FREE( msg->out.iov );

    /* delete the data buffer */
    FREE( msg->in.data );

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
 * message itself.  There MUST be NO gap (whitespace) between the colon
 * and the prefix.  The prefix is used by servers to indicate the true
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
 * for the command and its parameters.  There is no provision for
 * continuation of message lines.  See section 6 for more details about
 * current implementations.
 */
irc_ret_t irc_msg_parse(irc_msg_t* const msg)
{
    uint8_t* ptr = NULL;
    uint8_t* end = NULL;
    
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( msg->in.data, IRC_ERR );
    CHECK_RET( (msg->in.size > 0), IRC_ERR );
    
    UNIT_TEST_RET( irc_msg_parse );

    /* start by initializing the ptr to the first octet in the buffer */
    ptr = &(msg->in.data[0]);
    
    /* double check that the message buffer ends in \r\n */
    end = (&msg->in.data[0] + msg->in.size) - 2;
    CHECK_RET( end[0] == '\r', IRC_ERR );
    CHECK_RET( end[1] == '\n', IRC_ERR );

    /* zero out the last two bytes so that we end in null byte */
    end[0] = '\0';
    end[1] = '\0';
 
    /***** PREFIX *****/
    if ( ptr[0] == ':' )
    {
        /* skip over the leading ':' */
        ++ptr;

        CHECK_RET( parse_prefix( &(msg->prefix), &ptr, end ), IRC_ERR );
    }
   
    /***** COMMAND *****/
    CHECK_RET( parse_command( &(msg->cmd), &ptr, end ), IRC_ERR );

    /**** PARAMS ****/
    CHECK_RET( parse_params( &(msg->params), &ptr, end ), IRC_ERR );

    return IRC_OK;
}

#define IP_LOG_BUF_SIZE (128)
static ssize_t irc_msg_prefix_r( irc_msg_prefix_t const * const prefix, uint8_t * const buf, size_t len )
{
    uint8_t * p;
    static uint8_t tmp[IP_LOG_BUF_SIZE];

    switch( prefix->kind )
    {
        case CONN_PREFIX:
            /* no prefix...do nothing */
            MEMSET( buf, 0, len );
            return 0;
        case SERVERNAME_PREFIX:
            return snprintf( buf, len, "%s", STR_PTR(prefix->servername) );
        case NUH_PREFIX:
            switch( prefix->nuh.host.kind )
            {
                case NO_HOST:
                    return snprintf( buf, len, "%s", STR_PTR(prefix->nuh.nickname) );
                case V4_HOSTADDR:
                    if ( STR_PTR( prefix->nuh.host.hostname ) == NULL )
                    {
                        /* convert IPv4 address to dotted quad string */
                        MEMSET( tmp, 0, IP_LOG_BUF_SIZE );
                        inet_ntop( AF_INET, socket_in_addr((sockaddr_t*)&(prefix->nuh.host.addr)), 
                                   tmp, IP_LOG_BUF_SIZE );
                        p = tmp;
                    }
                    else
                    {
                        p = STR_PTR( prefix->nuh.host.hostname );
                    }

                    if ( STR_PTR(prefix->nuh.user) != NULL )
                    {
                        /* we have nick!user@host */
                        return snprintf( buf, len, "%s!%s@%s", 
                                         STR_PTR(prefix->nuh.nickname), 
                                         STR_PTR(prefix->nuh.user), p );
                    }
                    else
                    {
                        /* we have nick@host */
                        return snprintf( buf, len, "%s@%s", STR_PTR(prefix->nuh.nickname), p );
                    }
                    break;
                case V6_HOSTADDR:
                    if ( STR_PTR( prefix->nuh.host.hostname ) == NULL )
                    {
                        /* convert IPv6 address to dotted quad string */
                        MEMSET( tmp, 0, IP_LOG_BUF_SIZE );
                        inet_ntop( AF_INET6, socket_in_addr((sockaddr_t*)&(prefix->nuh.host.addr)), 
                                   tmp, IP_LOG_BUF_SIZE );
                        p = tmp;
                    }
                    else
                    {
                        p = STR_PTR( prefix->nuh.host.hostname );
                    }

                    if ( STR_PTR(prefix->nuh.user) != NULL )
                    {
                        /* we have nick!user@host */
                        return snprintf( buf, len, "%s!%s@%s", 
                                         STR_PTR(prefix->nuh.nickname), 
                                         STR_PTR(prefix->nuh.user), p );
                    }
                    else
                    {
                        /* we have nick@host */
                        return snprintf( buf, len, "%s@%s", 
                                         STR_PTR(prefix->nuh.nickname), p );
                    }
                    break;
                case HOSTNAME:
                    if ( STR_PTR(prefix->nuh.user) != NULL )
                    {
                        /* we have nick!user@host */
                        return snprintf( buf, len, "%s!%s@%s", 
                                         STR_PTR(prefix->nuh.nickname),
                                         STR_PTR(prefix->nuh.user), 
                                         STR_PTR( prefix->nuh.host.hostname ) );
                    }
                    else
                    {
                        /* we have nick@host */
                        return snprintf( buf, len, "%s@%s", 
                                         STR_PTR(prefix->nuh.nickname), 
                                         STR_PTR( prefix->nuh.host.hostname ) );
                    }
                    break;
            }
            break;
    }

    return IRC_ERR;
}

static void irc_msg_log_prefix( irc_msg_prefix_t const * const prefix )
{
    static uint8_t buf[IP_LOG_BUF_SIZE];

    switch( prefix->kind )
    {
        case CONN_PREFIX:
            /* no prefix...do nothing */
            break;
        case SERVERNAME_PREFIX:
            LOG( "  (%s)\n", STR_PTR(prefix->servername) );
            break;
        case NUH_PREFIX:
            switch( prefix->nuh.host.kind )
            {
                case NO_HOST:
                    LOG( " (%s)\n", STR_PTR(prefix->nuh.nickname) );
                    break;
                case V4_HOSTADDR:
                    /* convert IPv4 address to dotted quad string */
                    MEMSET( buf, 0, IP_LOG_BUF_SIZE );
                    inet_ntop( AF_INET, socket_in_addr((sockaddr_t*)&(prefix->nuh.host.addr)), buf, IP_LOG_BUF_SIZE );

                    if ( STR_PTR(prefix->nuh.user) != NULL )
                    {
                        /* we have nick!user@host */
                        LOG( "  (%s ! %s @ %s)\n", STR_PTR(prefix->nuh.nickname), STR_PTR(prefix->nuh.user), buf);
                    }
                    else
                    {
                        /* we have nick@host */
                        LOG( "  (%s @ %s)\n", STR_PTR(prefix->nuh.nickname), buf );
                    }
                    break;
                case V6_HOSTADDR:
                    /* convert IPv6 address to dotted quad string */
                    MEMSET( buf, 0, IP_LOG_BUF_SIZE );
                    inet_ntop( AF_INET6, socket_in_addr((sockaddr_t*)&(prefix->nuh.host.addr)), buf, IP_LOG_BUF_SIZE );

                    if ( STR_PTR(prefix->nuh.user) != NULL )
                    {
                        /* we have nick!user@host */
                        LOG( "  (%s ! %s @ %s)\n", STR_PTR(prefix->nuh.nickname), STR_PTR(prefix->nuh.user), buf);
                    }
                    else
                    {
                        /* we have nick@host */
                        LOG( "  (%s @ %s)\n", STR_PTR(prefix->nuh.nickname), buf );
                    }
                    break;
                case HOSTNAME:
                    if ( STR_PTR(prefix->nuh.user) != NULL )
                    {
                        /* we have nick!user@host */
                        LOG( "  (%s ! %s @ %s)\n", 
                             STR_PTR(prefix->nuh.nickname), 
                             STR_PTR(prefix->nuh.user), 
                             STR_PTR( prefix->nuh.host.hostname ) );
                    }
                    else
                    {
                        /* we have nick@host */
                        LOG( "  (%s @ %s)\n", 
                             STR_PTR(prefix->nuh.nickname), 
                             STR_PTR( prefix->nuh.host.hostname ) );
                    }
                    break;
            }
            break;
    }
}

void irc_msg_log( irc_msg_t const * const msg )
{
    list_itr_t itr, end;

    LOG( "(%s\n", irc_cmd_get_type_string( msg->cmd ) );

    /* PREFIX */
    irc_msg_log_prefix( &(msg->prefix) );
    
    /* command */
    LOG( "  (%s\n", irc_cmd_get_string( msg->cmd ) );

    if ( list_count( &(msg->params) ) > 0 )
    {
        itr = list_itr_begin( &(msg->params) );
        end = list_itr_end( &(msg->params) );

        LOG("  (\n");
        for ( ; itr != end; itr = list_itr_next( &(msg->params), itr ) )
        {
            LOG( "    %s\n", C(list_get( &(msg->params), itr )) );
        }
        LOG("  )\n");
    }
    
    LOG(")\n");
}

/* initialize the message in one pass */
irc_ret_t irc_msg_set_all(
    irc_msg_t* const msg,
    irc_command_t const cmd,
    irc_msg_prefix_t* const prefix,
    uint_t const count,
    ...
)
{
    va_list va;
    uint_t i;

    CHECK_PTR_RET(msg, IRC_BADPARAM);
    CHECK_RET(IS_VALID_COMMAND(cmd), IRC_BADPARAM);
   
    /* store the prefix if there is one */
    if(prefix != NULL)
    {
        /* copy the prefix into place */
        MEMCPY( &(msg->prefix), prefix, sizeof( irc_msg_prefix_t ) );
    }

    /* store the command string */
    msg->cmd = cmd;

    /* add parameters */
    va_start( va, count );
    for( i = 0; i < count; i++ )
    {
        CHECK_GOTO( IRC_OK == irc_msg_add_parameter( msg, va_arg(va, uint8_t*) ), _irc_msg_set_fail );
    }
    va_end(va);
    
    return IRC_OK;

_irc_msg_set_fail:
    va_end(va);
    return IRC_ERR;
}

/* add a parameter */
irc_ret_t irc_msg_add_parameter(irc_msg_t* const msg, uint8_t const * const param)
{
    irc_str_ref_t * s;
    CHECK_PTR_RET(msg, IRC_BADPARAM);
    CHECK_PTR_RET(param, IRC_BADPARAM);
    CHECK_PTR_RET(msg->trailing == FALSE, IRC_ERR );

    /* create str ref */
    CHECK_PTR_GOTO( s = CALLOC( 1, sizeof(irc_str_ref_t) ), failed_to_add_param );

    /* dup the parameter */
    CHECK_PTR_GOTO( STR_PTR_P_SET(s, T(strndup(C(param), IRC_MSG_SIZE))), failed_to_add_param );
  
    /* push the param to the param list */
    CHECK_GOTO( list_push_tail( &(msg->params), s ), failed_to_add_param );
    
    return IRC_OK;

failed_to_add_param:
    WARN("failed to push param into message %s\n", check_err_str_);
    FREE( STR_PTR_P(s) );
    FREE( s );
    return IRC_ERR;
}

irc_ret_t irc_msg_set_trailing( irc_msg_t * const msg, uint8_t const * const param )
{
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_RET( msg->trailing == FALSE, IRC_ERR );
    CHECK_RET( irc_msg_add_parameter( msg, param ), IRC_ERR );
    msg->trailing = TRUE;
    return IRC_OK;
}

/* this compiles the msg into a buffer than can be sent over the socket */
irc_ret_t irc_msg_finalize( irc_msg_t * const msg )
{
    struct iovec * vec;
    size_t newsize = 0;
    irc_str_ref_t * s = NULL;
    list_itr_t itr;
    static uint8_t buf[IRC_MSG_SIZE];
    int_t trailing = FALSE;

    CHECK_PTR_RET(msg, IRC_BADPARAM);

    if ( msg->out.iov != NULL )
        FREE( msg->out.iov );

    /***********************************************/
    /**** count how many struct iovec's we need ****/
    /***********************************************/

    /* add three for the prefix, (: prefix <space>)  */
    if ( msg->prefix.kind > CONN_PREFIX )
        newsize += 3;

    /* add one for the command */   
    newsize++;

    /* add two for each parameter (<space> param) */
    newsize += (list_count( &(msg->params) ) * 2);

    /* add one for colon if last param has a space */
    if ( msg->trailing )
        newsize++;

    /* add one more for the \r\n at the end */
    newsize++;

    /************************************/
    /**** fill in the struct iovec's ****/
    /************************************/
    
    /* now allocate the new iovec struct array */
    msg->out.iov = CALLOC( newsize, sizeof(struct iovec) );
    CHECK_PTR_RET_MSG( msg->out.iov, IRC_ERR, "failed to allocate iovec struct array\n" );

    /* store the array length */
    msg->out.nvec = newsize;

    /* now fill in the iovec structs */
    vec = msg->out.iov;

    if ( msg->prefix.kind > CONN_PREFIX )
    {
        /* add colon */
        vec->iov_base = &COLON;
        vec->iov_len = 1;
        vec++;

        /* serialize the prefix */
        s = CALLOC( 1, sizeof(irc_str_ref_t) );
        irc_msg_prefix_r( &(msg->prefix), buf, IRC_MSG_SIZE );
        STR_PTR_P_SET( s, T(strndup(buf, IRC_MSG_SIZE)) );
        s->dyn = TRUE;
        list_push_tail( &(msg->out.strs), (void*)s );

        /* add prefix */
        vec->iov_base = STR_PTR_P(s);
        vec->iov_len = strnlen( vec->iov_base, IRC_MSG_SIZE );
        vec++;

        /* add space */
        vec->iov_base = &SPACE;
        vec->iov_len = 1;
        vec++;
    }

    /* add command */
    vec->iov_base = T(irc_cmd_get_string( msg->cmd ));
    vec->iov_len = strnlen( vec->iov_base, IRC_MSG_SIZE );
    vec++;

    /* add the params */
    for ( itr = list_itr_begin( &(msg->params) ); 
          itr != list_itr_end( &(msg->params) ); 
          itr = list_itr_next( &(msg->params), itr ) )
    {
        /* add space */
        vec->iov_base = &SPACE;
        vec->iov_len = 1;
        vec++;

        /* if this is the last param and it is marked as 'trailing',
         * we need to precede it with a ':' character */
        if ( (itr == list_itr_tail( &(msg->params) ) ) && msg->trailing )
        {
            /* add colon */
            vec->iov_base = &COLON;
            vec->iov_len = 1;
            vec++;
        }

        /* add param */
        s = (irc_str_ref_t*)list_get( &(msg->params), itr );
        vec->iov_base = STR_PTR_P(s);
        vec->iov_len = strnlen( vec->iov_base, IRC_MSG_SIZE );
        vec++;
    }

    /* finish with \r\n */
    vec->iov_base = (void*)MSGEND;
    vec->iov_len = 2;

    return IRC_OK;
}

irc_ret_t irc_msg_flatten( irc_msg_t * const msg, uint8_t ** s )
{
    size_t i, len = 0;
    uint8_t * p, * buf;
    CHECK_PTR_RET( msg, IRC_BADPARAM );
    CHECK_PTR_RET( msg->out.iov, IRC_BADPARAM );
    CHECK_PTR_RET( s, IRC_BADPARAM );

    /* add up the total data size */
    for ( i = 0; i < msg->out.nvec; i++ )
    {
        len += msg->out.iov[i].iov_len;
    }
    ++len;

    CHECK_RET( len <= IRC_MSG_SIZE, IRC_ERR );

    buf = CALLOC( len, sizeof(uint8_t) );

    /* copy the data into the string */
    p = buf;
    for ( i = 0; i < msg->out.nvec; i++ )
    {
        MEMCPY( p, msg->out.iov[i].iov_base, msg->out.iov[i].iov_len );
        p += msg->out.iov[i].iov_len;
    }

    /* pass back the string pointer */
    (*s) = buf;

    return IRC_OK;
}



/*****************************************************************************/
/********** PRIVATE FUNCTIONS ************************************************/
/*****************************************************************************/

static inline int_t is_letter( uint8_t const c )
{
    return ( ( (c >= 'a') && (c <= 'z') ) ||
             ( (c >= 'A') && (c <= 'Z') ) );
}

static inline int_t is_digit( uint8_t const c )
{
    return ( (c >= '0') && (c <= '9') );
}

static inline int_t is_hex( uint8_t const c )
{
    return ( ( (c >= '0') && (c <= '9') ) ||
             ( (c >= 'A') && (c <= 'F') ) ||
             ( (c >= 'a') && (c <= 'f') ) );
}

static inline int_t is_special( uint8_t const c )
{
    return ( ( (c >= 0x5B) && (c <= 0x60) ) ||
             ( (c >= 0x7B) && (c <= 0x7D) ) );
}

static inline int_t is_user_octet( uint8_t const c )
{
    return ( ( (c >= 0x01) && (c <= 0x09) ) ||
             ( (c >= 0x0B) && (c <= 0x0C) ) ||
             ( (c >= 0x0E) && (c <= 0x1F) ) ||
             ( (c >= 0x21) && (c <= 0x3F) ) ||
             ( (c >= 0x41) && (c <= 0xFF) ) );
}

static inline int_t is_key_octet( uint8_t const c )
{
    return ( ( (c >= 0x01) && (c <= 0x05) ) ||
             ( (c >= 0x07) && (c <= 0x08) ) ||
             ( (c == 0x0C)                ) ||
             ( (c >= 0x0E) && (c <= 0x1F) ) ||
             ( (c >= 0x21) && (c <= 0x7F) ) );
}

static inline int_t is_nospcrlfcl_octet( uint8_t const c )
{
    return ( ( (c >= 0x01) && (c <= 0x09) ) ||
             ( (c >= 0x0B) && (c <= 0x0C) ) ||
             ( (c >= 0x0E) && (c <= 0x1F) ) ||
             ( (c >= 0x21) && (c <= 0x39) ) ||
             ( (c >= 0x3B) && (c <= 0xFF) ) );
}

static inline int_t is_chanstart( uint8_t const c )
{
    return ( ( c == '!' ) ||    /* 0x21 */
             ( c == '#' ) ||    /* 0x23 */
             ( c == '&' ) ||    /* 0x26 */
             ( c == '+' ) );    /* 0x2B */
}

static inline int_t is_chanstring( uint8_t const c )
{
    return ( ( (c >= 0x01) && (c <= 0x09) ) ||
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
static int_t parse_shortname( uint8_t **shortname, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    uint8_t * last = NULL;

    CHECK_PTR_RET( shortname, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET ( *ptr < end, FALSE );

    p = *ptr;

    if ( (*p == SPACE) || (*p == DOT) )
        return FALSE;

    for ( ; (p < end) && (*p != SPACE) && (*p != DOT); ++p )
    {
        if ( p == *ptr )
        {
            /* first octet must be letter or digit */
            if ( !is_letter(*p) && !is_digit(*p) )
                return FALSE;
        }
        else
        {
            /* remember this octet as possibly the last one */
            last = p;

            /* middle octets must be letter or digit or hyphen */
            if ( !is_letter(*p) && !is_digit(*p) && (*p != '-') )
                return FALSE;
        }
    }

    /* check that the last octet we saw is a letter or digit */
    if ( (last != NULL) && !is_letter(*last) && !is_digit(*last) )
        return FALSE;

    /* set shortname to point to start of shortname */
    *shortname = *ptr;

    /* update ptr */
    *ptr = p;

    return TRUE;
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * hostname = shortname *( "." shortname )
 *
 * NOTE: CANNOT BE AN IPv4 DOTTED QUAD IP ADDRESS
 */
static int_t parse_hostname( uint8_t ** hostname, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    uint8_t * shortname = NULL;
    struct in_addr dummy;

    CHECK_PTR_RET( hostname, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );

    p = *ptr;
    while ( parse_shortname( &shortname, &p, end ) )
    {
        if ( *p == DOT )
        {
            ++p;
        }
    }

    /* should have consumed all the way to end pointer */
    CHECK_RET( (p == end), FALSE );

    /* make sure it isn't an IPv4 dotted quad */
    CHECK_RET( (inet_pton( AF_INET, *ptr, &dummy ) != TRUE), FALSE );

    /* store hostname pointer */
    *hostname = *ptr;

    /* update ptr to the first non-hostname octet */
    *ptr = p;

    return TRUE;
}

/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * servername = hostname
 *
 * NOTE: severname cannot include IPv4 or IPv6 addresses, it must be a name.
 */
static int_t parse_servername( uint8_t ** servername, uint8_t **ptr, uint8_t * const end )
{
    CHECK_PTR_RET( servername, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET ( *ptr < end, FALSE );

    return parse_hostname( servername, ptr, end );
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * nickname = ( letter / special ) *8( letter / digit / special / "-" )
 *
 * special = '[' / '\' / ']' / '^' / '_' / '`' / '{' / '|' / '}'
 */
static int_t parse_nickname( uint8_t ** nickname, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;

    CHECK_PTR_RET( nickname, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );

    for ( p = *ptr; p < end; ++p )
    {
        if ( p == *ptr )
        {
            /* first character of nickname MUST be letter or special */
            if ( !is_letter(*p) && !is_special(*p) )
                return FALSE;
        }
        else
        {
            /* zero to eight letters, digits, special, or "-" */
            if ( !is_letter(*p) && !is_digit(*p) && !is_special(*p) && (*p != '-') )
                return FALSE;
        }

        if ( (p - *ptr) >= IRC_NICKNAME_MAX )
            return FALSE;
    }

    /* set nickname pointer */
    *nickname = *ptr;

    /* update ptr to first octet after nickname */
    *ptr = p;

    return TRUE;
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * user = 1*( %x01-09 / %x0B-0C / %x0E-1F / %x21-3F / %x41-FF )
 *
 * user is one or more of any octet excep NUL, CR, LF, " " and "@"
 */
static int_t parse_user( uint8_t ** user, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;

    CHECK_PTR_RET( user, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );

    for ( p = *ptr; (p < end); ++p )
    {
        if ( !is_user_octet(*p) )
            return FALSE;
    }

    /* set user pointer */
    *user = *ptr;

    /* update ptr to first octet after user */
    *ptr = p;

    return TRUE;
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * hostaddr = ip4addr / ip6addr
 */
static int_t parse_hostaddr( irc_msg_h_t * host, uint8_t ** ptr, uint8_t * const end )
{
    CHECK_PTR_RET( host, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );

    /* first try to parse an IPv6 address */
    if ( inet_pton( AF_INET6, *ptr, socket_in_addr(&(host->addr)) ) )
    {
        /* remember that it is an IPv6 address */
        host->kind = V6_HOSTADDR;
        return TRUE;
    }

    /* if that didn't work, try to parse an IPv4 address */
    if ( inet_pton( AF_INET, *ptr, socket_in_addr(&(host->addr)) ) )
    {
        /* remember that it is a IPv4 address */
        host->kind = V4_HOSTADDR;
        return TRUE;
    }

    return FALSE;
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * host = hostname / hostaddr
 */
static int_t parse_host( irc_msg_h_t * host, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    CHECK_PTR_RET( host, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );

    /* first try to parse a hostaddr */
    if ( parse_hostaddr( host, ptr, end ) )
    {
        /* store the raw string in the hostname */
        STR_PTR_SET( host->hostname, *ptr );

        /* we assume that the hostaddr goes from *ptr to end */
        *ptr = end;

        return TRUE;
    }

    /* if that didn't work, then it must be a hostname */
    CHECK_RET( parse_hostname( &p, ptr, end ), FALSE );
    STR_PTR_SET( host->hostname, p );

    /* remember that it is a hostname */
    host->kind = HOSTNAME;

    return TRUE;
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * nuh = ( nickname [ [ "!" user ] "@" host ] )
 */
static int_t parse_nuh( irc_msg_nuh_t * nuh, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    uint8_t * pend = NULL;
    uint8_t * nick = NULL;
    uint8_t * user = NULL;
    CHECK_PTR_RET( nuh, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );

    p = *ptr;
    for ( pend = p; (pend < end) && (*pend != '!') && (*pend != '@'); ++pend ) {}

    /* there is always at least a nickname */
    CHECK_RET( parse_nickname( &nick, &p, pend ), FALSE );
    STR_PTR_SET( nuh->nickname, nick );

    if ( *p == BANG ) /* user if we're at a '!' */
    {
        /* terminate nickname string and move to first octet of user */
        *p = '\0';
        ++p;
    
        for ( pend = p; (pend < end) && (*pend != '@'); ++pend ) {}

        /* if we got a user part, there must be a trailing '@' before the host part */
        CHECK_RET( (*pend == '@'), FALSE );

        /* parse user */
        CHECK_RET( parse_user( &user, &p, pend ), FALSE );
        STR_PTR_SET( nuh->user, user );
    }
    
    if ( *p == AT ) /* host if we're at a '@' */
    {
        /* terminate nickname or user string and move to first octet of host */
        *p = '\0';
        ++p;

        /* parse host */
        CHECK_RET( parse_host( &(nuh->host), &p, end ), FALSE );
    }

    /* move ptr up to the next octet after nuh */
    *ptr = p;

    return TRUE;
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * prefix = servername / (nickname [ [ "!" user ] "@" host ] )
 *
 * NOTE: this is an ambiguous grammar because the prefix could contain
 * just a sequence of letters (a-z, A-Z) and there is no way to tell if
 * it is just a server name without any dotted parts or just a nickname
 * with no user or host parts.  when parsing an ambiguous message, it
 * assumes the prefix specifies a server name.
 */
static int_t parse_prefix( irc_msg_prefix_t * const prefix, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    uint8_t * space = NULL;
    uint8_t * server = NULL;

    CHECK_PTR_RET( prefix, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET( *ptr < end, FALSE );
    
    p = *ptr;

    /* find the trailing space, and remember if we see a bang or at sign */
    for( space = p; (*space != SPACE) && (space < end); ++space ) {}

    /* check to see if we ran to the end of the buffer */
    CHECK_RET( (space < end), IRC_BAD_MESSAGE );

    /* terminate the prefix */
    *space = '\0';

    if ( parse_servername( &server, &p, space ) )
    {
        /* store the pointer */
        STR_PTR_SET( prefix->servername, server );

        /* prefix was a server name */
        prefix->kind = SERVERNAME_PREFIX;
    }
    else if ( parse_nuh( &(prefix->nuh), &p, space ) )
    {
        /* prefix was an nuh */
        prefix->kind = NUH_PREFIX;
    }
    else
    {
        return FALSE;
    }

    /* move ptr to the first octet of the command */
    ++p;
    *ptr = p;

    return TRUE;
}


/*
 * RFC 2812, Section 2.3.1 -- Message format in Augmented BNF
 *
 * command = 1*letter / 3digit
 */
static int_t parse_command( irc_command_t * const cmd, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    int_t space = FALSE;

    CHECK_PTR_RET( cmd, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET ( *ptr < end, FALSE );

    /* find the space at the end */
    for ( p = *ptr; (p < end) && (*p != SPACE); ++p ) 
    {
        if ( !isdigit(*p) && !isalpha(*p) )
            return FALSE;
    }

    /* temporarily terminate the command string so we can convert it
     * to the proper irc_command_t value */
    if ( *p == SPACE )
    {
        space = TRUE;
        *p = '\0';
    }

    /* get the command from the string */
    (*cmd) = irc_cmd_get_command_from_string( *ptr );

    /* make sure we got a valid command */
    CHECK_RET( ((*cmd) != NOCMD), FALSE );

    /* reset the string to prefixal state */
    if ( space )
        *p = SPACE;

    /* move the ptr to the octet after the command string */
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
static int_t parse_params( list_t * const params, uint8_t ** ptr, uint8_t * const end )
{
    uint8_t * p = NULL;
    uint8_t * pstart = NULL;
    int nparams = 0;
    int state = 0;
    irc_str_ref_t *s = NULL;

    CHECK_PTR_RET( params, FALSE );
    CHECK_PTR_RET( ptr, FALSE );
    CHECK_PTR_RET( *ptr, FALSE );
    CHECK_PTR_RET( end, FALSE );
    CHECK_RET ( *ptr <= end, FALSE );

    p = *ptr;
    while( p < end )
    {
        switch ( state )
        {
            case 0:  /* SPACE */
                /* all params start with a space */
                CHECK_RET( *p == SPACE, FALSE );
                state = 1;

                /* terminate previous string */
                *p = '\0';

                /* move to first octet of param */
                ++p;
                break;

            case 1:  /* [ ":" ] */
                if ( *p == ':' )
                {
                    /* zero out ':' */
                    *p = '\0';

                    /* move to first octet of param */
                    ++p;

                    state = 4;
                }
                else if (nparams == 14)
                {
                    /* 15th param with no ':' */
                    state = 4;
                }
                else
                {
                    state = 2; /* middle first char */
                }

                /* remember where the param started */
                pstart = p;
                break;

            case 2:  /* middle first char */
                CHECK_RET( is_nospcrlfcl_octet( *p ), FALSE );
                state = 3; /* middle rest */
                ++p;
                break;

            case 3:  /* middle rest */
                if ( *p == SPACE )
                {
                    /* end of param */
                    nparams++;

                    /* create str ref to the param */
                    CHECK_GOTO( s = CALLOC( 1, sizeof( irc_str_ref_t ) ), _irc_str_ref_new_fail );
                    STR_PTR_P_SET( s, pstart );
                    s->dyn = FALSE;

                    /* add pointer to param start to list */
                    CHECK_RET( list_push_tail( params, s ), FALSE );
                    pstart = NULL;

                    state = 0; /* space between params */
                }
                else if ( (*p == ':') || (is_nospcrlfcl_octet( *p ) ) )
                {
                    /* just a middle character of a param */
                    p++;
                }
                else
                {
                    /* anything else is a malformed param */
                    return FALSE;
                }
                break;

            case 4:  /* trailing */
                if ( (*p == ':') || (*p == SPACE) || (is_nospcrlfcl_octet( *p ) ) )
                {
                    /* valid middle char of trailing, move to the next octet */
                    ++p;
                }
                else
                {
                    /* anything else is a malformed trailing param */
                    return FALSE;
                }
                break;
        }
    }

    if ( pstart != NULL )
    {
        /* create str ref to the param */
        CHECK_GOTO( s = CALLOC( 1, sizeof( irc_str_ref_t ) ), _irc_str_ref_new_fail );
        STR_PTR_P_SET( s, pstart );
        s->dyn = FALSE;

        /* add the pointer to the start of the last param to the list */
        CHECK_RET( list_push_tail( params, s ), FALSE );
    }

    /* move ptr to first octet after params */
    *ptr = p;

    return TRUE;

_irc_str_ref_new_fail:
    WARN("%s\n", check_err_str_);
    return FALSE;
}


#if defined(UNIT_TESTING)

#include <CUnit/Basic.h>

static void test_msg_is_letter( void )
{
    CU_ASSERT_FALSE( is_letter( '@' ) );
    CU_ASSERT_TRUE( is_letter( 'A' ) );
    CU_ASSERT_FALSE( is_letter( '[' ) );
    CU_ASSERT_TRUE( is_letter( 'a' ) );
    CU_ASSERT_FALSE( is_letter( '{' ) );
}

static void test_msg_is_digit( void )
{
    CU_ASSERT_FALSE( is_digit( '/' ) );
    CU_ASSERT_TRUE( is_digit( '0' ) );
    CU_ASSERT_FALSE( is_digit( '@' ) );
}

static void test_msg_is_hex( void )
{
    CU_ASSERT_FALSE( is_hex('/') );
    CU_ASSERT_TRUE( is_hex('0') );
    CU_ASSERT_FALSE( is_hex(':') );
    CU_ASSERT_TRUE( is_hex('A') );
    CU_ASSERT_FALSE( is_hex('G') );
    CU_ASSERT_TRUE( is_hex('a') );
    CU_ASSERT_FALSE( is_hex('g') );
}

static void test_msg_is_special( void )
{
    CU_ASSERT_FALSE( is_special('Z') );
    CU_ASSERT_TRUE( is_special('[') );
    CU_ASSERT_FALSE( is_special('a') );
    CU_ASSERT_TRUE( is_special('{') );
    CU_ASSERT_FALSE( is_special('~') );
}

static void test_msg_is_user_octet( void )
{
    CU_ASSERT_FALSE( is_user_octet( '\x00' ) );
    CU_ASSERT_TRUE( is_user_octet( '\x01' ) );
    CU_ASSERT_FALSE( is_user_octet( '\x0A' ) );
    CU_ASSERT_TRUE( is_user_octet( '\x0B' ) );
    CU_ASSERT_FALSE( is_user_octet( '\x0D' ) );
    CU_ASSERT_TRUE( is_user_octet( '\x0E' ) );
    CU_ASSERT_FALSE( is_user_octet( '\x20' ) );
    CU_ASSERT_TRUE( is_user_octet( '\x21' ) );
    CU_ASSERT_FALSE( is_user_octet( '\x40' ) );
    CU_ASSERT_TRUE( is_user_octet( '\x41' ) );
}

static void test_msg_is_key_octet( void )
{
    CU_ASSERT_FALSE( is_key_octet( '\x00' ) );
    CU_ASSERT_TRUE( is_key_octet( '\x01' ) );
    CU_ASSERT_FALSE( is_key_octet( '\x06' ) );
    CU_ASSERT_TRUE( is_key_octet( '\x07' ) );
    CU_ASSERT_FALSE( is_key_octet( '\x09' ) );
    CU_ASSERT_TRUE( is_key_octet( '\x0C' ) );
    CU_ASSERT_FALSE( is_key_octet( '\x0D' ) );
    CU_ASSERT_TRUE( is_key_octet( '\x0E' ) );
    CU_ASSERT_FALSE( is_key_octet( '\x20' ) );
    CU_ASSERT_TRUE( is_key_octet( '\x21' ) );
    CU_ASSERT_FALSE( is_key_octet( '\x80' ) );
}

static void test_msg_is_nospcrlfcl_octet( void )
{
    CU_ASSERT_FALSE( is_nospcrlfcl_octet( '\x00' ) );
    CU_ASSERT_TRUE( is_nospcrlfcl_octet( '\x01' ) );
    CU_ASSERT_FALSE( is_nospcrlfcl_octet( '\x0A' ) );
    CU_ASSERT_TRUE( is_nospcrlfcl_octet( '\x0B' ) );
    CU_ASSERT_FALSE( is_nospcrlfcl_octet( '\x0D' ) );
    CU_ASSERT_TRUE( is_nospcrlfcl_octet( '\x0E' ) );
    CU_ASSERT_FALSE( is_nospcrlfcl_octet( '\x20' ) );
    CU_ASSERT_TRUE( is_nospcrlfcl_octet( '\x21' ) );
    CU_ASSERT_FALSE( is_nospcrlfcl_octet( '\x3A' ) );
    CU_ASSERT_TRUE( is_nospcrlfcl_octet( '\x3B' ) );
}

static void test_msg_is_chanstart( void )
{
    CU_ASSERT_FALSE( is_chanstart( '\x20' ) );
    CU_ASSERT_TRUE( is_chanstart( '!' ) );
    CU_ASSERT_FALSE( is_chanstart( '\x22' ) );
    CU_ASSERT_TRUE( is_chanstart( '#' ) );
    CU_ASSERT_FALSE( is_chanstart( '\x24' ) );
    CU_ASSERT_TRUE( is_chanstart( '&' ) );
    CU_ASSERT_FALSE( is_chanstart( '\x27' ) );
    CU_ASSERT_TRUE( is_chanstart( '+' ) );
    CU_ASSERT_FALSE( is_chanstart( '\x2C' ) );
}

static void test_msg_is_chanstring( void )
{
    CU_ASSERT_FALSE( is_chanstring( '\x00' ) );
    CU_ASSERT_TRUE( is_chanstring( '\x01' ) );
    CU_ASSERT_FALSE( is_chanstring( '\x0A' ) );
    CU_ASSERT_TRUE( is_chanstring( '\x0B' ) );
    CU_ASSERT_FALSE( is_chanstring( '\x0D' ) );
    CU_ASSERT_TRUE( is_chanstring( '\x0E' ) );
    CU_ASSERT_FALSE( is_chanstring( '\x20' ) );
    CU_ASSERT_TRUE( is_chanstring( '\x21' ) );
    CU_ASSERT_FALSE( is_chanstring( '\x2C' ) );
    CU_ASSERT_TRUE( is_chanstring( '\x2D' ) );
    CU_ASSERT_FALSE( is_chanstring( '\x3A' ) );
    CU_ASSERT_TRUE( is_chanstring( '\x3B' ) );
}

static void test_msg_parse_shortname( void )
{
    static uint8_t * shortname = NULL;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "www";
    static uint8_t * ptr_2 = " www";
    static uint8_t * ptr_3 = ".www";
    static uint8_t * ptr_4 = "ww w";
    static uint8_t * ptr_5 = "ww.w";
    static uint8_t * ptr_6 = "9ww";
    static uint8_t * ptr_7 = "#ww";
    static uint8_t * ptr_8 = "w-ww";
    static uint8_t * ptr_9 = "ww-";
    static uint8_t * ptr_10 = "w#w";
    static uint8_t * ptr_11 = "ww9";
    static uint8_t * ptr_12 = "ww#";

    CU_ASSERT_FALSE( parse_shortname( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_shortname( &shortname, NULL, NULL ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_0, NULL ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_1, NULL ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_TRUE( parse_shortname( &shortname, &ptr_1, &(ptr_1[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( shortname );
    shortname = NULL;

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_shortname( &shortname, &p, &(ptr_1[0]) ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_2, &(ptr_2[4]) ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_3, &(ptr_3[4]) ) );
    CU_ASSERT_PTR_NULL( shortname );
    
    CU_ASSERT_TRUE( parse_shortname( &shortname, &ptr_4, &(ptr_4[4]) ) );
    CU_ASSERT_PTR_NOT_NULL( shortname );
    shortname = NULL;

    CU_ASSERT_TRUE( parse_shortname( &shortname, &ptr_5, &(ptr_5[4]) ) );
    CU_ASSERT_PTR_NOT_NULL( shortname );
    shortname = NULL;

    CU_ASSERT_TRUE( parse_shortname( &shortname, &ptr_6, &(ptr_6[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( shortname );
    shortname = NULL;

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_7, &(ptr_7[3]) ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_TRUE( parse_shortname( &shortname, &ptr_8, &(ptr_8[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( shortname );
    shortname = NULL;

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_9, &(ptr_9[3]) ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_10, &(ptr_10[3]) ) );
    CU_ASSERT_PTR_NULL( shortname );

    CU_ASSERT_TRUE( parse_shortname( &shortname, &ptr_11, &(ptr_11[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( shortname );
    shortname = NULL;

    CU_ASSERT_FALSE( parse_shortname( &shortname, &ptr_12, &(ptr_12[3]) ) );
    CU_ASSERT_PTR_NULL( shortname );
}

static void test_msg_parse_hostname( void )
{
    static uint8_t * hostname = NULL;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "www";
    static uint8_t * ptr_2 = "w.w";
    static uint8_t * ptr_3 = "127.0.0.1";

    CU_ASSERT_FALSE( parse_hostname( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_hostname( &hostname, NULL, NULL ) );
    CU_ASSERT_PTR_NULL( hostname );

    CU_ASSERT_FALSE( parse_hostname( &hostname, &ptr_0, NULL ) );
    CU_ASSERT_PTR_NULL( hostname );

    CU_ASSERT_FALSE( parse_hostname( &hostname, &ptr_1, NULL ) );
    CU_ASSERT_PTR_NULL( hostname );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_hostname( &hostname, &p, &(ptr_1[0]) ) );
    CU_ASSERT_PTR_NULL( hostname );

    CU_ASSERT_TRUE( parse_hostname( &hostname, &ptr_1, &(ptr_1[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( hostname );
    hostname = NULL;

    CU_ASSERT_TRUE( parse_hostname( &hostname, &ptr_2, &(ptr_2[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( hostname );
    hostname = NULL;

    CU_ASSERT_FALSE( parse_hostname( &hostname, &ptr_3, &(ptr_3[9]) ) );
    CU_ASSERT_PTR_NULL( hostname );
}

static void test_msg_parse_servername( void )
{
    static uint8_t * servername = NULL;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "www";
    static uint8_t * ptr_2 = "w.w";

    CU_ASSERT_FALSE( parse_servername( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_servername( &servername, NULL, NULL ) );
    CU_ASSERT_PTR_NULL( servername );

    CU_ASSERT_FALSE( parse_servername( &servername, &ptr_0, NULL ) );
    CU_ASSERT_PTR_NULL( servername );

    CU_ASSERT_FALSE( parse_servername( &servername, &ptr_1, NULL ) );
    CU_ASSERT_PTR_NULL( servername );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_servername( &servername, &p, &(ptr_1[0]) ) );
    CU_ASSERT_PTR_NULL( servername );

    CU_ASSERT_TRUE( parse_servername( &servername, &ptr_1, &(ptr_1[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( servername );
    servername = NULL;

    CU_ASSERT_TRUE( parse_servername( &servername, &ptr_2, &(ptr_2[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( servername );
    servername = NULL;
}

static void test_msg_parse_nickname( void )
{
    static uint8_t * nickname = NULL;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "nik";
    static uint8_t * ptr_2 = "{ik";
    static uint8_t * ptr_3 = "9ik";
    static uint8_t * ptr_4 = "n-k";
    static uint8_t * ptr_5 = "n9k";
    static uint8_t * ptr_6 = "n}k";
    static uint8_t * ptr_7 = "ni-";
    static uint8_t * ptr_8 = "ni~";
    static uint8_t * ptr_9 = "nicktoolong";

    CU_ASSERT_FALSE( parse_nickname( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_nickname( &nickname, NULL, NULL ) );
    CU_ASSERT_PTR_NULL( nickname );

    CU_ASSERT_FALSE( parse_nickname( &nickname, &ptr_0, NULL ) );
    CU_ASSERT_PTR_NULL( nickname );

    CU_ASSERT_FALSE( parse_nickname( &nickname, &ptr_1, NULL ) );
    CU_ASSERT_PTR_NULL( nickname );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_nickname( &nickname, &p, &(ptr_1[0]) ) );
    CU_ASSERT_PTR_NULL( nickname );

    CU_ASSERT_TRUE( parse_nickname( &nickname, &ptr_1, &(ptr_1[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( nickname );
    nickname = NULL;

    CU_ASSERT_TRUE( parse_nickname( &nickname, &ptr_2, &(ptr_2[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( nickname );
    nickname = NULL;

    CU_ASSERT_FALSE( parse_nickname( &nickname, &ptr_3, &(ptr_3[3]) ) );
    CU_ASSERT_PTR_NULL( nickname );

    CU_ASSERT_TRUE( parse_nickname( &nickname, &ptr_4, &(ptr_4[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( nickname );
    nickname = NULL;

    CU_ASSERT_TRUE( parse_nickname( &nickname, &ptr_5, &(ptr_5[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( nickname );
    nickname = NULL;

    CU_ASSERT_TRUE( parse_nickname( &nickname, &ptr_6, &(ptr_6[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( nickname );
    nickname = NULL;

    CU_ASSERT_TRUE( parse_nickname( &nickname, &ptr_7, &(ptr_7[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( nickname );
    nickname = NULL;

    CU_ASSERT_FALSE( parse_nickname( &nickname, &ptr_8, &(ptr_8[3]) ) );
    CU_ASSERT_PTR_NULL( nickname );

    CU_ASSERT_FALSE( parse_nickname( &nickname, &ptr_9, &(ptr_9[12]) ) );
    CU_ASSERT_PTR_NULL( nickname );
}

static void test_msg_parse_user( void )
{
    static uint8_t * user = NULL;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "usr";
    static uint8_t * ptr_2 = "us\n";
    static uint8_t * ptr_3 = "";

    CU_ASSERT_FALSE( parse_user( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_user( &user, NULL, NULL ) );
    CU_ASSERT_PTR_NULL( user );

    CU_ASSERT_FALSE( parse_user( &user, &ptr_0, NULL ) );
    CU_ASSERT_PTR_NULL( user );

    CU_ASSERT_FALSE( parse_user( &user, &ptr_1, NULL ) );
    CU_ASSERT_PTR_NULL( user );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_user( &user, &p, &(ptr_1[0]) ) );
    CU_ASSERT_PTR_NULL( user );

    CU_ASSERT_TRUE( parse_user( &user, &ptr_1, &(ptr_1[3]) ) );
    CU_ASSERT_PTR_NOT_NULL( user );
    user = NULL;

    CU_ASSERT_FALSE( parse_user( &user, &ptr_2, &(ptr_2[3]) ) );
    CU_ASSERT_PTR_NULL( user );

    CU_ASSERT_FALSE( parse_user( &user, &ptr_3, &(ptr_3[0]) ) );
    CU_ASSERT_PTR_NULL( user );
}

static void test_msg_parse_hostaddr( void )
{
    static irc_msg_h_t host;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "::1";
    static uint8_t * ptr_2 = "127.0.0.1";
    static uint8_t * ptr_3 = "foo";

    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    /* test the pre-conditions */
    CU_ASSERT_FALSE( parse_hostaddr( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_hostaddr( &host, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_hostaddr( &host, &ptr_0, NULL ) );

    CU_ASSERT_FALSE( parse_hostaddr( &host, &ptr_1, NULL ) );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_hostaddr( &host, &p, &(ptr_1[0]) ) );

    CU_ASSERT_TRUE( parse_hostaddr( &host, &ptr_1, &(ptr_1[3] ) ) );
    CU_ASSERT_EQUAL( host.kind, V6_HOSTADDR );
    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    CU_ASSERT_TRUE( parse_hostaddr( &host, &ptr_2, &(ptr_2[10] ) ) );
    CU_ASSERT_EQUAL( host.kind, V4_HOSTADDR );
    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    CU_ASSERT_FALSE( parse_hostaddr( &host, &ptr_3, &(ptr_3[3] ) ) );
}

static void test_msg_parse_host( void )
{
    static irc_msg_h_t host;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "::1";
    static uint8_t * ptr_2 = "127.0.0.1";
    static uint8_t * ptr_3 = "foo";
    static uint8_t * ptr_4 = "~";

    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    /* test the pre-conditions */
    CU_ASSERT_FALSE( parse_host( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_host( &host, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_host( &host, &ptr_0, NULL ) );

    CU_ASSERT_FALSE( parse_host( &host, &ptr_1, NULL ) );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_host( &host, &p, &(ptr_1[0]) ) );

    CU_ASSERT_TRUE( parse_host( &host, &ptr_1, &(ptr_1[3] ) ) );
    CU_ASSERT_EQUAL( host.kind, V6_HOSTADDR );
    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    CU_ASSERT_TRUE( parse_host( &host, &ptr_2, &(ptr_2[10] ) ) );
    CU_ASSERT_EQUAL( host.kind, V4_HOSTADDR );
    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    CU_ASSERT_TRUE( parse_host( &host, &ptr_3, &(ptr_3[3] ) ) );
    CU_ASSERT_EQUAL( host.kind, HOSTNAME );
    MEMSET( &host, 0, sizeof( irc_msg_h_t ) );

    CU_ASSERT_FALSE( parse_host( &host, &ptr_4, &(ptr_4[3]) ) );
}

#define NUM_MSG_PARSE_NUH_CASES (14)
static void test_msg_parse_nuh( void )
{
    static irc_msg_nuh_t nuh;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "nick";

    static int_t i, j;
    static uint8_t buf[32];
    static uint8_t const * const nuhs[NUM_MSG_PARSE_NUH_CASES] =
    {
        "nick!user@host  ",
        "nick",
        "9ick",
        "nick@",
        "nick@::1",
        "nick@127.0.0.1",
        "nick@www.com",
        "nick!user@::1",
        "nick!user@127.0.0.1",
        "nick!user@www.com",
        "nick!user",
        "nick!use\n",
        "nick!use\n@",
        "nick ",
    };
    static size_t sizes[NUM_MSG_PARSE_NUH_CASES] = 
    { 
        17,
        5, 
        5,
        6,
        9, 
        15, 
        13, 
        14, 
        20, 
        18, 
        10, 
        10,
        11,
        6
    };
    static int_t expected[NUM_MSG_PARSE_NUH_CASES] = 
    { 
        FALSE,
        TRUE, 
        FALSE, 
        FALSE,
        TRUE, 
        TRUE, 
        TRUE, 
        TRUE, 
        TRUE, 
        TRUE, 
        FALSE, 
        FALSE,
        FALSE,
        FALSE
    };

    MEMSET( &nuh, 0, sizeof( irc_msg_h_t ) );

    /* test the pre-conditions */
    CU_ASSERT_FALSE( parse_nuh( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_nuh( &nuh, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_nuh( &nuh, &ptr_0, NULL ) );

    CU_ASSERT_FALSE( parse_nuh( &nuh, &ptr_1, NULL ) );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_nuh( &nuh, &p, &(ptr_1[0]) ) );

    for ( i = 0; i < NUM_MSG_PARSE_NUH_CASES; ++i )
    {
        MEMSET( &nuh, 0, sizeof( irc_msg_h_t ) );
        MEMSET( buf, 0, 32 );
        MEMCPY( buf, nuhs[i], sizes[i] );
        p = &(buf[0]);
        j = parse_nuh( &nuh, &p, &(p[sizes[i] - 1]) );
        CU_ASSERT_EQUAL( j, expected[i] );
    }
}

#define NUM_MSG_PARSE_PREFIX_CASES (19)
static void test_msg_parse_prefix( void )
{
    static irc_msg_prefix_t pfx;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "nick";

    static int_t i, j;
    static ssize_t k;
    static uint8_t buf[32], actual[IRC_MSG_SIZE];
    static uint8_t const * const pfxs[NUM_MSG_PARSE_PREFIX_CASES] =
    {
        "::1 ",
        "127.0.0.1 ",
        "www.com ",
        "blah ",
        "blah",
        "nick!user@host  ", /* extra spaces shouldn't cause prefix parse to fail */
        "nick ",
        "9ick ", /* in prefix conext, valid servername */
        "nick@ ",
        "nick@::1 ",
        "nick@127.0.0.1 ",
        "nick@www.com ",
        "nick!user@::1 ",
        "nick!user@127.0.0.1 ",
        "nick!user@www.com ",
        "nick!user ",
        "nick!use\n ",
        "nick!use\n@ ",
        "nick ",
    };
    static size_t sizes[NUM_MSG_PARSE_PREFIX_CASES] = 
    { 
        5,
        11,
        9,
        6,
        5,
        17,
        6, 
        6,
        7,
        10, 
        16, 
        14, 
        15, 
        21, 
        19, 
        11, 
        11,
        12,
        7
    };
    static int_t expected[NUM_MSG_PARSE_PREFIX_CASES] = 
    { 
        FALSE,
        FALSE,
        TRUE,
        TRUE,
        IRC_BAD_MESSAGE,
        TRUE,
        TRUE, 
        TRUE, 
        FALSE,
        TRUE, 
        TRUE, 
        TRUE, 
        TRUE, 
        TRUE, 
        TRUE, 
        FALSE, 
        FALSE,
        FALSE,
        TRUE
    };

    MEMSET( &pfx, 0, sizeof( irc_msg_prefix_t ) );

    /* test the pre-conditions */
    CU_ASSERT_FALSE( parse_prefix( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_prefix( &pfx, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_prefix( &pfx, &ptr_0, NULL ) );

    CU_ASSERT_FALSE( parse_prefix( &pfx, &ptr_1, NULL ) );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_prefix( &pfx, &p, &(ptr_1[0]) ) );

    for ( i = 0; i < NUM_MSG_PARSE_PREFIX_CASES; ++i )
    {
        MEMSET( actual, 0, IRC_MSG_SIZE );
        MEMSET( &pfx, 0, sizeof( irc_msg_prefix_t ) );
        MEMSET( buf, 0, 32 );
        MEMCPY( buf, pfxs[i], sizes[i] );
        p = &(buf[0]);
        j = parse_prefix( &pfx, &p, &(p[sizes[i] - 1]) );
        CU_ASSERT_EQUAL( j, expected[i] );
        if ( expected[i] == TRUE )
        {
            k = irc_msg_prefix_r( &pfx, actual, IRC_MSG_SIZE );
            CU_ASSERT_TRUE( k >= 0 );
            CU_ASSERT_TRUE( strncmp( actual, pfxs[i], strlen(actual) ) == 0 );
        }
    }
}

#define NUM_MSG_PARSE_CMD_CASES (4)
static void test_msg_parse_cmd( void )
{
    static irc_command_t cmd;;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = "PING ";

    static int_t i, j;
    static uint8_t buf[32];
    static uint8_t const * const cmds[NUM_MSG_PARSE_CMD_CASES] =
    {
        "PING",
        "|ING",
        "200",
        "FOO"
    };
    static size_t sizes[NUM_MSG_PARSE_CMD_CASES] = 
    { 
        5,
        5,
        4,
        4
    };
    static int_t expected[NUM_MSG_PARSE_CMD_CASES] = 
    { 
        TRUE,
        FALSE,
        TRUE,
        FALSE
    };

    cmd = NOCMD;

    /* test the pre-conditions */
    CU_ASSERT_FALSE( parse_command( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_command( &cmd, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_command( &cmd, &ptr_0, NULL ) );

    CU_ASSERT_FALSE( parse_command( &cmd, &ptr_1, NULL ) );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_command( &cmd, &p, &(ptr_1[0]) ) );

    for ( i = 0; i < NUM_MSG_PARSE_CMD_CASES; ++i )
    {
        cmd = NOCMD;
        MEMSET( buf, 0, 32 );
        MEMCPY( buf, cmds[i], sizes[i] );
        p = &(buf[0]);
        j = parse_command( &cmd, &p, &(p[sizes[i] - 1]) );
        CU_ASSERT_EQUAL( j, expected[i] );
    }
}

#define NUM_MSG_PARSE_PARAMS_CASES (10)
static void test_msg_parse_params( void )
{
    static list_t params;
    static uint8_t * p = NULL;
    static uint8_t * ptr_0 = NULL;
    static uint8_t * ptr_1 = " blah";

    static int_t i, j;
    static uint8_t buf[32];
    static uint8_t const * const pms[NUM_MSG_PARSE_PARAMS_CASES] =
    {
        " hello",
        " hello world",
        " :hello world",
        " 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20",
        "bad",
        " b" "\x0a" "d",
        " \x0a" "ad",
        " fun:ky",
        " 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 :0",
        " 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 " "\x0a" "0"
    };
    static size_t sizes[NUM_MSG_PARSE_PARAMS_CASES] = 
    { 
        7,
        13,
        14,
        54,
        4,
        5,
        5,
        8,
        54,
        54
    };
    static int_t expected[NUM_MSG_PARSE_PARAMS_CASES] = 
    { 
        TRUE,
        TRUE,
        TRUE,
        TRUE,
        FALSE,
        FALSE,
        FALSE,
        TRUE,
        TRUE,
        FALSE
    };

    list_initialize( &params, IRC_NUM_PARAMS, NULL );

    /* test the pre-conditions */
    CU_ASSERT_FALSE( parse_params( NULL, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_params( &params, NULL, NULL ) );

    CU_ASSERT_FALSE( parse_params( &params, &ptr_0, NULL ) );

    CU_ASSERT_FALSE( parse_params( &params, &ptr_1, NULL ) );

    p = &(ptr_1[1]);
    CU_ASSERT_FALSE( parse_params( &params, &p, &(ptr_1[0]) ) );

    for ( i = 0; i < NUM_MSG_PARSE_PARAMS_CASES; ++i )
    {
        list_deinitialize( &params );
        list_initialize( &params, IRC_NUM_PARAMS, NULL );
        MEMSET( buf, 0, 32 );
        MEMCPY( buf, pms[i], sizes[i] );
        p = &(buf[0]);
        j = parse_params( &params, &p, &(p[sizes[i] - 1]) );
        CU_ASSERT_EQUAL( j, expected[i] );
    }
}

#define NUM_STATIC_STR (5)
void test_dyn_str_list( void )
{
    int_t i;
    list_t t;
    irc_str_ref_t *sref = NULL;
    static uint8_t const * const strs[NUM_STATIC_STR] = 
    {
        "blah1",
        "blah2",
        "blah3",
        "blah4",
        "blah5"
    };

    list_initialize( &t, 0, &param_delete_fn );

    for ( i = 0; i < NUM_STATIC_STR; i++ )
    {
        sref = CALLOC( 1, sizeof(irc_str_ref_t) );
        STR_PTR_P_SET( sref, (uint8_t*)strs[i] );
        STR_LEN_P_SET( sref, strlen( strs[i] ) );
        list_push_tail( &t, (void*)sref );
    }

    CU_ASSERT_EQUAL( NUM_STATIC_STR, list_count( &t ) );
    list_deinitialize( &t );
    CU_ASSERT_EQUAL( 0, list_count( &t ) );

    list_initialize( &t, 0, &param_delete_fn );

    for ( i = 0; i < NUM_STATIC_STR; i++ )
    {
        sref = CALLOC( 1, sizeof(irc_str_ref_t) );
        STR_PTR_P_SET( sref, strdup(strs[i]) );
        STR_LEN_P_SET( sref, strlen( strs[i] ) );
        sref->dyn = TRUE;
        list_push_tail( &t, (void*)sref );
    }

    CU_ASSERT_EQUAL( NUM_STATIC_STR, list_count( &t ) );
    list_deinitialize( &t );
    CU_ASSERT_EQUAL( 0, list_count( &t ) );
}

void test_msg_private_functions( void )
{
    test_msg_is_letter();
    test_msg_is_digit();
    test_msg_is_hex();
    test_msg_is_special();
    test_msg_is_user_octet();
    test_msg_is_key_octet();
    test_msg_is_nospcrlfcl_octet();
    test_msg_is_chanstart();
    test_msg_is_chanstring();

    test_msg_parse_shortname();
    test_msg_parse_hostname();
    test_msg_parse_servername();
    test_msg_parse_nickname();
    test_msg_parse_user();
    test_msg_parse_hostaddr();
    test_msg_parse_host();
    test_msg_parse_nuh();
    test_msg_parse_prefix();
    test_msg_parse_cmd();
    test_msg_parse_params();

    test_dyn_str_list();
}

#endif

