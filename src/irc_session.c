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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#define DEBUG_ON

#include <cutil/debug.h>
#include <cutil/macros.h>
#include <cutil/events.h>
#include <cutil/btree.h>

#include "irc_commands.h"
#include "irc_event.h"
#include "irc_msg.h"
#include "irc_conn.h"
#include "irc_session.h"

/* these are the session specific event handlers */

/* this gets called when we receive a PING message from the server */
static irc_ret_t session_ping_handler( irc_session_t * const session,
									   irc_msg_t * const msg,
									   void * user_data )
{
	int8_t const * dest;
	irc_msg_t * pong = NULL;

	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	CHECK_RET( (msg->cmd == PING), IRC_BADPARAM );

	/* get a pointer to the last part of the PING message */
	dest = (msg->trailing != NULL) ? msg->trailing : msg->parameters[msg->num_params-1];
	DEBUG("received PING from %s\n", dest);

	/* send PONG */
	pong = irc_msg_new();
	irc_msg_initialize( pong, PONG, NULL, 1, dest );

	/* send the PONG command */
	irc_conn_send_msg( &(session->conn), pong );

	return IRC_DONE;
}

/* this gets called when we receive an ERR_NEEDMOREPARAMS error from the server */
static irc_ret_t session_err_needmoreparams_handler( irc_session_t * const session,
													 irc_msg_t * const msg,
													 void * user_data )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	CHECK_RET( (msg->cmd == ERR_NEEDMOREPARAMS), IRC_BADPARAM );

	/* this is a valid response to the following commands:
	 *	PASS
	 *	USER
	 *	OPER
	 *	USER
	 *	SERVICE
	 *	SQUIT
	 *	JOIN
	 *	PART
	 *	MODE
	 *	TOPIC
	 *	INVITE
	 *	KICK
	 *	CONNECT
	 *	KILL
	 *	WALLOPS
	 *	USERHOST
	 *	ISON
	 */
	
	WARN( "received %s for command: %s (%s)\n", 
		  irc_cmd_get_string( msg->cmd ), 
		  msg->parameters[msg->num_params-1], 
		  msg->trailing );

	/* chain to the next handler */
	return IRC_OK;
}

/* this gets called when we receive an ERR_ALREADYREGISTERED error from the server */
static irc_ret_t session_err_alreadyregistered_handler( irc_session_t * const session,
														irc_msg_t * const msg,
														void * user_data )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	CHECK_RET( (msg->cmd == ERR_ALREADYREGISTERED), IRC_BADPARAM );

	/* this is a valid response to the following commands:
	 *	PASS
	 *	USER
	 *	SERVICE
	 */

	WARN( "received %s (%s)\n", irc_cmd_get_string( msg->cmd ), msg->trailing );

	/* chain to the next handler */
	return IRC_OK;
}

/* this gets called when we receive an ERR_UNAVAILRESOURCE error from the server */
static irc_ret_t session_err_unavailresource_handler( irc_session_t * const session,
													  irc_msg_t * const msg,
													  void * user_data )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	CHECK_RET( (msg->cmd == ERR_ALREADYREGISTERED), IRC_BADPARAM );

	/* this is a valid response to the following commands:
	 *	NICK
	 *	JOIN
	 */

	WARN( "received %s %s (%s)\n", 
		  irc_cmd_get_string( msg->cmd ), 
		  msg->parameters[msg->num_params-1], 
		  msg->trailing );

	/* chain to the next handler */
	return IRC_OK;
}

/* this gets called when we receive an ERR_UNAVAILRESOURCE error from the server */
static irc_ret_t session_nick_error_handler( irc_session_t * const session,
											 irc_msg_t * const msg,
											 void * user_data )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );

	/* these are all of the NICK errors other than ERR_UNAVAILRESOURCE */

	/* chain to the next handler */
	return IRC_OK;
}



























#define FNV_PRIME (0x01000193)
static uint32_t fnv_key_hash(void const * const key)
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

static int int_less( void * l, void * r )
{
	int li = (int)l;
	int ri = (int)r;

	if ( li < ri )
		return -1;
	else if ( li > ri )
		return 1;
	return 0;
}

static int string_eq(void const * const l, void const * const r)
{
	return (strcmp( l, r ) == 0);
}

static irc_ret_t irc_session_call_handler( irc_session_t * const session, 
										   irc_msg_t * const msg,
										   irc_command_t const cmd )
{
	bt_itr_t itr;
	event_handler_fn handler_fn = NULL;
	bt_t * handler_list = NULL;
	
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );

	handler_list = ht_find_prehash ( session->handlers, 
									 irc_event_get_has_from_cmd ( cmd ),
									 (void*)irc_event_get_name_from_cmd( cmd ) );
	CHECK_PTR_RET_MSG( handler_list, IRC_ERR, 
					   "no handler registered for %s", irc_cmd_get_string( cmd ) );

	/* iterator through the list of handlers calling them until we either run out of
	 * handlers or one of the handlers returns IRC_DONE. */
	itr = bt_itr_begin( handler_list );
	for ( ; itr != bt_itr_end( handler_list ); itr = bt_itr_next( handler_list, itr ) )
	{
		handler_fn = (event_handler_fn)bt_itr_get( handler_list, itr );

		if ( handler_fn == NULL )
		{
			WARN("NULL handler fn pointer!\n");
			continue;
		}

		if ( (*handler_fn)( session, msg, session->user_data ) == IRC_DONE )
			break;
	}

	return IRC_OK;
}

static void send_pass( irc_session_t * const session )
{
	irc_msg_t * pass = NULL;
	int8_t * server_pass = NULL;
	CHECK_PTR( session );

	server_pass = irc_session_get_prehash( session, SERVER_PASS_HASH, SERVER_PASS_KEY );

	/* send the PASS command */
	pass = irc_msg_new();
	irc_msg_initialize( pass, PASS, NULL, 1, server_pass );

	/* send the PASS command */
	irc_conn_send_msg( &(session->conn), pass );
}

static void send_nick( irc_session_t * const session )
{
	irc_msg_t * nick = NULL;
	int8_t * nick_name = NULL;
	CHECK_PTR( session );

	nick_name = irc_session_get_prehash( session, NICK_NAME_HASH, NICK_NAME_KEY );

	/* send the NICK command */
	nick = irc_msg_new();
	irc_msg_initialize( nick, NICK, NULL, 1, nick_name );

	/* send the NICk command */
	irc_conn_send_msg( &(session->conn), nick );
}

static void send_user( irc_session_t * const session )
{
	irc_msg_t * user = NULL;
	int8_t * user_name = NULL;
	CHECK_PTR( session );

	user_name = irc_session_get_prehash( session, USER_NAME_HASH, USER_NAME_KEY);

	/* send the USER command */
	user = irc_msg_new();
	irc_msg_initialize( user, USER, NULL, 3, user_name, "0", "*" );
	irc_msg_set_trailing( user, user_name );

	/* send the USER command */
	irc_conn_send_msg( &(session->conn), user );
}

static void send_quit( irc_session_t * const session )
{
	irc_msg_t * quit = NULL;
	int8_t * quit_msg = NULL;
	CHECK_PTR( session );

	quit_msg = irc_session_get_prehash( session, QUIT_MSG_HASH, QUIT_MSG_KEY );

	/* send QUIT */
	quit = irc_msg_new();
	irc_msg_initialize( quit, QUIT, NULL, 0 );
	irc_msg_set_trailing( quit, quit_msg );

	/* send the QUIT command */
	irc_conn_send_msg( &(session->conn), quit );
}

void check_umodes( int8_t const * const modes )
{
	int i;
	for ( i = 0; i < IRC_UMODE_COUNT; ++i )
	{
		if ( modes[i] == '\0' )
			break;
		if ( !IS_UMODE( modes[i] ) )
			WARN( "unknown user mode: %c\n", modes[i] );
	}
}

void check_cmodes( int8_t const * const modes )
{
	int i;
	for ( i = 0; i < IRC_CMODE_COUNT; ++i )
	{
		if ( modes[i] == '\0' )
			break;
		if ( !IS_CMODE( modes[i] ) )
			WARN( "unknown channel mode: %c\n", modes[i] );
	}
}

void check_smodes( int8_t const * const modes )
{
	int i;
	for ( i = 0; i < IRC_SMODE_COUNT; ++i )
	{
		if ( modes[i] == '\0' )
			break;
		if ( !IS_SMODE( modes[i] ) )
			WARN( "unknown server mode: %c\n", modes[i] );
	}
}

static void parse_client_server_reply( irc_session_t * const session,
									   irc_msg_t * const msg )
{
	CHECK_PTR( session );
	CHECK_PTR( msg );

	switch( msg->cmd )
	{
		case RPL_WELCOME:
			DEBUG( "%s\n", msg->trailing );
			break;
		case RPL_YOURHOST:
			
			break;
		case RPL_CREATED:
			break;
		case RPL_MYINFO:
			switch( msg->num_params )
			{
				case 9: /* KineIRCd */

					/* server modes that take a parameter */
					irc_session_set_prehash( session, 
											 SERVER_MODES_PARAM_HASH,
											 SERVER_MODES_PARAM_KEY,
											 strdup( msg->parameters[8] ) );
					check_smodes( msg->parameters[8] );

					/* server modes */
					irc_session_set_prehash( session, 
											 SERVER_MODES_HASH,
											 SERVER_MODES_KEY,
											 strdup( msg->parameters[7] ) );
					check_smodes( msg->parameters[7] );

					/* user modes that take a parameter */
					irc_session_set_prehash( session, 
											 USER_MODES_PARAM_HASH,
											 USER_MODES_PARAM_KEY,
											 strdup( msg->parameters[6] ) );
					check_umodes( msg->parameters[6] );

				case 6: /* ircd */

					/* parse the cmodes with a parameter */
					irc_session_set_prehash( session, 
											 CHANNEL_MODES_PARAM_HASH,
											 CHANNEL_MODES_PARAM_KEY,
											 strdup( msg->parameters[5] ) );
					check_cmodes( msg->parameters[5] );


				case 5: /* RFC2812 */

					/* channel modes */
					irc_session_set_prehash( session, 
											 CHANNEL_MODES_HASH,
											 CHANNEL_MODES_KEY,
											 strdup( msg->parameters[4] ) );
					check_cmodes( msg->parameters[4] );

					/* user modes */
					irc_session_set_prehash( session, 
											 USER_MODES_HASH,
											 USER_MODES_KEY,
											 strdup( msg->parameters[3] ) );
					check_umodes( msg->parameters[3] );

					/* store version */
					irc_session_set_prehash( session,
											 SERVER_VERSION_HASH,
											 SERVER_VERSION_KEY,
											 strdup( msg->parameters[2] ) );
			}
			break;

		case RPL_BOUNCE:	/* also RPL_ISUPPORT */
			/* if it is a bound message, the trailing string will be like:
			 *
			 * 'Try server <server name>, port <port number>'
			 *
			 * we need to parse the server and port, then kick off bounce
			 * state machine. */
			break;

		case RPL_MAP:
			break;
		case RPL_MAPEND:
			break;
		case RPL_SNOMASK:
			break;
		case RPL_STATMENTOT:
			break;

		case RPL_BOUNCE_2:	/* also RPL_STATMEM */
			break;
		
		case RPL_YOURCOOKIE:
			break;
		case RPL_MAP_2:
			break;
		case RPL_MAPMORE:
			break;
		case RPL_MAPEND_2:
			break;
		
		case RPL_YOURID:
			break;
		case RPL_SAVENICK:
			break;
		
		case RPL_ATTEMPTINGJUNC:
			break;
		case RPL_ATTEMPTINGREROUTE:
			break;
	}
}

static irc_ret_t irc_conn_message_in( irc_conn_t * const conn, 
									  irc_msg_t * const msg, 
									  void * user_data  )
{
	int8_t const * dest;
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	/* execute the connection registration state machine */
	switch ( session->state )
	{
		case IRC_SESSION_CONNECTED:
			/* do nothing */
			break;
		case IRC_SESSION_PASS:
			session->state = IRC_SESSION_NICK;
			send_nick( session );
			break;
		case IRC_SESSION_NICK:
			session->state = IRC_SESSION_USER;
			send_user( session );
			break;
		case IRC_SESSION_USER:
			session->state = IRC_SESSION_ACTIVE;
			/* TODO: on_connect callback */
			break;
		case IRC_SESSION_ACTIVE:
			/* do nothing */
			break;
		case IRC_SESSION_QUIT:
			irc_conn_disconnect( &(session->conn), TRUE );
			break;
		case IRC_SESSION_PENDING_DISCONNECT:
			/* do nothing */
			break;
	}

	/* parse 001-099 replies */
	if ( (msg->cmd >= RPL_WELCOME) && (msg->cmd <= 99) )
	{
		parse_client_server_reply( session, msg );
	}
	
	/* TODO: make handler callbacks by looking up the event by name and iterating
	 * over the handler function pointers calling them until we run out of handlers
	 * or one returns IRC_DONE */
	WARN("unknown incoming message!\n");

	return IRC_OK;
}

static irc_ret_t irc_conn_message_out( irc_conn_t * const conn,
									   irc_msg_t * const msg,
									   void * user_data )
{
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	if ( session->state == IRC_SESSION_QUIT )
	{
		/* our QUIT command has been sent, now we're pending disconnect */
		session->state = IRC_SESSION_PENDING_DISCONNECT;
	}

	/* free the message */
	irc_msg_delete( msg );

	return IRC_OK;
}

static irc_ret_t irc_conn_connected( irc_conn_t * const conn, 
									 void * user_data )
{
	irc_session_t * session = (irc_session_t*)user_data;
	int8_t * password = NULL;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	/* should only receive these when disconnected */
	ASSERT( session->state == IRC_SESSION_DISCONNECTED );

	/* we have a connection to the server, now we must register it */
	session->state = IRC_SESSION_CONNECTED;

	/* kick off the IRC connection registration */
	password = irc_session_get_prehash( session, SERVER_PASS_HASH, SERVER_PASS_KEY );
	if ( password != NULL )
	{
		/* set state before sending the command */
		session->state = IRC_SESSION_PASS;

		/* send the PASS command */
		send_pass( session );
	}
	else
	{
		/* set state before sending the command */
		session->state = IRC_SESSION_NICK;

		/* send the NICK command */
		send_nick( session );
	}

	return IRC_OK;
}

static irc_ret_t irc_conn_disconnected( irc_conn_t * const conn, 
										void * user_data )
{
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	if ( session->state != IRC_SESSION_PENDING_DISCONNECT )
	{
		WARN("got disconnected unexpectedly\n");
	}

	session->state = IRC_SESSION_DISCONNECTED;

	DEBUG("session has been taken down completely\n");

	/* call "disconnected" handler */
	irc_session_call_handler( session, NULL, SESSION_DISCONNECTED );

	return IRC_OK;
}

void irc_session_initialize( irc_session_t * const session,
							 evt_loop_t * const el,
							 void * user_data )
{
	int i, j;
	bt_t * bt = NULL;
	event_name_t const * event_list;

	static irc_conn_ops_t conn_ops = 
	{
		&irc_conn_message_in,
		&irc_conn_message_out,
		&irc_conn_connected,
		&irc_conn_disconnected
	};

	static event_name_t const * const event_lists[] =
	{
		irc_reply_events_000,
		irc_reply_events_200,
		irc_reply_events_300,
		irc_error_events_400,
		irc_error_events_500,
		irc_command_events,
		irc_session_events
	};

	/* zero everything out */
	MEMSET( (void*)session, 0, sizeof( irc_session_t ) );

	/* store the session state */
	session->state = IRC_SESSION_DISCONNECTED;

	/* store the event loop handle */
	session->el = el;

	/* create the irc connection */
	irc_conn_initialize( &(session->conn), &conn_ops, el, (void*)session );

	/* create the settings hashtable */
	session->settings = ht_new( 64, &fnv_key_hash, FREE, &string_eq, NULL );

	/* create the handlers hashtable */
	session->handlers = ht_new( 8, &fnv_key_hash, &bt_delete, &string_eq, NULL );

	/* store the handler context */
	session->user_data = user_data;

	/* now set up all of the handler chains for all of the different events */
	for ( i = 0; i < ARRAY_SIZE( event_lists ); ++i )
	{
		event_list = event_lists[i];

		for ( j = 0; j < ARRAY_SIZE( event_list ); ++j )
		{
			if ( event_list[j].name == NULL )
				continue;

			/* create a new btree to store the handlers in priority order */
			bt = bt_new( 1, int_less, NULL, NULL );

			/* add the btree tot he handlers hashtable under the event name */
			hg_add_prehash( session->handlers, 
							event_list[j].hash, 
							(void*)event_list[j].name,
							(void*)bt );

			DEBUG( "added handler list for: %s\n", event_list[j].name );
		}
	}

	/* now set the PING handler */
	irc_session_set_handler( session, T("ping"), 
							 &session_ping_handler, SESSION_HANDLER_PRIORITY );
	irc_session_set_handler( session, T("needmoreparams"), 
						     &session_err_needmoreparams_handler, 
							 SESSION_HANDLER_LAST_PRIORITY );
	irc_session_set_handler( session, T("alreadyregistered"), 
							 &session_err_alreadyregistered_handler, 
							 SESSION_HANDLER_LAST_PRIORITY );
	irc_session_set_handler( session, T("unavailresource"), 
							 &session_err_unavailresource_handler, 
							 SESSION_HANDLER_LAST_PRIORITY );
}


irc_session_t * irc_session_new( evt_loop_t * const el,
								 void * user_data )
{
	irc_session_t * session = NULL;

	CHECK_PTR_RET( el, NULL );

	/* allocate the session struct */
	session = MALLOC( sizeof(irc_session_t) );
	CHECK_PTR_RET_MSG( session, NULL, "failed to allocate session struct\n" );

	irc_session_initialize( session, el, user_data );

	return session;
}


void irc_session_deinitialize( irc_session_t * const session )
{
	CHECK_PTR( session );
	CHECK_MSG( session->state == IRC_SESSION_DISCONNECTED, "deinitializing active session\n" );

	DEBUG("deinitializing session\n");

	/* must be disconnected to deinitialize everything */
	irc_conn_deinitialize( &(session->conn) );

	/* clean up hash tables */
	ht_delete( session->settings );
	hg_delete( session->handlers );

	/* drop pointer to context */
	session->user_data = NULL;
}


void irc_session_delete( void * s )
{
	irc_session_t * session = (irc_session_t*)s;
	CHECK_PTR( session );
	CHECK_MSG( session->state == IRC_SESSION_DISCONNECTED, "deleting active session\n" );

	/* deinit the session, don't sent the QUIT */
	irc_session_deinitialize( session );

	FREE( session );
}

irc_ret_t irc_session_set( irc_session_t * const session,
						   int8_t * const key,
						   void * const value )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( key, IRC_BADPARAM );
	CHECK_PTR_RET( value, IRC_BADPARAM );

	ht_remove( session->settings, key );
	ht_add( session->settings, key, value );
	return IRC_OK;
}

irc_ret_t irc_session_set_prehash( irc_session_t * const session,
								   uint32_t const hash,
								   int8_t * const key,
								   void * const value )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( key, IRC_BADPARAM );
	CHECK_PTR_RET( value, IRC_BADPARAM );

	ht_remove_prehash( session->settings, hash, key );
	ht_add_prehash( session->settings, hash, key, value );
	return IRC_OK;
}
								   

void * irc_session_get( irc_session_t * const session,
					    int8_t const * const key )
{
	CHECK_PTR_RET( session, NULL );
	CHECK_PTR_RET( key, NULL );

	return ht_find( session->settings, key );
}

void * irc_session_get_prehash( irc_session_t * const session,
						  	    uint32_t const hash,
								int8_t const * const key )
{
	CHECK_PTR_RET( session, NULL );
	CHECK_PTR_RET( key, NULL );

	return ht_find_prehash( session->settings, hash, key );
}


irc_ret_t irc_session_set_handler( irc_session_t * const session,
								   int8_t * const event_name,
								   event_handler_fn event_handler,
								   int const priority )
{
	bt_t * handler_list = NULL;

	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );
	CHECK_PTR_RET( event_name, IRC_BADPARAM );
	CHECK_PTR_RET( event_handler, IRC_BADPARAM );

	/* look up the btree associated with the specified event name */
	handler_list = (bt_t*)ht_find( session->handlers, (void*)event_name );
	CHECK_PTR_RET( handler_list, IRC_BADPARAM );

	/* add the new handler pointer at the specified priority */
	bt_add( handler_list, (void*)priority, (void*)event_handler );
}

irc_ret_t irc_session_connect( irc_session_t * const session )
{
	int8_t * host;
	uint16_t port;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	host = (int8_t*)irc_session_get_prehash( session, SERVER_HOST_HASH, SERVER_HOST_KEY );
	port = *((uint16_t*)irc_session_get_prehash( session, SERVER_PORT_HASH, SERVER_PORT_KEY ));

	/* try to initiate an irc connection */
	DEBUG( "attempting connection to: %s:%d\n", host, port );
	if ( irc_conn_connect( &(session->conn), host, port ) != IRC_OK )
	{
		WARN(" failed to create session connection\n" );
		return IRC_ERR;
	}

	return IRC_OK;
}

irc_ret_t irc_session_disconnect( irc_session_t * const session, int do_quit )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );

	if ( session->state >= IRC_SESSION_CONNECTED )
	{
		if ( do_quit && ( session->state == IRC_SESSION_ACTIVE ) )
		{
			DEBUG("sending QUIT to kick off orderly disconnect\n");

			/* set out state before sending the command */
			session->state = IRC_SESSION_QUIT;
			send_quit( session );

			/* disconnect, wait for all messages to be transmitted */
			irc_conn_disconnect( &(session->conn), TRUE );

			return IRC_OK;
		}
	}
	
	DEBUG("don't have registered connection so tear down immediately\n");

	/* move to pending disconnect state */
	session->state = IRC_SESSION_PENDING_DISCONNECT;

	/* disconnect, DON'T wait for all messages to be transmitted */
	irc_conn_disconnect( &(session->conn), FALSE );

	return IRC_OK;
}

