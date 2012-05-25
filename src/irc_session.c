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
#include "irc_msg.h"
#include "irc_conn.h"
#include "irc_session.h"

/* handles calling the handlers associated with the cmd */
static irc_ret_t irc_session_call_handler( irc_session_t * const session, 
										   irc_msg_t * const msg,
										   irc_command_t const cmd )
{
	bt_itr_t itr;
	event_handler_fn handler_fn = NULL;
	bt_t * handler_list = NULL;
	
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );

	handler_list = ht_find( session->handlers, (void*)cmd );
	CHECK_PTR_RET( handler_list, IRC_ERR );

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

		DEBUG( "Calling handler for %s\n", irc_cmd_get_string( cmd ) );
		if ( (*handler_fn)( session, msg, session->user_data ) == IRC_DONE )
			break;
	}

	return IRC_OK;
}


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

/* this gets called when we receive a RPL_WELCOME message from the server */
static irc_ret_t session_rpl_welcome_handler( irc_session_t * const session,
									   irc_msg_t * const msg,
									   void * user_data )
{
	int8_t const * dest;
	irc_msg_t * pong = NULL;

	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	CHECK_RET( (msg->cmd == RPL_WELCOME), IRC_BADPARAM );

	/* get a pointer to the last part of the PING message */
	dest = (msg->trailing != NULL) ? msg->trailing : msg->parameters[msg->num_params-1];
	DEBUG("received RPL_WELCOME from %s\n", dest);

	/* we have a registered connection to the server, we're now active */
	session->state = IRC_SESSION_ACTIVE;

	/* call the irc session connected event callback */
	irc_session_call_handler( session, NULL, SESSION_CONNECTED );
	
	return IRC_DONE;
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


/* this gets called when we receive a RPL_MYINFO message from the server */
static irc_ret_t session_rpl_myinfo_handler( irc_session_t * const session,
										 irc_msg_t * const msg,
										 void * user_data )
{
	int8_t const * dest;
	irc_msg_t * pong = NULL;

	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );
	CHECK_RET( (msg->cmd == RPL_MYINFO), IRC_BADPARAM );

	switch( msg->num_params )
	{
		case 9: /* KineIRCd */

			/* server modes that take a parameter */
			irc_session_set( session, 
							 SERVER_MODES_PARAM,
							 strdup( msg->parameters[8] ) );
			check_smodes( msg->parameters[8] );

			/* server modes */
			irc_session_set( session, 
							 SERVER_MODES,
							 strdup( msg->parameters[7] ) );
			check_smodes( msg->parameters[7] );

			/* user modes that take a parameter */
			irc_session_set( session, 
							 USER_MODES_PARAM,
							 strdup( msg->parameters[6] ) );
			check_umodes( msg->parameters[6] );

		case 6: /* ircd */

			/* parse the cmodes with a parameter */
			irc_session_set( session, 
							 CHANNEL_MODES_PARAM,
							 strdup( msg->parameters[5] ) );
			check_cmodes( msg->parameters[5] );


		case 5: /* RFC2812 */

			/* channel modes */
			irc_session_set( session, 
							 CHANNEL_MODES,
							 strdup( msg->parameters[4] ) );
			check_cmodes( msg->parameters[4] );

			/* user modes */
			irc_session_set( session, 
							 USER_MODES,
							 strdup( msg->parameters[3] ) );
			check_umodes( msg->parameters[3] );

			/* store version */
			irc_session_set( session,
							 SERVER_VERSION,
							 strdup( msg->parameters[2] ) );
	}

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

/* this is the catch-all handler that logs all inbound messages */
static irc_ret_t session_log_handler( irc_session_t * const session,
									  irc_msg_t * const msg,
									  void * user_data )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );

	/* log it */
	irc_msg_log( msg );	

	/* chain to the next handler */
	return IRC_OK;
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

static void send_pass( irc_session_t * const session )
{
	irc_msg_t * pass = NULL;
	int8_t * server_pass = NULL;
	CHECK_PTR( session );

	server_pass = irc_session_get( session, SERVER_PASS );

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

	nick_name = irc_session_get( session, NICK_NAME );

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

	user_name = irc_session_get( session, USER_NAME );

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

	quit_msg = irc_session_get( session, QUIT_MSG );

	/* send QUIT */
	quit = irc_msg_new();
	irc_msg_initialize( quit, QUIT, NULL, 0 );
	irc_msg_set_trailing( quit, quit_msg );

	/* send the QUIT command */
	irc_conn_send_msg( &(session->conn), quit );
}


static irc_ret_t irc_conn_message_in( irc_conn_t * const conn, 
									  irc_msg_t * const msg, 
									  void * user_data  )
{
	irc_session_t * session = (irc_session_t*)user_data;
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( msg, IRC_BADPARAM );

	/* call registered handlers */
	irc_session_call_handler( session, msg, msg->cmd );

	/* call the catch-all handlers */
	irc_session_call_handler( session, msg, ANYCMD );

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
	if ( irc_session_get( session, SERVER_PASS ) != NULL )
	{
		/* send the PASS command */
		send_pass( session );
	}
	else
	{
		/* send the NICK command */
		send_nick( session );
	}

	/* send the USER command */
	send_user( session );

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
	static irc_conn_ops_t conn_ops = 
	{
		&irc_conn_message_in,
		&irc_conn_message_out,
		&irc_conn_connected,
		&irc_conn_disconnected
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
	session->settings = ht_new( 64, NULL, FREE, NULL, NULL );

	/* create the handlers hashtable */
	session->handlers = ht_new( 8, NULL, &bt_delete, NULL, NULL );

	/* store the handler context */
	session->user_data = user_data;

	/* set the PING handler at the highest priority */
	irc_session_set_handler( session, PING, 
							 &session_ping_handler, 
							 SESSION_HANDLER_FIRST_PRIORITY );

	/* handle RPL_WELCOME */
	irc_session_set_handler( session, RPL_WELCOME,
							 &session_rpl_welcome_handler,
							 SESSION_HANDLER_FIRST_PRIORITY );

	/* handle RPL_MYINFO */
	irc_session_set_handler( session, RPL_MYINFO,
							 &session_rpl_myinfo_handler,
							 SESSION_HANDLER_FIRST_PRIORITY );

	/* set the ERR_NEEDMOREPARAMS handler at lowest priority */
	irc_session_set_handler( session, ERR_NEEDMOREPARAMS,
						     &session_err_needmoreparams_handler, 
							 SESSION_HANDLER_LAST_PRIORITY );

	/* set handler for ERR_ALREADYREGISTERED at lowest priority */
	irc_session_set_handler( session, ERR_ALREADYREGISTERED,
							 &session_err_alreadyregistered_handler, 
							 SESSION_HANDLER_LAST_PRIORITY );

	/* set handler for ERR_UNAVAILRESOURCE at lowest priority */
	irc_session_set_handler( session, ERR_UNAVAILRESOURCE,
							 &session_err_unavailresource_handler, 
							 SESSION_HANDLER_LAST_PRIORITY );
	
	/* set the catch-all handler */
	irc_session_set_handler( session, ANYCMD,
							 &session_log_handler,
							 SESSION_HANDLER_FIRST_PRIORITY );
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
	ht_delete( session->handlers );

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
						   irc_session_setting_t const setting,
						   void * const value )
{
	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( value, IRC_BADPARAM );
	ht_remove( session->settings, (void*)setting);
	ht_add( session->settings, (void*)setting, value );
	return IRC_OK;
}


void * irc_session_get( irc_session_t * const session,
					    irc_session_setting_t const setting )
{
	CHECK_PTR_RET( session, NULL );
	return ht_find( session->settings, (void*)setting );
}


irc_ret_t irc_session_set_handler( irc_session_t * const session,
								   irc_command_t const cmd,
								   event_handler_fn event_handler,
								   int const priority )
{
	bt_t * handler_list = NULL;

	CHECK_PTR_RET( session, IRC_BADPARAM );
	CHECK_PTR_RET( session->handlers, IRC_BADPARAM );
	CHECK_RET( IS_VALID_COMMAND( cmd ), IRC_BADPARAM );
	CHECK_PTR_RET( event_handler, IRC_BADPARAM );

	/* look up the btree associated with the specified event name */
	handler_list = (bt_t*)ht_find( session->handlers, (void*)cmd );

	if ( handler_list == NULL )
	{
		/* create a new btree to store the handlers in priority order */
		handler_list = bt_new( 1, &int_less, NULL, NULL );

		/* add the new handler pointer at the specified priority */
		bt_add( handler_list, (void*)priority, (void*)event_handler );

		/* add the btree to the handlers hashtable under the command */
		ht_add( session->handlers, (void*)cmd, (void*)handler_list );

		if ( ht_find( session->handlers, (void*)cmd ) != (void*)handler_list )
		{
			WARN( "adding handler list to session handlers failed!\n" );
		}
	}
	else
	{
		/* add the new handler pointer at the specified priority */
		bt_add( handler_list, (void*)priority, (void*)event_handler );
	}

	if ( bt_find( handler_list, (void*)priority ) != (void*)event_handler )
	{
		WARN( "adding event handler to event handler list failed!\n" );
	}

	return IRC_OK;
}

irc_ret_t irc_session_connect( irc_session_t * const session )
{
	int8_t * host;
	uint16_t port;
	CHECK_PTR_RET( session, IRC_BADPARAM );

	host = (int8_t*)irc_session_get( session, SERVER_HOST );
	port = *((uint16_t*)irc_session_get( session, SERVER_PORT ));

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

	if ( session->state == IRC_SESSION_PENDING_DISCONNECT )
	{
		/* have already tried to disconnect... */
		session->state = IRC_SESSION_DISCONNECTED;

		DEBUG("forcing session takedown\n");

		/* call "disconnected" handler */
		irc_session_call_handler( session, NULL, SESSION_DISCONNECTED );

	}
	else
	{
		/* haven't tried to disconnect yet... */
		DEBUG("beginning connection disconnect\n");

		/* move to pending disconnect state */
		session->state = IRC_SESSION_PENDING_DISCONNECT;

		/* disconnect, DON'T wait for all messages to be transmitted */
		irc_conn_disconnect( &(session->conn), FALSE );
	}

	return IRC_OK;
}

