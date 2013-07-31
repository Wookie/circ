/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
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

#include <stdint.h>

#include <CUnit/Basic.h>

#include <cutil/macros.h>
#include <cutil/events.h>
#include <cutil/list.h>
#include <cutil/log.h>
#include <circ/commands.h>
#include <circ/msg.h>

#include "test_macros.h"
#include "test_flags.h"

extern evt_loop_t * el;
extern void test_msg_private_functions( void );

static void test_msg_newdel( void )
{
    irc_msg_t * msg = NULL;

    msg = irc_msg_new();
    CU_ASSERT_PTR_NOT_NULL( msg );
    irc_msg_delete( msg );
    msg = NULL;

    fail_alloc = TRUE;
    msg = irc_msg_new();
    CU_ASSERT_PTR_NULL( msg );
    fail_alloc = FALSE;

    fake_list_init = TRUE;
    fake_list_init_ret = FALSE;
    msg = irc_msg_new();
    CU_ASSERT_PTR_NULL( msg );
    fake_list_init = FALSE;

    /* try to delete NULL ptr */
    irc_msg_delete( msg );
}

static void test_msg_parse_ping( void )
{
    static uint8_t const * ping = "PING LAG1370515089364389\r\n";
    irc_msg_t * msg = NULL;

    msg = irc_msg_new_from_data( ping, strlen( ping ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PING );
    irc_msg_delete( msg );
    msg = NULL;

    fail_alloc = TRUE;
    msg = irc_msg_new_from_data( ping, strlen( ping ) );
    CU_ASSERT_PTR_NULL( msg );
    fail_alloc = FALSE;

    fake_list_init = TRUE;
    fake_list_init_ret = FALSE;
    msg = irc_msg_new_from_data( ping, strlen( ping ) );
    CU_ASSERT_PTR_NULL( msg );
    fake_list_init = FALSE;

    fake_irc_msg_parse = TRUE;
    fake_irc_msg_parse_ret = FALSE;
    msg = irc_msg_new_from_data( ping, strlen( ping ) );
    CU_ASSERT_PTR_NULL( msg );
    fake_irc_msg_parse = FALSE;

    fail_irc_msg_new_data_alloc = TRUE;
    msg = irc_msg_new_from_data( ping, strlen( ping ) );
    CU_ASSERT_PTR_NULL( msg );
    fail_irc_msg_new_data_alloc = FALSE;
}

static void test_msg_parse_prereqs( void )
{
    irc_msg_t * msg = NULL;

    CU_ASSERT_EQUAL( IRC_BADPARAM, irc_msg_parse( msg ) );

    msg = irc_msg_new();
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( IRC_ERR, irc_msg_parse( msg ) );

    msg->in.data = CALLOC( 32, sizeof(uint8_t) );
    CU_ASSERT_EQUAL( IRC_ERR, irc_msg_parse( msg ) );

    msg->in.size = 32;
    CU_ASSERT_EQUAL( IRC_ERR, irc_msg_parse( msg ) );

    msg->in.data[30] = '\r';
    CU_ASSERT_EQUAL( IRC_ERR, irc_msg_parse( msg ) );

    msg->in.data[31] = '\n';
    CU_ASSERT_EQUAL( IRC_ERR, irc_msg_parse( msg ) );

    irc_msg_delete( msg );
}

static void test_msg_parse_prefix( void )
{
    static uint8_t const * data0 = ":qeed!~qeed@adsl-98-85-45-93.mco.bellsouth.net QUIT :Quit: qeed\r\n";
    static uint8_t const * data1 = ":\x0a" " \r\n";
    static uint8_t const * data2 = ":blah\r\n";
    irc_msg_t * msg = NULL;

    msg = irc_msg_new_from_data( data0, strlen( data0 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, QUIT );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data1, strlen( data1 ) );
    CU_ASSERT_PTR_NULL( msg );

    msg = irc_msg_new_from_data( data2, strlen( data2 ) );
    CU_ASSERT_PTR_NULL( msg );
}

static void test_msg_log( void )
{
    static uint8_t const * data0 = ":qeed!~qeed@adsl-98-85-45-93.mco.bellsouth.net QUIT :Quit: qeed\r\n";
    static uint8_t const * data1 = "PING LAG1370515089364389\r\n";
    static uint8_t const * data2 = ":blah PONG 1 2 3 4 :trailing parameter\r\n";
    static uint8_t const * data3 = "PONG\r\n";
    static uint8_t const * data4 = ":[blah] PONG\r\n";
    static uint8_t const * data5 = ":[blah]@127.0.0.1 PONG\r\n";
    static uint8_t const * data6 = ":[blah]!blah@127.0.0.1 PONG\r\n";
    static uint8_t const * data7 = ":[blah]@::1 PONG\r\n";
    static uint8_t const * data8 = ":[blah]!blah@::1 PONG\r\n";
    static uint8_t const * data9 = ":[blah]@foo.com PONG\r\n";
    irc_msg_t * msg = NULL;
    list_t * list = NULL;
    log_t * log = NULL;

    list = list_new( 0, FREE );
    CU_ASSERT_PTR_NOT_NULL( list );

    /* clear the list and set it up for logging */
    log = start_logging( LOG_TYPE_LIST, (void*)list, FALSE );
    CU_ASSERT_PTR_NOT_NULL( log );
    
    msg = irc_msg_new_from_data( data0, strlen( data0 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, QUIT );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data1, strlen( data1 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PING );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data2, strlen( data2 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data3, strlen( data3 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data4, strlen( data4 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data5, strlen( data5 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data6, strlen( data6 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data7, strlen( data7 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data8, strlen( data8 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;

    msg = irc_msg_new_from_data( data9, strlen( data9 ) );
    CU_ASSERT_PTR_NOT_NULL( msg );
    CU_ASSERT_EQUAL( msg->cmd, PONG );
    irc_msg_log( msg );
    irc_msg_delete( msg );
    msg = NULL;
    
    stop_logging( log );
    log = NULL;

    /* clean up the list */
    list_delete( list );
}

static void test_msg_parse_params( void )
{
    static uint8_t const * data0 = "QUIT \x0a\r\n";
    irc_msg_t * msg = NULL;

    msg = irc_msg_new_from_data( data0, strlen( data0 ) );
    CU_ASSERT_PTR_NULL( msg );
}


static int init_msg_suite( void )
{
    srand(0xDEADBEEF);
    reset_test_flags();
    return 0;
}

static int deinit_msg_suite( void )
{
    reset_test_flags();
    return 0;
}

static CU_pSuite add_msg_tests( CU_pSuite pSuite )
{
    ADD_TEST( "new/delete of msg", test_msg_newdel );
    ADD_TEST( "parse ping", test_msg_parse_ping );
    ADD_TEST( "parse prereqs", test_msg_parse_prereqs );
    ADD_TEST( "parse prefix", test_msg_parse_prefix );
    ADD_TEST( "parse params", test_msg_parse_params );
    ADD_TEST( "msg log", test_msg_log );

    ADD_TEST( "msg private functions", test_msg_private_functions );
    
    return pSuite;
}

CU_pSuite add_msg_test_suite()
{
    CU_pSuite pSuite = NULL;

    /* add the suite to the registry */
    pSuite = CU_add_suite("Msg Tests", init_msg_suite, deinit_msg_suite);
    CHECK_PTR_RET( pSuite, NULL );

    /* add in msg specific tests */
    CHECK_PTR_RET( add_msg_tests( pSuite ), NULL );

    return pSuite;
}

