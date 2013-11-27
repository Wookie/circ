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

#include <cutil/debug.h>
#include <cutil/macros.h>
#include <cutil/events.h>
#include <cutil/tests/test_macros.h>

#include <circ/commands.h>
#include <circ/msg.h>
#include <circ/conn.h>

#include "test_flags.h"

extern evt_loop_t * el;
extern void test_conn_private_functions( void );

static irc_ret_t conn_message_in( irc_conn_t * const conn,
                                  irc_msg_t * const msg,
                                  void * user_data )
{
    return IRC_OK;
}

static irc_ret_t conn_message_out( irc_conn_t * const conn,
                                   irc_msg_t * const msg,
                                   void * user_data )
{
    return IRC_OK;
}

static irc_ret_t conn_connected( irc_conn_t * const conn,
                                 void * user_data )
{
    return IRC_OK;
}

static irc_ret_t conn_disconnected( irc_conn_t * const conn,
                                    void * user_data )
{
    return IRC_OK;
}

static void test_conn_newdel( void )
{
    int i;
    irc_conn_t * c;
    static irc_conn_ops_t conn_ops = 
    {
        &conn_message_in,
        &conn_message_out,
        &conn_connected,
        &conn_disconnected
    };

    for ( i = 0; i < 32; i++ )
    {
        c = irc_conn_new( "foo.com", "7001", &conn_ops, el, NULL);

        CU_ASSERT_PTR_NOT_NULL( c );

        irc_conn_delete( (void*)c );
    }
}

static int init_conn_suite( void )
{
    srand(0xDEADBEEF);
    reset_circ_test_flags();
    return 0;
}

static int deinit_conn_suite( void )
{
    reset_circ_test_flags();
    return 0;
}

static CU_pSuite add_conn_tests( CU_pSuite pSuite )
{
    ADD_TEST( "new/delete of conn", test_conn_newdel );

    ADD_TEST( "conn private functions", test_conn_private_functions );
    
    return pSuite;
}

CU_pSuite add_conn_test_suite()
{
    CU_pSuite pSuite = NULL;

    /* add the suite to the registry */
    pSuite = CU_add_suite("Conn Tests", init_conn_suite, deinit_conn_suite);
    CHECK_PTR_RET( pSuite, NULL );

    /* add in conn specific tests */
    CHECK_PTR_RET( add_conn_tests( pSuite ), NULL );

    return pSuite;
}

