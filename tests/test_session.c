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

#include <cutil/tests/test_macros.h>
#include <circ/session.h>

#include "test_flags.h"

extern evt_loop_t * el;
extern void test_session_private_functions( void );

static void test_session_newdel( void )
{
    irc_session_t * s = NULL;

    CU_ASSERT_PTR_NULL( irc_session_new( NULL, NULL ) );
    s = irc_session_new( el, NULL );
    CU_ASSERT_PTR_NOT_NULL( s );
    irc_session_delete( NULL );
    irc_session_delete( s );
}

static int init_session_suite( void )
{
    srand(0xDEADBEEF);
    reset_test_flags();
    return 0;
}

static int deinit_session_suite( void )
{
    reset_test_flags();
    return 0;
}

static CU_pSuite add_session_tests( CU_pSuite pSuite )
{
    ADD_TEST( "new/delete of session", test_session_newdel );

    ADD_TEST( "session private functions", test_session_private_functions );
    
    return pSuite;
}

CU_pSuite add_session_test_suite()
{
    CU_pSuite pSuite = NULL;

    /* add the suite to the registry */
    pSuite = CU_add_suite("Session Tests", init_session_suite, deinit_session_suite);
    CHECK_PTR_RET( pSuite, NULL );

    /* add in session specific tests */
    CHECK_PTR_RET( add_session_tests( pSuite ), NULL );

    return pSuite;
}

