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

#include <cutil/events.h>
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
}

static void test_msg_parse_ping( void )
{
	static uint8_t const * ping = "PING LAG1370515089364389\r\n";
	irc_msg_t * msg = NULL;

	msg = irc_msg_new_from_data( ping, strlen( ping ) );
	CU_ASSERT_PTR_NOT_NULL( msg );
	CU_ASSERT_EQUAL( msg->cmd, PING );

	irc_msg_delete( msg );
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

