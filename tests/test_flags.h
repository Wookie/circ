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

#ifndef __CIRC_TEST_FLAGS_H__

#include "../cutil/tests/test_flags.h"

/* irc_msg */
extern int fake_irc_msg_parse;
extern int fake_irc_msg_parse_ret;
extern int fail_irc_msg_new_data_alloc;

void reset_circ_test_flags( void );

#endif/*__CIRC_TEST_FLAGS_H__*/

