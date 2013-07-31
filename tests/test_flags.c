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

#include <cutil/debug.h>
#include <cutil/macros.h>

/* irc_msg */
int fake_irc_msg_parse = FALSE;
int fake_irc_msg_parse_ret = FALSE;
int fail_irc_msg_new_data_alloc = FALSE;

void reset_circ_test_flags( void )
{
    reset_test_flags();

    /* irc_msg */
    fake_irc_msg_parse = FALSE;
    fake_irc_msg_parse_ret = FALSE;
    fail_irc_msg_new_data_alloc = FALSE;
}

