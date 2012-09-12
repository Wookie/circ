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

/* malloc/calloc/realloc fail switch */
int fail_alloc = FALSE;

/* system call flags */
int fake_accept = FALSE;
int fake_accept_ret = -1;
int fake_bind = FALSE;
int fake_bind_ret = -1;
int fake_connect = FALSE;
int fake_connect_ret = -1;
int fake_connect_errno = FALSE;
int fake_connect_errno_value = 0;
int fake_fcntl = FALSE;
int fake_fcntl_ret = -1;
int fake_fork = FALSE;
int fake_fork_ret = -1;
int fake_fstat = FALSE;
int fake_fstat_ret = -1;
int fake_getdtablesize = FALSE;
int fake_getdtablesize_ret = -1;
int fake_getegid = FALSE;
int fake_getegid_ret = -1;
int fake_geteuid = FALSE;
int fake_geteuid_ret = -1;
int fake_getgid = FALSE;
int fake_getgid_ret = -1;
int fake_getgroups = FALSE;
int fake_getgroups_ret = -1;
int fake_getuid = FALSE;
int fake_getuid_ret = -1;
int fake_listen = FALSE;
int fake_listen_ret = -1;
int fake_pipe = FALSE;
int fake_pipe_ret = -1;
int fake_setegid = FALSE;
int fake_setegid_ret = -1;
int fake_seteuid = FALSE;
int fake_seteuid_ret = -1;
int fake_setgroups = FALSE;
int fake_setgroups_ret = -1;
int fake_setregid = FALSE;
int fake_setregid_ret = -1;
int fake_setreuid = FALSE;
int fake_setreuid_ret = -1;
int fake_setsockopt = FALSE;
int fake_setsockopt_ret = -1;
int fake_socket = FALSE;
int fake_socket_ret = -1;

void reset_test_flags( void )
{
	/* malloc/calloc/realloc fail switch */
	fail_alloc = FALSE;

	/* system call flags */
	fake_accept = FALSE;
	fake_accept_ret = -1;
	fake_bind = FALSE;
	fake_bind_ret = -1;
	fake_connect = FALSE;
	fake_connect_ret = -1;
	fake_connect_errno = FALSE;
	fake_connect_errno_value = 0;
	fake_fcntl = FALSE;
	fake_fcntl_ret = -1;
	fake_fork = FALSE;
	fake_fork_ret = -1;
	fake_fstat = FALSE;
	fake_fstat_ret = -1;
	fake_getdtablesize = FALSE;
	fake_getdtablesize_ret = -1;
	fake_getegid = FALSE;
	fake_getegid_ret = -1;
	fake_geteuid = FALSE;
	fake_geteuid_ret = -1;
	fake_getgid = FALSE;
	fake_getgid_ret = -1;
	fake_getgroups = FALSE;
	fake_getgroups_ret = -1;
	fake_getuid = FALSE;
	fake_getuid_ret = -1;
	fake_listen = FALSE;
	fake_listen_ret = -1;
	fake_pipe = FALSE;
	fake_pipe_ret = -1;
	fake_setegid = FALSE;
	fake_setegid_ret = -1;
	fake_seteuid = FALSE;
	fake_seteuid_ret = -1;
	fake_setgroups = FALSE;
	fake_setgroups_ret = -1;
	fake_setregid = FALSE;
	fake_setregid_ret = -1;
	fake_setreuid = FALSE;
	fake_setreuid_ret = -1;
	fake_setsockopt = FALSE;
	fake_setsockopt_ret = -1;
	fake_socket = FALSE;
	fake_socket_ret = -1;
}

