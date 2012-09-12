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

#ifndef __TEST_FLAGS_H__

/* malloc/calloc/realloc fail switch */
extern int fail_alloc;

/* system call flags */
extern int fake_accept;
extern int fake_accept_ret;
extern int fake_bind;
extern int fake_bind_ret;
extern int fake_connect;
extern int fake_connect_ret;
extern int fake_connect_errno;
extern int fake_connect_errno_value;
extern int fake_fcntl;
extern int fake_fcntl_ret;
extern int fake_fork;
extern int fake_fork_ret;
extern int fake_fstat;
extern int fake_fstat_ret;
extern int fake_getdtablesize;
extern int fake_getdtablesize_ret;
extern int fake_getegid;
extern int fake_getegid_ret;
extern int fake_geteuid;
extern int fake_geteuid_ret;
extern int fake_getgid;
extern int fake_getgid_ret;
extern int fake_getgroups;
extern int fake_getgroups_ret;
extern int fake_getuid;
extern int fake_getuid_ret;
extern int fake_listen;
extern int fake_listen_ret;
extern int fake_pipe;
extern int fake_pipe_ret;
extern int fake_setegid;
extern int fake_setegid_ret;
extern int fake_seteuid;
extern int fake_seteuid_ret;
extern int fake_setgroups;
extern int fake_setgroups_ret;
extern int fake_setregid;
extern int fake_setregid_ret;
extern int fake_setreuid;
extern int fake_setreuid_ret;
extern int fake_setsockopt;
extern int fake_setsockopt_ret;
extern int fake_socket;
extern int fake_socket_ret;

void reset_test_flags( void );

#endif/*__TEST_FLAGS_H__*/

