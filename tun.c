/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2010 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 *
 *   Free Software Foundation, Inc.
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA 02110-1301 USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#if defined(__sun__)
#include <stropts.h>
#include <sys/sockio.h>
#include <net/if_tun.h>
#ifndef TUNNEWPPA
#error "Install TAP driver from http://www.whiteboard.ne.jp/~admin2/tuntap/"
#endif
#endif

#include "openconnect.h"

/*
 * If an if_tun.h include file was found anywhere (by the Makefile), it's 
 * included. Else, we end up assuming that we have BSD-style devices such
 * as /dev/tun0 etc.
 */
#ifdef IF_TUN_HDR
#include IF_TUN_HDR
#endif

/*
 * The OS X tun/tap driver doesn't provide a header file; you're expected
 * to define this for yourself.
 */
#ifdef __APPLE__
#define TUNSIFHEAD  _IOW('t', 96, int)
#endif

/*
 * OpenBSD always puts the protocol family prefix onto packets. Other
 * systems let us enable that with the TUNSIFHEAD ioctl, and some of them
 * (e.g. FreeBSD) _need_ it otherwise they'll interpret IPv6 packets as IPv4.
 */
#if defined(__OpenBSD__) || defined(TUNSIFHEAD)
#define TUN_HAS_AF_PREFIX 1
#endif

#ifdef __sun__
static int local_config_tun(struct openconnect_info *vpninfo, int mtu_only)
{
	if (!mtu_only)
		vpninfo->progress(vpninfo, PRG_ERR,
				  "No vpnc-script configured. Need Solaris IP-setting code\n");
	return 0;
}
#else
static int local_config_tun(struct openconnect_info *vpninfo, int mtu_only)
{
	struct ifreq ifr;
	int net_fd;

	net_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (net_fd < 0) {
		perror("open net");
		return -EINVAL;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, vpninfo->ifname, sizeof(ifr.ifr_name) - 1);

	if (!mtu_only) {
		struct sockaddr_in addr;

		if (ioctl(net_fd, SIOCGIFFLAGS, &ifr) < 0)
			perror("SIOCGIFFLAGS");

		ifr.ifr_flags |= IFF_UP | IFF_POINTOPOINT;
		if (ioctl(net_fd, SIOCSIFFLAGS, &ifr) < 0)
			perror("SIOCSIFFLAGS");

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(vpninfo->vpn_addr);
		memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
		if (ioctl(net_fd, SIOCSIFADDR, &ifr) < 0)
			perror("SIOCSIFADDR");
	}

	ifr.ifr_mtu = vpninfo->mtu;
	if (ioctl(net_fd, SIOCSIFMTU, &ifr) < 0)
		perror("SIOCSIFMTU");

	close(net_fd);

	return 0;
}
#endif

static int setenv_int(const char *opt, int value)
{
	char buf[16];
	sprintf(buf, "%d", value);
	return setenv(opt, buf, 1);
}

static int netmasklen(struct in_addr addr)
{
	int masklen;

	for (masklen = 0; masklen < 32; masklen++) {
		if (ntohl(addr.s_addr) >= (0xffffffff << masklen))
			break;
	}
	return 32 - masklen;
}

static int process_split_xxclude(struct openconnect_info *vpninfo,
				 char *in_ex, char *route, int *v4_incs,
				 int *v6_incs)
{
	struct in_addr addr;
	char envname[80];
	char *slash;

	slash = strchr(route, '/');
	if (!slash) {
	badinc:
		vpninfo->progress(vpninfo, PRG_ERR,
				  "Discard bad split %sclude: \"%s\"\n",
				  in_ex, route);
		return -EINVAL;
	}

	*slash = 0;

	if (strchr(route, ':')) {
		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_ADDR", in_ex,
			 *v6_incs);
		setenv(envname, route, 1);

		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_MASKLEN", in_ex,
			 *v6_incs);
		setenv(envname, slash+1, 1);

		(*v6_incs)++;
		return 0;
	}
		
	if (!inet_aton(route, &addr)) {
		*slash = '/';
		goto badinc;
	}

	envname[79] = 0;
	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_ADDR", in_ex, *v4_incs);
	setenv(envname, route, 1);

	/* Put it back how we found it */
	*slash = '/';

	if (!inet_aton(slash+1, &addr))
		goto badinc;

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASK", in_ex, *v4_incs);
	setenv(envname, slash+1, 1);

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASKLEN", in_ex, *v4_incs);
	setenv_int(envname, netmasklen(addr));

	(*v4_incs)++;
	return 0;
}

static int appendenv(const char *opt, const char *new)
{
	char buf[1024];
	char *old = getenv(opt);

	buf[1023] = 0;
	if (old)
		snprintf(buf, 1023, "%s %s", old, new);
	else
		snprintf(buf, 1023, "%s", new);

	return setenv(opt, buf, 1);
}

static void setenv_cstp_opts(struct openconnect_info *vpninfo)
{
	char *env_buf;
	int buflen = 0;
	int bufofs = 0;
	struct vpn_option *opt;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next)
		buflen += 2 + strlen(opt->option) + strlen(opt->value);

	env_buf = malloc(buflen + 1);
	if (!env_buf)
		return;

	env_buf[buflen] = 0;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next)
		bufofs += snprintf(env_buf + bufofs, buflen - bufofs,
				   "%s=%s\n", opt->option, opt->value);

	setenv("CISCO_CSTP_OPTIONS", env_buf, 1);
	free(env_buf);
}

static void set_banner(struct openconnect_info *vpninfo)
{
	char *banner, *q;
	const char *p;

	if (!vpninfo->banner || !(banner = malloc(strlen(vpninfo->banner)))) {
		unsetenv("CISCO_BANNER");
		return;
	}
	p = vpninfo->banner;
	q = banner;
	
	while (*p) {
		if (*p == '%' && isxdigit(p[1]) && isxdigit(p[2])) {
			*(q++) = unhex(p + 1);
			p += 3;
		} else 
			*(q++) = *(p++);
	}
	*q = 0;
	setenv("CISCO_BANNER", banner, 1);

	free(banner);
}	

static void set_script_env(struct openconnect_info *vpninfo)
{
	char host[80];
	int ret = getnameinfo(vpninfo->peer_addr, vpninfo->peer_addrlen, host,
			      sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (!ret)
		setenv("VPNGATEWAY", host, 1);

	setenv("reason", "connect", 1);
	set_banner(vpninfo);
	unsetenv("CISCO_SPLIT_INC");
	unsetenv("CISCO_SPLIT_EXC");

	setenv_int("INTERNAL_IP4_MTU", vpninfo->mtu);

	if (vpninfo->vpn_addr) {
		setenv("INTERNAL_IP4_ADDRESS", vpninfo->vpn_addr, 1);
		if (vpninfo->vpn_netmask) {
			struct in_addr addr;
			struct in_addr mask;

			if (inet_aton(vpninfo->vpn_addr, &addr) &&
			    inet_aton(vpninfo->vpn_netmask, &mask)) {
				char *netaddr;

				addr.s_addr &= mask.s_addr;
				netaddr = inet_ntoa(addr);

				setenv("INTERNAL_IP4_NETADDR", netaddr, 1);
				setenv("INTERNAL_IP4_NETMASK", vpninfo->vpn_netmask, 1);
				setenv_int("INTERNAL_IP4_NETMASKLEN", netmasklen(mask));
			}
		}
	}
	if (vpninfo->vpn_addr6) {
		setenv("INTERNAL_IP6_ADDRESS", vpninfo->vpn_addr6, 1);
		setenv("INTERNAL_IP6_NETMASK", vpninfo->vpn_netmask6, 1);
	}

	if (vpninfo->vpn_dns[0])
		setenv("INTERNAL_IP4_DNS", vpninfo->vpn_dns[0], 1);
	else
		unsetenv("INTERNAL_IP4_DNS");
	if (vpninfo->vpn_dns[1])
		appendenv("INTERNAL_IP4_DNS", vpninfo->vpn_dns[1]);
	if (vpninfo->vpn_dns[2])
		appendenv("INTERNAL_IP4_DNS", vpninfo->vpn_dns[2]);

	if (vpninfo->vpn_nbns[0])
		setenv("INTERNAL_IP4_NBNS", vpninfo->vpn_nbns[0], 1);
	else
		unsetenv("INTERNAL_IP4_NBNS");
	if (vpninfo->vpn_nbns[1])
		appendenv("INTERNAL_IP4_NBNS", vpninfo->vpn_nbns[1]);
	if (vpninfo->vpn_nbns[2])
		appendenv("INTERNAL_IP4_NBNS", vpninfo->vpn_nbns[2]);

	if (vpninfo->vpn_domain)
		setenv("CISCO_DEF_DOMAIN", vpninfo->vpn_domain, 1);
	else unsetenv ("CISCO_DEF_DOMAIN");

	if (vpninfo->vpn_proxy_pac)
		setenv("CISCO_PROXY_PAC", vpninfo->vpn_proxy_pac, 1);

	if (vpninfo->split_includes) {
		struct split_include *this = vpninfo->split_includes;
		int nr_split_includes = 0;
		int nr_v6_split_includes = 0;

		while (this) {
			process_split_xxclude(vpninfo, "IN", this->route,
					      &nr_split_includes,
					      &nr_v6_split_includes);
			this = this->next;
		}
		if (nr_split_includes)
			setenv_int("CISCO_SPLIT_INC", nr_split_includes);
		if (nr_v6_split_includes)
			setenv_int("CISCO_IPV6_SPLIT_INC", nr_v6_split_includes);
	}
	if (vpninfo->split_excludes) {
		struct split_include *this = vpninfo->split_excludes;
		int nr_split_excludes = 0;
		int nr_v6_split_excludes = 0;

		while (this) {
			process_split_xxclude(vpninfo, "EX", this->route,
					      &nr_split_excludes,
					      &nr_v6_split_excludes);
			this = this->next;
		}
		if (nr_split_excludes)
			setenv_int("CISCO_SPLIT_EXC", nr_split_excludes);
		if (nr_v6_split_excludes)
			setenv_int("CISCO_IPV6_SPLIT_EXC", nr_v6_split_excludes);
	}
	setenv_cstp_opts(vpninfo);
}

static int script_config_tun(struct openconnect_info *vpninfo)
{
   if (system(vpninfo->vpnc_script)) {
           int e = errno;
                vpninfo->progress(vpninfo, PRG_ERR,
                             "Failed to spawn script '%s': %s\n",
                             vpninfo->vpnc_script, strerror(e));
           return -e;
	}
	return 0;
}


/* Set up a tuntap device. */
int setup_tun(struct openconnect_info *vpninfo)
{
	int tun_fd;

	set_script_env(vpninfo);

	if (vpninfo->script_tun) {
		pid_t child;
		int fds[2];

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)) {
			perror("socketpair");
			vpninfo->progress(vpninfo, PRG_ERR, "can't create socketpair\n");
			exit(1);
		}
		tun_fd = fds[0];
		child = fork();
		if (child < 0) {
			perror("fork");
			vpninfo->progress(vpninfo, PRG_ERR, "can't fork\n");
			exit(1);
		} else if (!child) {
			close(tun_fd);
			setenv_int("VPNFD", fds[1]);
			execl("/system/bin/sh", "/system/bin/sh", "-c", vpninfo->vpnc_script, NULL);
			perror("execl");
			vpninfo->progress(vpninfo, PRG_ERR, "can't execl()\n");
			exit(1);
		}
		close(fds[1]);
		vpninfo->script_tun = child;
		vpninfo->ifname = "(script)";
	} else {
#ifdef IFF_TUN /* Linux */
		struct ifreq ifr;
		int tunerr;

		tun_fd = open("/dev/net/tun", O_RDWR);
		if (tun_fd < 0) {
			/* Android has /dev/tun instead of /dev/net/tun
			   Since other systems might have too, just try it
			   as a fallback instead of using ifdef __ANDROID__ */
			tunerr = errno;
			tun_fd = open("/dev/tun", O_RDWR);
		}
		if (tun_fd < 0) {
			/* If the error on /dev/tun is ENOENT, that's boring.
			   Use the error we got on /dev/net/tun instead */
			if (errno != -ENOENT)
				tunerr = errno;

			vpninfo->progress(vpninfo, PRG_ERR,
					  "Failed to open tun device: %s\n",
					  strerror(tunerr));
			exit(1);
		}
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
		if (vpninfo->ifname)
			strncpy(ifr.ifr_name, vpninfo->ifname,
				sizeof(ifr.ifr_name) - 1);
		if (ioctl(tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
			vpninfo->progress(vpninfo, PRG_ERR,
					  "TUNSETIFF failed: %s\n",
					  strerror(errno));
			exit(1);
		}
		if (!vpninfo->ifname)
			vpninfo->ifname = strdup(ifr.ifr_name);
#elif defined (__sun__)
		static char tun_name[80];
		int tun2_fd, ip_fd = open("/dev/ip", O_RDWR);
		int unit_nr, mux_id;
		struct ifreq ifr;

		if (ip_fd < 0) {
			perror("open /dev/ip");
			return -EIO;
		}

		tun_fd = open("/dev/tun", O_RDWR);
		if (tun_fd < 0) {
			perror("open /dev/tun");
			close(ip_fd);
			return -EIO;
		}

		unit_nr = ioctl(tun_fd, TUNNEWPPA, -1);
		if (unit_nr < 0) {
			perror("Failed to create new tun");
			close(tun_fd);
			close(ip_fd);
			return -EIO;
		}
		
		tun2_fd = open("/dev/tun", O_RDWR);
		if (tun2_fd < 0) {
			perror("open /dev/tun again");
			close(tun_fd);
			close(ip_fd);
			return -EIO;
		}
		if (ioctl(tun2_fd, I_PUSH, "ip") < 0) {
			perror("Can't push IP");
			close(tun2_fd);
			close(tun_fd);
			close(ip_fd);
			return -EIO;
		}
		if (ioctl(tun2_fd, IF_UNITSEL, &unit_nr) < 0) {
			perror("Can't select unit");
			close(tun2_fd);
			close(tun_fd);
			close(ip_fd);
			return -EIO;
		}
		mux_id = ioctl(ip_fd, I_PLINK, tun2_fd);
		if (mux_id < 0) {
			perror("Can't link tun to IP");
			close(tun2_fd);
			close(tun_fd);
			close(ip_fd);
			return -EIO;
		}
		close(tun2_fd);

		sprintf(tun_name, "tun%d", unit_nr);
		vpninfo->ifname = tun_name;

		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, tun_name);
		ifr.ifr_ip_muxid = mux_id;

		if (ioctl(ip_fd, SIOCSIFMUXID, &ifr) < 0) {
			perror("Set mux id");
			close(tun_fd);
			ioctl(ip_fd, I_PUNLINK, mux_id);
			close(ip_fd);
			return -EIO;
		}
		/* Solaris tunctl needs this in order to tear it down */
		vpninfo->progress(vpninfo, PRG_DEBUG, "mux id is %d\n", mux_id);
		vpninfo->tun_muxid = mux_id;
		vpninfo->ip_fd = ip_fd;

#else /* BSD et al have /dev/tun$x devices */
		static char tun_name[80];
		int i;
		for (i = 0; i < 255; i++) {
			sprintf(tun_name, "/dev/tun%d", i);
			tun_fd = open(tun_name, O_RDWR);
			if (tun_fd >= 0)
				break;
		}
		if (tun_fd < 0) {
			perror("open tun");
			vpninfo->progress(vpninfo, PRG_ERR, "can't open tun device\n");
			exit(1);
		}
		vpninfo->ifname = tun_name + 5;
#ifdef TUNSIFHEAD
		i = 1;
		if (ioctl(tun_fd, TUNSIFHEAD, &i) < 0) {
			perror("TUNSIFHEAD");
			vpninfo->progress(vpninfo, PRG_ERR, "TUNSIFHEAD\n");
			exit(1);
		}
#endif
#endif
		if (vpninfo->vpnc_script) {
			setenv("TUNDEV", vpninfo->ifname, 1);
			script_config_tun(vpninfo);
			/* We have to set the MTU for ourselves, because the script doesn't */
			local_config_tun(vpninfo, 1);
		} else
			local_config_tun(vpninfo, 0);
	}

	fcntl(tun_fd, F_SETFD, FD_CLOEXEC);

	vpninfo->tun_fd = tun_fd;

	if (vpninfo->select_nfds <= tun_fd)
		vpninfo->select_nfds = tun_fd + 1;

	FD_SET(tun_fd, &vpninfo->select_rfds);

	fcntl(vpninfo->tun_fd, F_SETFL, fcntl(vpninfo->tun_fd, F_GETFL) | O_NONBLOCK);

	return 0;
}

int tun_mainloop(struct openconnect_info *vpninfo, int *timeout)
{
	unsigned char buf[2000];
	int len;
	int work_done = 0;

	if (FD_ISSET(vpninfo->tun_fd, &vpninfo->select_rfds)) {
		while ((len = read(vpninfo->tun_fd, buf, sizeof(buf))) > 0) {
			unsigned char *pkt = buf;
#ifdef TUN_HAS_AF_PREFIX
			if (!vpninfo->script_tun) {
				pkt += 4;
				len -= 4;
			}
#endif
			if (queue_new_packet(&vpninfo->outgoing_queue, pkt,
					     len))
				break;

			work_done = 1;
			vpninfo->outgoing_qlen++;
			if (vpninfo->outgoing_qlen == vpninfo->max_qlen) {
				FD_CLR(vpninfo->tun_fd, &vpninfo->select_rfds);
				break;
			}
		}
	} else if (vpninfo->outgoing_qlen < vpninfo->max_qlen) {
		FD_SET(vpninfo->tun_fd, &vpninfo->select_rfds);
	}

	/* The kernel returns -ENOMEM when the queue is full, so theoretically
	   we could handle that and retry... but it doesn't let us poll() for
	   the no-longer-full situation, so let's not bother. */
	while (vpninfo->incoming_queue) {
		struct pkt *this = vpninfo->incoming_queue;
		unsigned char *data = this->data;
		int len = this->len;

#ifdef TUN_HAS_AF_PREFIX
		if (!vpninfo->script_tun) {
			struct ip *iph = (void *)data;
			int type;

			if (iph->ip_v == 6)
				type = AF_INET6;
			else if (iph->ip_v == 4)
				type = AF_INET;
			else {
				static int complained = 0;
				if (!complained) {
					complained = 1;
					vpninfo->progress(vpninfo, PRG_ERR,
							  "Unknown packet (len %d) received: %02x %02x %02x %02x...\n",
							  len, data[0], data[1], data[2], data[3]);
				}
				free(this);
				continue;
			}
			data -= 4;
			len += 4;
			*(int *)data = htonl(type);
		}
#endif
		vpninfo->incoming_queue = this->next;

		if (write(vpninfo->tun_fd, data, len) < 0 &&
		    errno == ENOTCONN) {
			vpninfo->quit_reason = "Client connection terminated";
			return 1;
		}
		free(this);
	}
	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

void shutdown_tun(struct openconnect_info *vpninfo)
{	
	if (vpninfo->script_tun) {
		kill(vpninfo->script_tun, SIGHUP);
	} else {
		if (vpninfo->vpnc_script) {
			setenv("reason", "disconnect", 1);
			if (system(vpninfo->vpnc_script) == -1) {
				vpninfo->progress(vpninfo, PRG_ERR,
						  "Failed to spawn script '%s': %s\n",
						  vpninfo->vpnc_script,
						  strerror(errno));
			}
		}
#ifdef __sun__
		if (ioctl(vpninfo->ip_fd, I_PUNLINK, vpninfo->tun_muxid) < 0)
			perror("ioctl(I_PUNLINK)");

		close(vpninfo->ip_fd);
		vpninfo->ip_fd = -1;
#endif
	}

	close(vpninfo->tun_fd);
	vpninfo->tun_fd = -1;
}
