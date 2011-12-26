#include <stdio.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <android/log.h>
#include <cutils/sockets.h>

#include <openssl/ssl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "openconnect.h"

#define OC_BINARY "/system/xbin/openconnect"
#define OC_SCRIPT "/system/xbin/openconnect-up"
#define OC_USER "vpn"

#define TUN_MAJOR 10
#define TUN_MINOR 200
#define TUN_DIR "/dev/net"
#define TUN_NOD "/dev/net/tun"

static const char *oc_username = NULL;
static const char *oc_password = NULL;
static char *oc_cafile = NULL;
static pid_t oc_pid = 0;

static void android_log(int level, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    __android_log_vprint(level, "openconnect-agent", format, ap);
    va_end(ap);
}

static void android_write_progress(struct openconnect_info *info, int level,
                                   const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    __android_log_vprint(ANDROID_LOG_DEBUG, "openconnect-agent", format, ap);
    va_end(ap);
}

static int control;
static int open_control(void)
{
    int i;

    if ((i = android_get_control_socket("openconnect")) == -1) {
        android_log(ANDROID_LOG_ERROR, "No control socket");
        return -1;
    }
    android_log(ANDROID_LOG_DEBUG, "Waiting for control socket");
    if (listen(i, 1) == -1 || (control = accept(i, NULL, 0)) == -1) {
        android_log(ANDROID_LOG_ERROR, "Cannot get control socket");
        exit(-1);
    }
    close(i);

    return control;
}

static int close_control(void)
{
    return close(control);
}

/*
 * Receive command arguments via control socket.
 */
static int recv_cmd(int *argc, char ***argv)
{
    int i;
    static char *args[256];

    for (i = 0; i < 255; ++i) {
        unsigned char length;
        if (recv(control, &length, 1, 0) != 1) {
            android_log(ANDROID_LOG_ERROR, "Cannot get argument length");
            return -1;
        }
        if (length == 0xFF) {
            break;
        } else {
            int offset = 0;
            args[i] = malloc(length + 1);
            while (offset < length) {
                int n = recv(control, &args[i][offset], length - offset, 0);
                if (n > 0) {
                    offset += n;
                } else {
                    android_log(ANDROID_LOG_ERROR, "Cannot get argument value");
                    return -1;
                }
            }
            args[i][length] = 0;
            android_log(ANDROID_LOG_DEBUG, "Argument %d: %s", i, args[i]);
        }
    }
    android_log(ANDROID_LOG_DEBUG, "Received %d argument(s)", i);

    *argc = i;
    *argv = args;
    return 0;
}

static void free_cmd(int num, char **args)
{
    int i;
    for (i = 0; i < num; i++)
        free(args[i]);
}

static int send_ack(int code)
{
    unsigned char x = (unsigned char)code;
    android_log(ANDROID_LOG_DEBUG, "sending ack %u", x);

    if (send(control, &x, 1, 0) != 1) {
        android_log(ANDROID_LOG_ERROR, "send_ack() failed");
        return -1;
    }

    return 0;
}

static int send_req(const char *req)
{
    int len = strlen(req);

    int pos;
    for (pos = 0; pos < len;) {
        int n = len - pos;
        if (n > 254)
            n = n % 254;
        android_log(ANDROID_LOG_DEBUG, "sending %d bytes via control socket", n);

        unsigned char x = (unsigned char)n;
        int rv = send(control, &x, 1, 0);
        if (rv <= 0)
            return -1;

        rv = send(control, req + pos, n, 0);
        if (rv <= 0)
            return -1;
        android_log(ANDROID_LOG_DEBUG, "sent %s (%d)", req + pos, rv);

        pos += rv;
    }

    return 0;
}

static int validate_peer_cert(struct openconnect_info *vpninfo,
                              X509 *peer_cert, const char *reason)
{
    int ret;
    char fingerprint[256];

    android_log(ANDROID_LOG_DEBUG, "validate_peer_cert()\n");

    ret = openconnect_get_cert_sha1(vpninfo, peer_cert, fingerprint);

    /* XXX we don't check the server certificate */
    return 0;
}

static int write_new_config(struct openconnect_info *vpninfo, char *buf, int buflen)
{
    android_log(ANDROID_LOG_DEBUG, "write_new_config()\n");
    return 0;
}

static int send_form_fragment(char *str)
{
    android_log(ANDROID_LOG_DEBUG, "%s: request is %s\n", __FUNCTION__, str);

    if (send_req(str) < 0) {
        android_log(ANDROID_LOG_ERROR, "%s failed\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

static int send_form_fields(struct oc_auth_form *form)
{
    while (form->banner &&
           (form->banner[strlen(form->banner) - 1] == '\n' ||
            form->banner[strlen(form->banner) - 1] == '\r'))
        form->banner[strlen(form->banner) - 1] = '\0';

    while (form->message &&
           (form->message[strlen(form->message) - 1] == '\n' ||
            form->message[strlen(form->message) - 1] == '\r'))
        form->message[strlen(form->message) - 1] = '\0';

    while (form->error &&
           (form->error[strlen(form->error) - 1] == '\n' ||
            form->error[strlen(form->error) - 1] == '\r'))
        form->error[strlen(form->error) - 1] = '\0';

    char message[512];
    snprintf(message,
             sizeof(message) - 1,
             "M %s%s%s%s%s",
             form->banner ? form->banner : "",
             (form->banner && (form->error || form->message)) ? "\n" : "",
             form->error ? form->error : "",
             (form->error && form->message) ? "\n" : "",
             form->message ? form->message : "");
    if (send_form_fragment(message))
        return -1;

    struct oc_form_opt *opt;
    for (opt = form->opts; opt; opt = opt->next) {
        android_log(ANDROID_LOG_DEBUG, "opt type %d name %s label %s value %s\n",
                    opt->type, opt->name, opt->label, opt->value);
        if (opt->type == OC_FORM_OPT_SELECT) {
            struct oc_form_opt_select *sel = (void *)opt;
            int i;

            snprintf(message, sizeof(message) - 1, "S %s/%s=[",
                     opt->name, opt->label);
            for (i = 0; i < sel->nr_choices; i++) {
                android_log(ANDROID_LOG_DEBUG, "opt select name %s label %s auth_type "
                            "%s override_name %s override_label %s\n",
                            sel->choices[i].name,
                            sel->choices[i].label,
                            sel->choices[i].auth_type,
                            sel->choices[i].override_name,
                            sel->choices[i].override_label);
                size_t len = strlen(message);
                snprintf(message + len,
                         sizeof(message) - 1 - len,
                         "%s/%s%s",
                         sel->choices[i].name,
                         sel->choices[i].label,
                         i == sel->nr_choices - 1 ? "" : "|");
            }
            size_t len = strlen(message);
            snprintf(message + len, sizeof(message) - 1 - len, "]");
            android_log(ANDROID_LOG_DEBUG, "sending option '%s'\n", message);
            if (send_form_fragment(message))
                return -1;
        } else if (opt->type != OC_FORM_OPT_HIDDEN) {
            if (!strcasecmp(opt->name, "password") &&
                opt->type == OC_FORM_OPT_PASSWORD) {
                android_log(ANDROID_LOG_DEBUG, "setting password in form\n");
                opt->value = strdup(oc_password);
            } else if (!strcasecmp(opt->name, "username")) {
                android_log(ANDROID_LOG_DEBUG, "setting username in form\n");
                opt->value = strdup(oc_username);
            }

            android_log(ANDROID_LOG_DEBUG, "sending option '%s'\n", message);
            char type = opt->type == OC_FORM_OPT_PASSWORD ? 'P' : 'T';
            snprintf(message, sizeof(message) - 1, "%c %s/%s=%s",
                     type, opt->name, opt->label, opt->value ? opt->value : "");
            if (send_form_fragment(message))
                return -1;
        }
    }

    /* end of fragments */
    if (send_form_fragment("E"))
        return -1;

    return 0;
}

static void set_form_opt(struct oc_auth_form *form, int type, char *name)
{
    char *val = strchr(name, '=');
    if (!val) {
        android_log(ANDROID_LOG_ERROR, "invalid option %s\n", name);
        return;
    }
    *val = '\0';
    val++;

    struct oc_form_opt *opt;
    for (opt = form->opts; opt; opt = opt->next) {
        android_log(ANDROID_LOG_DEBUG, "opt type %d name %s label %s is: val %s\n",
                    opt->type, opt->name, opt->label, opt->value);
        if (opt->type != type || strcmp(opt->name, name))
            continue;
        opt->value = strdup(val);
        android_log(ANDROID_LOG_DEBUG, "setting opt type %d name %s label %s val %s\n",
                    opt->type, opt->name, opt->label, opt->value);
    }
}

static int recv_form_values(struct oc_auth_form *form)
{
    int num;
    char **msg;
    if (recv_cmd(&num, &msg) < 0) {
        android_log(ANDROID_LOG_ERROR, "%s: recv_cmd() failed\n", __FUNCTION__);
        return -1;
    }

    android_log(ANDROID_LOG_DEBUG, "%s: got %d form options\n", __FUNCTION__, num);

    int n;
    for (n = 0; n < num; n++) {
        char *m = msg[n];
        android_log(ANDROID_LOG_DEBUG, "checking from opt %s\n", m);
        if (strlen(m) < 3) {
            android_log(ANDROID_LOG_ERROR, "invalid option %s\n", m);
            continue;
        }

        switch (m[0]) {
            case 'S':
                set_form_opt(form, OC_FORM_OPT_SELECT, &m[2]);
                break;
            case 'T':
                set_form_opt(form, OC_FORM_OPT_TEXT, &m[2]);
                break;
            case 'P':
                set_form_opt(form, OC_FORM_OPT_PASSWORD, &m[2]);
                break;
            case 'E':
                break;
            default:
                android_log(ANDROID_LOG_ERROR, "invalid option type %c\n", m[0]);
                break;
        }
    }

    send_ack(num);

    free_cmd(num, msg);

    return 0;
}

static int process_auth_form(struct openconnect_info *vpninfo,
                             struct oc_auth_form *form)
{
    android_log(ANDROID_LOG_DEBUG, "processing auth form\nbanner %s\nmessage %s\n"
                "error %s\nauth_id %s\nmethod %s\naction %s\n",
                form->banner, form->message, form->error, form->auth_id,
                form->method, form->action);

    int ret = send_form_fields(form);
    if (ret)
        return ret;

    ret = recv_form_values(form);
    if (ret)
        return ret;

    android_log(ANDROID_LOG_DEBUG, "process_auth_form() OK\n");
    return 0;
}

static int do_setup(int argc, char **argv, struct openconnect_info *vpninfo)
{
	int i;

	if (argc != 6 && argc != 3) {
        android_log(ANDROID_LOG_ERROR, "Parameter mismatch\n");
        return -1;
	}

    openconnect_set_hostname(vpninfo, strdup(argv[0]));
	//port = 443;
	oc_username = strdup(argv[1]);
	oc_password = strdup(argv[2]);
	if (argc == 6) {
        openconnect_set_client_cert(vpninfo, strdup(argv[4]), strdup(argv[3]));
        openconnect_set_cafile(vpninfo, strdup(argv[5]));
        oc_cafile = strdup(argv[5]);
	}

    return 0;
}

static int start_daemon(struct openconnect_info *vpninfo, char *tun_if)
{
    int ret = -1;
    int p[2] = { -1, -1 };
    char arg[256];
    char *gw = NULL, *gwcert = NULL, *cookie = NULL, *user = NULL, *intf = NULL;

    snprintf(arg, sizeof(arg) - 1, "%s:%d",
             openconnect_get_hostname(vpninfo),
             openconnect_get_port(vpninfo));
    gw = strdup(arg);
    if (!gw) {
        android_log(ANDROID_LOG_ERROR, "out of memory\n");
        goto out;
    }

    X509 *cert = openconnect_get_peer_cert(vpninfo);
    if (cert) {
        openconnect_get_cert_sha1(vpninfo, cert, arg);
        gwcert = strdup(arg);
        if (!gwcert) {
            android_log(ANDROID_LOG_ERROR, "out of memory\n");
            goto out;
        }
    }

    cookie = strdup(openconnect_get_cookie(vpninfo));
    openconnect_clear_cookie(vpninfo);

    snprintf(arg, sizeof(arg) - 1, "--setuid=%s", OC_USER);
    user = strdup(arg);
    if (!user) {
        android_log(ANDROID_LOG_ERROR, "out of memory\n");
        goto out;
    }

    snprintf(arg, sizeof(arg) - 1, "--interface=%s", tun_if);
    intf = strdup(arg);
    if (!intf) {
        android_log(ANDROID_LOG_ERROR, "out of memory\n");
        goto out;
    }

    char * const args[12] = {
        OC_BINARY,
        "--servercert",
        gwcert,
        "--cookie-on-stdin",
        "--script",
        OC_SCRIPT,
        intf,
        user,
        oc_cafile ? "--cafile" : gw,
        oc_cafile ? oc_cafile : NULL,
        oc_cafile ? gw : NULL,
        NULL
    };
    android_log(ANDROID_LOG_DEBUG, "daemon command line:\n");
    int i;
    for (i = 0; args[i]; i++)
        android_log(ANDROID_LOG_DEBUG, "\t%s\n", args[i]);

    if (pipe(p) < 0) {
        android_log(ANDROID_LOG_ERROR, "pipe() failed\n");
        goto out;
    }

    oc_pid = fork();
    if (!oc_pid) {
        close(p[1]);
        p[1] = -1;
        if (dup2(p[0], 0) < 0) { // STDIN_FILENO
            android_log(ANDROID_LOG_ERROR, "dup2() failed\n");
            exit(1);
        }
        if (execv(OC_BINARY, args) < 0) {
            android_log(ANDROID_LOG_ERROR, "execv() failed\n");
            exit(1);
        }
    } else if (oc_pid > 0) {
        close(p[0]);
        p[0] = -1;
        if (write(p[1], cookie, strlen(cookie)) != (int)strlen(cookie) ||
            write(p[1], "\n", 1) != 1) {
            android_log(ANDROID_LOG_ERROR, "write() failed\n");
            goto out;
        }
        close(p[1]);
        p[1] = -1;
    } else {
        android_log(ANDROID_LOG_ERROR, "fork() failed\n");
        goto out;
    }

    ret = 0;
    goto out_free;

out:
    if (oc_pid)
        kill(oc_pid, SIGKILL);
    if (p[0] >= 0)
        close(p[0]);
    if (p[1] >= 0)
        close(p[1]);
out_free:
    if (gw)
        free((void *)gw);
    if (gwcert)
        free((void *)gwcert);
    if (cookie)
        free((void *)cookie);
    if (user)
        free((void *)user);
    if (intf)
        free((void *)intf);
    return ret;
}

static int get_tun(char *tun_if)
{
	struct passwd *pw = getpwnam(OC_USER);
	if (!pw) {
        android_log(ANDROID_LOG_ERROR, "getpwnam() failed\n");
		return -1;
    }

	uid_t tun_owner = pw->pw_uid;
	gid_t tun_group = pw->pw_gid;

	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
        android_log(ANDROID_LOG_ERROR, "opening tun control device failed\n");
        return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	int i;
	for (i = 0; i < 32; i++) {
		sprintf(ifr.ifr_name, "vpn%d", i);
		if (!ioctl(fd, TUNSETIFF, (void *)&ifr))
			break;
	}
	if (i == 32) {
        android_log(ANDROID_LOG_ERROR, "can't find available tun tun_if\n");
        return -1;
    }

	if (ioctl(fd, TUNSETOWNER, tun_owner) < 0) {
        android_log(ANDROID_LOG_ERROR, "TUNSETOWNER failed\n");
        return -1;
	}

	if (ioctl(fd, TUNSETPERSIST, 1)) {
        android_log(ANDROID_LOG_ERROR, "TUNSETPERSIST failed\n");
        return -1;
	}

    strcpy(tun_if, ifr.ifr_name);

	close(fd);
    return 0;
}

static int put_tun(char *tun_if)
{
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
        android_log(ANDROID_LOG_ERROR, "opening tun control device failed\n");
        return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strcpy(ifr.ifr_name, tun_if);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        android_log(ANDROID_LOG_ERROR, "TUNSETIFF failed\n");
        return -1;
	}

	if (ioctl(fd, TUNSETPERSIST, 0)) {
        android_log(ANDROID_LOG_ERROR, "TUNSETPERSIST failed\n");
        return -1;
	}

	close(fd);
    return 0;
}

static void handle_child(int sig)
{
    pid_t pid;

    do {
        pid = waitpid(-1, NULL, WNOHANG);
        if (pid == oc_pid)
            oc_pid = 0;
    } while (pid > 0);
}

static int create_dev(void)
{
    /* This might fail if the directory already exists. */
    if (mkdir(TUN_DIR, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP |
              S_IROTH | S_IXOTH) < 0 && errno != EEXIST) {
        android_log(ANDROID_LOG_ERROR, "mkdir %s: %s\n", TUN_DIR,
                    strerror(errno));
        return -1;
    }

    dev_t dev = makedev(TUN_MAJOR, TUN_MINOR);
    if (mknod(TUN_NOD, S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
              dev) < 0 && errno != EEXIST) {
        android_log(ANDROID_LOG_ERROR, "mknod %s: %s\n", TUN_NOD,
                    strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret = -1;
    struct openconnect_info *vpninfo = NULL;

    android_log(ANDROID_LOG_INFO, "%s starting\n", argv[0]);

    if (system("modprobe tun") < 0) {
        android_log(ANDROID_LOG_ERROR, "modprobing tun failed\n");
        goto out;
    }

    if (create_dev() < 0) {
        android_log(ANDROID_LOG_ERROR, "creating device node failed\n");
        goto out;
    }

    if (signal(SIGCHLD, handle_child) == SIG_ERR) {
        android_log(ANDROID_LOG_ERROR, "couldn't set up signal handler\n");
        goto out;
    }

    /* get control socket */
	if (open_control() < 0)
        goto out;

    /* receive parameters via control socket and set up vpninfo */
	if (recv_cmd(&argc, &argv) < 0)
        goto out;
    vpninfo = (void *)openconnect_vpninfo_new("OpenConnect Android VPN Agent",
                                              validate_peer_cert,
                                              write_new_config,
                                              process_auth_form,
                                              android_write_progress);
	if (do_setup(argc, argv, vpninfo) < 0)
        goto out;
    send_ack(argc);
    free_cmd(argc, argv);

    openconnect_init_openssl();

    openconnect_reset_ssl(vpninfo);

    ret = openconnect_obtain_cookie(vpninfo);
    if (ret) {
        android_log(ANDROID_LOG_ERROR, "could not obtain cookie (%d)\n", ret);
        goto out;
    }
    android_log(ANDROID_LOG_DEBUG, "cookie obtained\n");

    char tun_if[IFNAMSIZ];
    if (get_tun(tun_if))
        goto out;
    android_log(ANDROID_LOG_DEBUG, "got tun device %s\n", tun_if);

    if (start_daemon(vpninfo, tun_if))
        goto out;
    android_log(ANDROID_LOG_DEBUG, "started daemon, pid: %u\n", oc_pid);

    if (oc_pid) {
        send_req("X");
        while (oc_pid)
            sleep(3);
    }

    if (put_tun(tun_if))
        goto out;

    ret = 0;

out:
    if (vpninfo)
        openconnect_vpninfo_free(vpninfo);
    return ret;
}
