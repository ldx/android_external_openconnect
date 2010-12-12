#include <openssl/ui.h>

#include <android/log.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h> /* for AID_VPN */

#include "openconnect.h"

static int control;

int open_control(void)
{
    int i;

    if ((i = android_get_control_socket("openconnect")) == -1) {
        android_log(PRG_ERR, "No control socket");
        return -1;
    }
    android_log(PRG_DEBUG, "Waiting for control socket");
    if (listen(i, 1) == -1 || (control = accept(i, NULL, 0)) == -1) {
        android_log(PRG_ERR, "Cannot get control socket");
        exit(-1);
    }
    close(i);

    return control;
}

int close_control(void)
{
    return close(control);
}

/*
 * Receive command arguments via control socket.
 */
int recv_cmd(int *argc, char ***argv)
{
    int i;
    static char *args[256];

    for (i = 0; i < 255; ++i) {
        unsigned char length;
        if (recv(control, &length, 1, 0) != 1) {
            android_log(PRG_ERR, "Cannot get argument length");
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
                    android_log(PRG_ERR, "Cannot get argument value");
                    return -1;
                }
            }
            args[i][length] = 0;
            android_log(PRG_DEBUG, "Argument %d: %s", i, args[i]);
        }
    }
    android_log(PRG_DEBUG, "Received %d argument(s)", i);

    *argc = i;
    *argv = args;
    return 0;
}

void free_cmd(int num, char **args)
{
    int i;
    for (i = 0; i < num; i++)
        free(args[i]);
}

int send_ack(int code)
{
    unsigned char x = (unsigned char)code;
    android_log(PRG_DEBUG, "sending ack %u", x);

    if (send(control, &x, 1, 0) != 1) {
        android_log(PRG_ERR, "send_ack() failed");
        return -1;
    }

    return 0;
}

int send_req(const char *req)
{
    int len = strlen(req);

    int pos;
    for (pos = 0; pos < len;) {
        int n = len - pos;
        if (n > 254)
            n = n % 254;
        android_log(PRG_DEBUG, "sending %d bytes via control socket", n);

        unsigned char x = (unsigned char)n;
        int rv = send(control, &x, 1, 0);
        if (rv <= 0)
            return -1;

        rv = send(control, req + pos, n, 0);
        if (rv <= 0)
            return -1;
        android_log(PRG_DEBUG, "sent %s (%d)", req + pos, rv);

        pos += rv;
    }

    return 0;
}

void android_log(int level, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	__android_log_vprint(level, "openconnect", format, ap);
	va_end(ap);
}

void android_write_progress(struct openconnect_info *info, int level,
                            const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	__android_log_vprint(level, "openconnect", format, ap);
	va_end(ap);
}

static char ui_buf[512];
static int ui_android_open(UI *ui)
{
    ui_buf[0] = '\0';
    android_log(PRG_DEBUG, "called ui_android_open()");
    return 1;
}

static int ui_android_close(UI *ui)
{
    android_log(PRG_DEBUG, "called ui_android_close()");
    return 1;
}

static int ui_android_flush(UI *ui)
{
    android_log(PRG_DEBUG, "called ui_android_flush()");
    return 1;
}

static int ui_android_read(UI *ui, UI_STRING *uis)
{
    int ok = 0;
    int num = 0;
    const char *str;
    char **args;

    switch (UI_get_string_type(uis)) {
	case UIT_BOOLEAN:
	    android_log(PRG_DEBUG, "called ui_android_read() output boolean %s",
	                UI_get0_output_string(uis));
	    android_log(PRG_DEBUG, "called ui_android_read() action boolean %s",
	                UI_get0_action_string(uis));
	    //			UI_get_input_flags(uis) & UI_INPUT_FLAG_ECHO
	case UIT_PROMPT:
        str = UI_get0_output_string(uis);
	    android_log(PRG_DEBUG, "called ui_android_read() output prompt %s",
                    str);
	    break;
	case UIT_VERIFY:
        str = UI_get0_output_string(uis);
	    android_log(PRG_DEBUG, "called ui_android_read() verify output %s",
                    str);
	    break;
	default:
        return 1;
	    break;
    }

    strlcat(ui_buf, "=X=", sizeof(ui_buf));
    strlcat(ui_buf, str, sizeof(ui_buf));

process:
    if (send_req(ui_buf) < 0) {
        android_log(PRG_ERR, "send_req() failed");
        goto out;
    }

    if (recv_cmd(&num, &args) < 0) {
        android_log(PRG_ERR, "recv_cmd() failed");
        goto out;
    }
    if (num != 1) {
        android_log(PRG_ERR, "parameter number mismatch");
        goto out;
    }

    android_log(PRG_DEBUG, "ui_android_read() cmd: %s %d", args[0], num);

    send_ack(num);

    UI_set_result(ui, uis, args[0]);

    ok = 1;

out:
    if (num)
        free_cmd(num, args);
    ui_buf[0] = '\0';
    return ok;
}

static int ui_android_write(UI *ui, UI_STRING *uis)
{
    char *str, *pos;

    switch (UI_get_string_type(uis)) {
	case UIT_ERROR:
	case UIT_INFO:
        str = UI_get0_output_string(uis);
        while ((pos = strchr(ui_buf, "\n")))
               *pos = " ";
        strlcat(ui_buf, str, sizeof(ui_buf));
	    android_log(PRG_DEBUG, "called ui_android_write() %s", str);
	    break;
	default:
	    break;
    }
    return 1;
}

int set_android_ui(void)
{
	UI_METHOD *ui_method = UI_create_method("AnyConnect Android VPN UI");

	UI_method_set_opener(ui_method, ui_android_open);
	UI_method_set_reader(ui_method, ui_android_read);
	UI_method_set_writer(ui_method, ui_android_write);
	UI_method_set_closer(ui_method, ui_android_close);

	UI_set_default_method(ui_method);

    return 0;
}

int set_my_uid(void)
{
    return setuid(AID_VPN);
}
