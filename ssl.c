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
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#if defined(__linux__)
#include <sys/vfs.h>
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__APPLE__)
#include <sys/param.h>
#include <sys/mount.h>
#elif defined (__sun__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/statvfs.h>
#elif defined (__GNU__)
#include <sys/statfs.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#ifdef ANDROID
#include "keystore_get.h"
#endif

#include "openconnect-internal.h"

/* OSX < 1.6 doesn't have AI_NUMERICSERV */
#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

/* Helper functions for reading/writing lines over SSL.
   We could use cURL for the HTTP stuff, but it's overkill */

int  __attribute__ ((format (printf, 2, 3)))
	openconnect_SSL_printf(SSL *ssl, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	buf[1023] = 0;

	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	return SSL_write(ssl, buf, strlen(buf));

}

static int print_err(const char *str, size_t len, void *ptr)
{
	struct openconnect_info *vpninfo = ptr;

	vpn_progress(vpninfo, PRG_ERR, "%s", str);
	return 0;
}

void report_ssl_errors(struct openconnect_info *vpninfo)
{
	ERR_print_errors_cb(print_err, vpninfo);
}

int openconnect_SSL_gets(SSL *ssl, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ( (ret = SSL_read(ssl, buf + i, 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i-1] == '\r') {
				buf[i-1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	if (ret == 0) {
		ret = -SSL_get_error(ssl, ret);
	}
	buf[i] = 0;
	return i ?: ret;
}

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	struct openconnect_info *vpninfo = v;

	/* Only try the provided password once... */
	SSL_CTX_set_default_passwd_cb(vpninfo->https_ctx, NULL);
	SSL_CTX_set_default_passwd_cb_userdata(vpninfo->https_ctx, NULL);

	if (len <= strlen(vpninfo->cert_password)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PEM password too long (%zd >= %d)\n"),
			     strlen(vpninfo->cert_password), len);
		return -1;
	}
	strcpy(buf, vpninfo->cert_password);
	return strlen(vpninfo->cert_password);
}

static int load_pkcs12_certificate(struct openconnect_info *vpninfo, PKCS12 *p12)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	STACK_OF(X509) *ca;
	int ret = 0;
	char pass[PEM_BUFSIZE];

 retrypass:
	/* We do this every time round the loop, to work around a bug in
	   OpenSSL < 1.0.0-beta2 -- where the stack at *ca will be freed
	   when PKCS12_parse() returns an error, but *ca is left pointing
	   to the freed memory. */
	ca = NULL;
	if (!vpninfo->cert_password) {
		if (EVP_read_pw_string(pass, PEM_BUFSIZE,
				       "Enter PKCS#12 pass phrase:", 0))
			return -EINVAL;
	}
	if (!PKCS12_parse(p12, vpninfo->cert_password?:pass, &pkey, &cert, &ca)) {
		unsigned long err = ERR_peek_error();

		report_ssl_errors(vpninfo);

		if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
		    ERR_GET_FUNC(err) == PKCS12_F_PKCS12_PARSE &&
		    ERR_GET_REASON(err) == PKCS12_R_MAC_VERIFY_FAILURE) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Parse PKCS#12 failed (wrong passphrase?)\n"));
			vpninfo->cert_password = NULL;
			goto retrypass;
		}

		vpn_progress(vpninfo, PRG_ERR,
			     _("Parse PKCS#12 failed (see above errors)\n"));
		PKCS12_free(p12);
		return -EINVAL;
	}
	if (cert) {
		vpninfo->cert_x509 = cert;
		SSL_CTX_use_certificate(vpninfo->https_ctx, cert);
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PKCS#12 contained no certificate!"));
		ret = -EINVAL;
	}

	if (pkey) {
		SSL_CTX_use_PrivateKey(vpninfo->https_ctx, pkey);
		EVP_PKEY_free(pkey);
	} else {
		vpn_progress(vpninfo, PRG_ERR,
			     _("PKCS#12 contained no private key!"));
		ret = -EINVAL;
	}

	/* Only include supporting certificates which are actually necessary */
	if (ca) {
		int i;
	next:
		for (i = 0; i < sk_X509_num(ca); i++) {
			X509 *cert2 = sk_X509_value(ca, i);
			if (X509_check_issued(cert2, cert) == X509_V_OK) {
				char buf[200];

				if (cert2 == cert)
					break;

				X509_NAME_oneline(X509_get_subject_name(cert2),
						  buf, sizeof(buf));
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Extra cert from PKCS#12: '%s'\n"), buf);
				CRYPTO_add(&cert2->references, 1, CRYPTO_LOCK_X509);
				SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert2);
				cert = cert2;
				goto next;
			}
		}
		sk_X509_pop_free(ca, X509_free);
	}

	PKCS12_free(p12);
	return ret;
}

#ifdef HAVE_ENGINE
static int load_tpm_certificate(struct openconnect_info *vpninfo)
{
	ENGINE *e;
	EVP_PKEY *key;
	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("tpm");
	if (!e) {
		vpn_progress(vpninfo, PRG_ERR, _("Can't load TPM engine.\n"));
		report_ssl_errors(vpninfo);
		return -EINVAL;
	}
	if (!ENGINE_init(e) || !ENGINE_set_default_RSA(e) ||
	    !ENGINE_set_default_RAND(e)) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to init TPM engine\n"));
		report_ssl_errors(vpninfo);
		ENGINE_free(e);
		return -EINVAL;
	}

	if (vpninfo->cert_password) {
		if (!ENGINE_ctrl_cmd(e, "PIN", strlen(vpninfo->cert_password),
				     vpninfo->cert_password, NULL, 0)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to set TPM SRK password\n"));
			report_ssl_errors(vpninfo);
		}
	}
	key = ENGINE_load_private_key(e, vpninfo->sslkey, NULL, NULL);
	if (!key) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to load TPM private key\n"));
		report_ssl_errors(vpninfo);
		ENGINE_free(e);
		ENGINE_finish(e);
		return -EINVAL;
	}
	if (!SSL_CTX_use_PrivateKey(vpninfo->https_ctx, key)) {
		vpn_progress(vpninfo, PRG_ERR, _("Add key from TPM failed\n"));
		report_ssl_errors(vpninfo);
		ENGINE_free(e);
		ENGINE_finish(e);
		return -EINVAL;
	}
	return 0;
}
#else
static int load_tpm_certificate(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without TPM support\n"));
	return -EINVAL;
}
#endif

static int reload_pem_cert(struct openconnect_info *vpninfo)
{
	BIO *b = BIO_new(BIO_s_file_internal());

	if (!b)
		return -ENOMEM;

	if (BIO_read_filename(b, vpninfo->cert) <= 0) {
	err:
		BIO_free(b);
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to reload X509 cert for expiry check\n"));
		report_ssl_errors(vpninfo);
		return -EIO;
	}
	vpninfo->cert_x509 = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
	if (!vpninfo->cert_x509)
		goto err;

	return 0;
}

#ifdef ANDROID
static BIO *BIO_from_keystore(const char *key)
{
	BIO *bio = NULL;
	char value[KEYSTORE_MESSAGE_SIZE];
	int length = keystore_get(key, strlen(key), value);
	if (length != -1 && (bio = BIO_new(BIO_s_mem())) != NULL) {
		BIO_write(bio, value, length);
	}
	return bio;
}
#endif

static int load_certificate(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_TRACE,
		     _("Using certificate file %s\n"), vpninfo->cert);

#ifdef ANDROID
	BIO *b = BIO_from_keystore(vpninfo->cert);
	if (!b)
		return -ENOMEM;

	vpninfo->cert_x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
	BIO_free(b);

	if (!vpninfo->cert_x509 ||
		!SSL_CTX_use_certificate(vpninfo->https_ctx, vpninfo->cert_x509)) {
		vpn_progress(vpninfo, PRG_ERR,
					 _("Loading certificate failed\n"));
		if (vpninfo->cert_x509) {
			X509_free(vpninfo->cert_x509);
			vpninfo->cert_x509 = NULL;
		}
		return -ENOENT;
	}

	EVP_PKEY *evp = NULL;
	b = BIO_from_keystore(vpninfo->sslkey);
	if (b) {
		evp = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
		BIO_free(b);
	}

	if (!evp || !SSL_CTX_use_PrivateKey(vpninfo->https_ctx, evp)) {
		report_ssl_errors(vpninfo);
		vpn_progress(vpninfo, PRG_ERR,
					 _("Loading private key failed\n"));
		if (evp)
			EVP_PKEY_free(evp);
		X509_free(vpninfo->cert_x509);
		vpninfo->cert_x509 = NULL;
		return -ENOENT;
	}

	EVP_PKEY_free(evp);
#else
	if (vpninfo->cert_type == CERT_TYPE_PKCS12 ||
	    vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
		FILE *f;
		PKCS12 *p12;

		f = fopen(vpninfo->cert, "r");
		if (!f) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open certificate file %s: %s\n"),
				     vpninfo->cert, strerror(errno));
			return -ENOENT;
		}
		p12 = d2i_PKCS12_fp(f, NULL);
		fclose(f);
		if (p12)
			return load_pkcs12_certificate(vpninfo, p12);

		/* Not PKCS#12 */
		if (vpninfo->cert_type == CERT_TYPE_PKCS12) {
			vpn_progress(vpninfo, PRG_ERR, _("Read PKCS#12 failed\n"));
			report_ssl_errors(vpninfo);
			return -EINVAL;
		}
		/* Clear error and fall through to see if it's a PEM file... */
		ERR_clear_error();
	}

	/* It's PEM or TPM now, and either way we need to load the plain cert: */
	if (!SSL_CTX_use_certificate_chain_file(vpninfo->https_ctx,
						vpninfo->cert)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading certificate failed\n"));
		report_ssl_errors(vpninfo);
		return -EINVAL;
	}

	/* Ew, we can't get it back from the OpenSSL CTX in any sane fashion */
	reload_pem_cert(vpninfo);

	if (vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
		FILE *f = fopen(vpninfo->sslkey, "r");
		char buf[256];

		if (!f) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open private key file %s: %s\n"),
				     vpninfo->cert, strerror(errno));
			return -ENOENT;
		}

		buf[255] = 0;
		while (fgets(buf, 255, f)) {
			if (!strcmp(buf, "-----BEGIN TSS KEY BLOB-----\n")) {
				vpninfo->cert_type = CERT_TYPE_TPM;
				break;
			} else if (!strcmp(buf, "-----BEGIN RSA PRIVATE KEY-----\n") ||
				   !strcmp(buf, "-----BEGIN DSA PRIVATE KEY-----\n") ||
				   !strcmp(buf, "-----BEGIN ENCRYPTED PRIVATE KEY-----\n")) {
				vpninfo->cert_type = CERT_TYPE_PEM;
				break;
			}
		}
		fclose(f);
		if (vpninfo->cert_type == CERT_TYPE_UNKNOWN) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to identify private key type in '%s'\n"),
				     vpninfo->sslkey);
			return -EINVAL;
		}
	}

	if (vpninfo->cert_type == CERT_TYPE_TPM)
		return load_tpm_certificate(vpninfo);

	/* Standard PEM certificate */
	if (vpninfo->cert_password) {
		SSL_CTX_set_default_passwd_cb(vpninfo->https_ctx,
					      pem_pw_cb);
		SSL_CTX_set_default_passwd_cb_userdata(vpninfo->https_ctx,
						       vpninfo);
	}
 again:
	if (!SSL_CTX_use_RSAPrivateKey_file(vpninfo->https_ctx, vpninfo->sslkey,
					    SSL_FILETYPE_PEM)) {
		unsigned long err = ERR_peek_error();
		
		report_ssl_errors(vpninfo);

#ifndef EVP_F_EVP_DECRYPTFINAL_EX
#define EVP_F_EVP_DECRYPTFINAL_EX EVP_F_EVP_DECRYPTFINAL
#endif
		/* If the user fat-fingered the passphrase, try again */
		if (ERR_GET_LIB(err) == ERR_LIB_EVP &&
		    ERR_GET_FUNC(err) == EVP_F_EVP_DECRYPTFINAL_EX &&
		    ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Loading private key failed (wrong passphrase?)\n"));
			goto again;
		}
		
		vpn_progress(vpninfo, PRG_ERR,
			     _("Loading private key failed (see above errors)\n"));
		return -EINVAL;
	}
#endif
	return 0;
}

static int get_cert_fingerprint(struct openconnect_info *vpninfo,
				X509 *cert, const EVP_MD *type,
				char *buf)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int i, n;

	if (!X509_digest(cert, type, md, &n))
		return -ENOMEM;

	for (i=0; i < n; i++)
		sprintf(&buf[i*2], "%02X", md[i]);

	return 0;
}

int get_cert_md5_fingerprint(struct openconnect_info *vpninfo,
			     X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, EVP_md5(), buf);
}

int openconnect_get_cert_sha1(struct openconnect_info *vpninfo,
			      X509 *cert, char *buf)
{
	return get_cert_fingerprint(vpninfo, cert, EVP_sha1(), buf);
}

static int check_server_cert(struct openconnect_info *vpninfo, X509 *cert)
{
	char fingerprint[EVP_MAX_MD_SIZE * 2 + 1];
	int ret;

	ret = openconnect_get_cert_sha1(vpninfo, cert, fingerprint);
	if (ret)
		return ret;

	if (strcasecmp(vpninfo->servercert, fingerprint)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Server SSL certificate didn't match: %s\n"), fingerprint);
		return -EINVAL;
	}
	return 0;
}

static int match_hostname_elem(const char *hostname, int helem_len,
			       const char *match, int melem_len)
{
	if (!helem_len && !melem_len)
		return 0;

	if (!helem_len || !melem_len)
		return -1;


	if (match[0] == '*') {
		int i;

		for (i = 1 ; i <= helem_len; i++) {
			if (!match_hostname_elem(hostname + i, helem_len - i,
						 match + 1, melem_len - 1))
				return 0;
		}
		return -1;
	}

	/* From the NetBSD (5.1) man page for ctype(3):
           Values of type char or signed char must first be cast to unsigned char,
	   to ensure that the values are within the correct range.  The result
	   should then be cast to int to avoid warnings from some compilers.
	   We do indeed get warning "array subscript has type 'char'" without
	   the casts. Ick. */
	if (toupper((int)(unsigned char)hostname[0]) ==
	    toupper((int)(unsigned char)match[0]))
		return match_hostname_elem(hostname + 1, helem_len - 1,
					   match + 1, melem_len - 1);

	return -1;
}

static int match_hostname(const char *hostname, const char *match)
{
	while (*match) {
		const char *h_dot, *m_dot;
		int helem_len, melem_len;

		h_dot = strchr(hostname, '.');
		m_dot = strchr(match, '.');
		
		if (h_dot && m_dot) {
			helem_len = h_dot - hostname + 1;
			melem_len = m_dot - match + 1;
		} else if (!h_dot && !m_dot) {
			helem_len = strlen(hostname);
			melem_len = strlen(match);
		} else
			return -1;


		if (match_hostname_elem(hostname, helem_len,
					match, melem_len))
			return -1;

		hostname += helem_len;
		match += melem_len;
	}
	if (*hostname)
		return -1;

	return 0;
}

/* cf. RFC2818 and RFC2459 */
static int match_cert_hostname(struct openconnect_info *vpninfo, X509 *peer_cert)
{
	STACK_OF(GENERAL_NAME) *altnames;
	X509_NAME *subjname;
	ASN1_STRING *subjasn1;
	char *subjstr = NULL;
	int addrlen = 0;
	int i, altdns = 0;
	char addrbuf[sizeof(struct in6_addr)];
	int ret;

	/* Allow GEN_IP in the certificate only if we actually connected
	   by IP address rather than by name. */
	if (inet_pton(AF_INET, vpninfo->hostname, addrbuf) > 0)
		addrlen = 4;
	else if (inet_pton(AF_INET6, vpninfo->hostname, addrbuf) > 0)
		addrlen = 16;
	else if (vpninfo->hostname[0] == '[' &&
		 vpninfo->hostname[strlen(vpninfo->hostname)-1] == ']') {
		char *p = &vpninfo->hostname[strlen(vpninfo->hostname)-1];
		*p = 0;
		if (inet_pton(AF_INET6, vpninfo->hostname + 1, addrbuf) > 0)
			addrlen = 16;
		*p = ']';
	}

	altnames = X509_get_ext_d2i(peer_cert, NID_subject_alt_name,
				    NULL, NULL);
	for (i = 0; i < sk_GENERAL_NAME_num(altnames); i++) {
		const GENERAL_NAME *this = sk_GENERAL_NAME_value(altnames, i);

		if (this->type == GEN_DNS) {
			char *str;

			int len = ASN1_STRING_to_UTF8((void *)&str, this->d.ia5);
			if (len < 0)
				continue;

			altdns = 1;

			/* We don't like names with embedded NUL */
			if (strlen(str) != len)
				continue;

			if (!match_hostname(vpninfo->hostname, str)) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Matched DNS altname '%s'\n"),
					     str);
				GENERAL_NAMES_free(altnames);
				OPENSSL_free(str);
				return 0;
			} else {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("No match for altname '%s'\n"),
					     str);
			}
			OPENSSL_free(str);
		} else if (this->type == GEN_IPADD && addrlen) {
			char host[80];
			int family;

			if (this->d.ip->length == 4) {
				family = AF_INET;
			} else if (this->d.ip->length == 16) {
				family = AF_INET6;
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Certificate has GEN_IPADD altname with bogus length %d\n"),
					     this->d.ip->length);
				continue;
			}
			
			/* We only do this for the debug messages */
			inet_ntop(family, this->d.ip->data, host, sizeof(host));

			if (this->d.ip->length == addrlen &&
			    !memcmp(addrbuf, this->d.ip->data, addrlen)) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Matched %s address '%s'\n"),
					     (family == AF_INET6)?"IPv6":"IPv4",
					     host);
				GENERAL_NAMES_free(altnames);
				return 0;
			} else {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("No match for %s address '%s'\n"),
					     (family == AF_INET6)?"IPv6":"IPv4",
					     host);
			}
		} else if (this->type == GEN_URI) {
			char *str;
			char *url_proto, *url_host, *url_path, *url_host2;
			int url_port;
			int len = ASN1_STRING_to_UTF8((void *)&str, this->d.ia5);

			if (len < 0)
				continue;

			/* We don't like names with embedded NUL */
			if (strlen(str) != len)
				continue;

			if (internal_parse_url(str, &url_proto, &url_host, &url_port, &url_path, 0)) {
				OPENSSL_free(str);
				continue;
			}

			if (!url_proto || strcasecmp(url_proto, "https"))
				goto no_uri_match;

			if (url_port != vpninfo->port)
				goto no_uri_match;

			/* Leave url_host as it was so that it can be freed */
			url_host2 = url_host;
			if (addrlen == 16 && vpninfo->hostname[0] != '[' &&
			    url_host[0] == '[' && url_host[strlen(url_host)-1] == ']') {
				/* Cope with https://[IPv6]/ when the hostname is bare IPv6 */
				url_host[strlen(url_host)-1] = 0;
				url_host2++;
			}

			if (strcasecmp(vpninfo->hostname, url_host2))
				goto no_uri_match;

			if (url_path) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("URI '%s' has non-empty path; ignoring\n"),
					     str);
				goto no_uri_match_silent;
			}
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Matched URI '%s'\n"),
				     str);
			free(url_proto);
			free(url_host);
			free(url_path);
			OPENSSL_free(str);
			GENERAL_NAMES_free(altnames);
			return 0;

		no_uri_match:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("No match for URI '%s'\n"),
				     str);
		no_uri_match_silent:
			free(url_proto);
			free(url_host);
			free(url_path);
			OPENSSL_free(str);
		}
	}
	GENERAL_NAMES_free(altnames);

	/* According to RFC2818, we don't use the legacy subject name if
	   there was an altname with DNS type. */
	if (altdns) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No altname in peer cert matched '%s'\n"),
			     vpninfo->hostname);
		return -EINVAL;
	}

	subjname = X509_get_subject_name(peer_cert);
	if (!subjname) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No subject name in peer cert!\n"));
		return -EINVAL;
	}

	/* Find the _last_ (most specific) commonName */
	i = -1;
	while (1) {
		int j = X509_NAME_get_index_by_NID(subjname, NID_commonName, i);
		if (j >= 0)
			i = j;
		else
			break;
	}

	subjasn1 = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subjname, i));

	i = ASN1_STRING_to_UTF8((void *)&subjstr, subjasn1);

	if (!subjstr || strlen(subjstr) != i) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse subject name in peer cert\n"));
		return -EINVAL;
	}
	ret = 0;

	if (match_hostname(vpninfo->hostname, subjstr)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Peer cert subject mismatch ('%s' != '%s')\n"),
			     subjstr, vpninfo->hostname);
		ret = -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Matched peer certificate subject name '%s'\n"),
			     subjstr);
	}

	OPENSSL_free(subjstr);			  
	return ret;
}

static int verify_peer(struct openconnect_info *vpninfo, SSL *https_ssl)
{
	X509 *peer_cert;
	int ret;

	peer_cert = SSL_get_peer_certificate(https_ssl);

	if (vpninfo->servercert) {
		/* If given a cert fingerprint on the command line, that's
		   all we look for */
		ret = check_server_cert(vpninfo, peer_cert);
	} else {
		int vfy = SSL_get_verify_result(https_ssl);
		const char *err_string = NULL;

		if (vfy != X509_V_OK)
			err_string = X509_verify_cert_error_string(vfy);
		else if (match_cert_hostname(vpninfo, peer_cert))
			err_string = _("certificate does not match hostname");

		if (err_string) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Server certificate verify failed: %s\n"),
				     err_string);

			if (vpninfo->validate_peer_cert)
				ret = vpninfo->validate_peer_cert(vpninfo->cbdata,
								  peer_cert,
								  err_string);
			else
				ret = -EINVAL;
		} else {
			ret = 0;
		}
	}
	X509_free(peer_cert);

	return ret;
}

static void workaround_openssl_certchain_bug(struct openconnect_info *vpninfo,
					     SSL *ssl)
{
	/* OpenSSL has problems with certificate chains -- if there are
	   multiple certs with the same name, it doesn't necessarily
	   choose the _right_ one. (RT#1942)
	   Pick the right ones for ourselves and add them manually. */
	X509 *cert = SSL_get_certificate(ssl);
	X509 *cert2;
	X509_STORE *store = SSL_CTX_get_cert_store(vpninfo->https_ctx);
	X509_STORE_CTX ctx;

	if (!cert || !store)
		return;

	/* If we already have 'supporting' certs, don't add them again */
	if (vpninfo->https_ctx->extra_certs)
		return;

	if (!X509_STORE_CTX_init(&ctx, store, NULL, NULL))
		return;

	while (ctx.get_issuer(&cert2, &ctx, cert) == 1) {
		char buf[200];
		if (cert2 == cert)
			break;
		cert = cert2;
		X509_NAME_oneline(X509_get_subject_name(cert),
				  buf, sizeof(buf));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Extra cert from cafile: '%s'\n"), buf);
		SSL_CTX_add_extra_chain_cert(vpninfo->https_ctx, cert);
	}
	X509_STORE_CTX_cleanup(&ctx);
}

#if OPENSSL_VERSION_NUMBER >= 0x00908000
static int ssl_app_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
	/* We've seen certificates in the wild which don't have the
	   purpose fields filled in correctly */
	X509_VERIFY_PARAM_set_purpose(ctx->param, X509_PURPOSE_ANY);
	return X509_verify_cert(ctx);
}
#endif

static int check_certificate_expiry(struct openconnect_info *vpninfo)
{
	ASN1_TIME *notAfter;
	const char *reason = NULL;
	time_t t;
	int i;

	if (!vpninfo->cert_x509)
		return 0;

	t = time(NULL);
	notAfter = X509_get_notAfter(vpninfo->cert_x509);
	i = X509_cmp_time(notAfter, &t);
	if (!i) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error in client cert notAfter field\n"));
		return -EINVAL;
	} else if (i < 0) {
		reason = _("Client certificate has expired at");
	} else {
		t += vpninfo->cert_expire_warning;
		i = X509_cmp_time(notAfter, &t);
		if (i < 0) {
			reason = _("Client certificate expires soon at");
		}
	}
	if (reason) {
		BIO *bp = BIO_new(BIO_s_mem());
		BUF_MEM *bm;
		const char *expiry = _("<error>");
		char zero = 0;

		if (bp) {
			ASN1_TIME_print(bp, notAfter);
			BIO_write(bp, &zero, 1);
			BIO_get_mem_ptr(bp, &bm);
			expiry = bm->data;
		}
		vpn_progress(vpninfo, PRG_ERR, "%s: %s\n", reason, expiry);
		if (bp)
			BIO_free(bp);
	}
	return 0;
}

int openconnect_open_https(struct openconnect_info *vpninfo)
{
	method_const SSL_METHOD *ssl3_method;
	SSL *https_ssl;
	BIO *https_bio;
	int ssl_sock = -1;
	int err;

	if (!vpninfo->port)
		vpninfo->port = 443;

	if (vpninfo->peer_addr) {
		ssl_sock = socket(vpninfo->peer_addr->sa_family, SOCK_STREAM, IPPROTO_IP);
		if (ssl_sock < 0) {
		reconn_err:
			if (vpninfo->proxy) {
				vpn_progress(vpninfo, PRG_ERR, 
					     _("Failed to reconnect to proxy %s\n"),
					     vpninfo->proxy);
			} else {
				vpn_progress(vpninfo, PRG_ERR, 
					     _("Failed to reconnect to host %s\n"),
					     vpninfo->hostname);
			}
			return -EINVAL;
		}
		if (connect(ssl_sock, vpninfo->peer_addr, vpninfo->peer_addrlen))
			goto reconn_err;
		
	} else {
		struct addrinfo hints, *result, *rp;
		char *hostname;
		char port[6];

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
		hints.ai_protocol = 0;
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		/* The 'port' variable is a string because it's easier
		   this way than if we pass NULL to getaddrinfo() and
		   then try to fill in the numeric value into
		   different types of returned sockaddr_in{6,}. */
#ifdef LIBPROXY_HDR
		if (vpninfo->proxy_factory) {
			char *url;
			char **proxies;
			int i = 0;

			free(vpninfo->proxy_type);
			vpninfo->proxy_type = NULL;
			free(vpninfo->proxy);
			vpninfo->proxy = NULL;

			if (vpninfo->port == 443)
				i = asprintf(&url, "https://%s/%s", vpninfo->hostname,
					     vpninfo->urlpath?:"");
			else
				i = asprintf(&url, "https://%s:%d/%s", vpninfo->hostname,
					     vpninfo->port, vpninfo->urlpath?:"");
			if (i == -1)
				return -ENOMEM;

			proxies = px_proxy_factory_get_proxies(vpninfo->proxy_factory,
							       url);

			while (proxies && proxies[i]) {
				if (!vpninfo->proxy &&
				    (!strncmp(proxies[i], "http://", 7) ||
				     !strncmp(proxies[i], "socks://", 8) ||
				     !strncmp(proxies[i], "socks5://", 9)))
					internal_parse_url(proxies[i], &vpninfo->proxy_type,
						  &vpninfo->proxy, &vpninfo->proxy_port,
						  NULL, 0);
				i++;
			}
			free(url);
			free(proxies);
			if (vpninfo->proxy)
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Proxy from libproxy: %s://%s:%d/\n"),
					     vpninfo->proxy_type, vpninfo->proxy, vpninfo->port);
		}
#endif
		if (vpninfo->proxy) {
			hostname = vpninfo->proxy;
			snprintf(port, 6, "%d", vpninfo->proxy_port);
		} else {
			hostname = vpninfo->hostname;
			snprintf(port, 6, "%d", vpninfo->port);
		}

		if (hostname[0] == '[' && hostname[strlen(hostname)-1] == ']') {
			/* Solaris has no strndup(). */
			int len = strlen(hostname) - 2;
			char *new_hostname = malloc(len + 1);
			if (!new_hostname)
				return -ENOMEM;
			memcpy(new_hostname, hostname + 1, len);
			new_hostname[len] = 0;

			hostname = new_hostname;
			hints.ai_flags |= AI_NUMERICHOST;
		}

		err = getaddrinfo(hostname, port, &hints, &result);
		if (hints.ai_flags & AI_NUMERICHOST)
			free(hostname);

		if (err) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("getaddrinfo failed for host '%s': %s\n"),
				     hostname, gai_strerror(err));
			return -EINVAL;
		}

		for (rp = result; rp ; rp = rp->ai_next) {
			char host[80];

			if (!getnameinfo(rp->ai_addr, rp->ai_addrlen, host,
					 sizeof(host), NULL, 0, NI_NUMERICHOST))
				vpn_progress(vpninfo, PRG_INFO,
					     _("Attempting to connect to %s%s%s:%s\n"),
					     rp->ai_family == AF_INET6?"[":"",
					     host,
					     rp->ai_family == AF_INET6?"]":"",
					     port);
			
			ssl_sock = socket(rp->ai_family, rp->ai_socktype,
					  rp->ai_protocol);
			if (ssl_sock < 0)
				continue;
			if (connect(ssl_sock, rp->ai_addr, rp->ai_addrlen) >= 0) {
				/* Store the peer address we actually used, so that DTLS can
				   use it again later */
				vpninfo->peer_addr = malloc(rp->ai_addrlen);
				if (!vpninfo->peer_addr) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Failed to allocate sockaddr storage\n"));
					close(ssl_sock);
					return -ENOMEM;
				}
				vpninfo->peer_addrlen = rp->ai_addrlen;
				memcpy(vpninfo->peer_addr, rp->ai_addr, rp->ai_addrlen);
				break;
			}
			close(ssl_sock);
			ssl_sock = -1;
		}
		freeaddrinfo(result);
		
		if (ssl_sock < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect to host %s\n"),
				     vpninfo->proxy?:vpninfo->hostname);
			return -EINVAL;
		}
	}
	fcntl(ssl_sock, F_SETFD, FD_CLOEXEC);

	if (vpninfo->proxy) {
		err = process_proxy(vpninfo, ssl_sock);
		if (err) {
			close(ssl_sock);
			return err;
		}
	}

	ssl3_method = TLSv1_client_method();
	if (!vpninfo->https_ctx) {
		vpninfo->https_ctx = SSL_CTX_new(ssl3_method);

		/* Some servers (or their firewalls) really don't like seeing
		   extensions. */
#ifdef SSL_OP_NO_TICKET
		SSL_CTX_set_options (vpninfo->https_ctx, SSL_OP_NO_TICKET);
#endif

		if (vpninfo->cert) {
			err = load_certificate(vpninfo);
			if (err) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Loading certificate failed. Aborting.\n"));
				return err;
			}
			check_certificate_expiry(vpninfo);
		}

		/* We just want to do:
		   SSL_CTX_set_purpose(vpninfo->https_ctx, X509_PURPOSE_ANY); 
		   ... but it doesn't work with OpenSSL < 0.9.8k because of 
		   problems with inheritance (fixed in v1.1.4.6 of
		   crypto/x509/x509_vpm.c) so we have to play silly buggers
		   instead. This trick doesn't work _either_ in < 0.9.7 but
		   I don't know of _any_ workaround which will, and can't
		   be bothered to find out either. */
#if OPENSSL_VERSION_NUMBER >= 0x00908000
		SSL_CTX_set_cert_verify_callback(vpninfo->https_ctx,
						 ssl_app_verify_callback, NULL);
#endif
		SSL_CTX_set_default_verify_paths(vpninfo->https_ctx);

		if (vpninfo->cafile) {
#ifndef ANDROID
			if (!SSL_CTX_load_verify_locations(vpninfo->https_ctx, vpninfo->cafile, NULL)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to open CA file '%s'\n"),
					     vpninfo->cafile);
				report_ssl_errors(vpninfo);
				close(ssl_sock);
				return -EINVAL;
			}
#else
			BIO *bio = BIO_from_keystore(vpninfo->cafile);
			if (!bio) {
				vpn_progress(vpninfo, PRG_ERR,
							 _("Failed to open CA file '%s'\n"),
							 vpninfo->cafile);
				report_ssl_errors(vpninfo);
				close(ssl_sock);
				return -ENOMEM;
			}

			STACK_OF(X509_INFO) *stack;
			stack = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
			BIO_free(bio);

			if (!stack) {
				vpn_progress(vpninfo, PRG_ERR,
							 _("Failed to open CA file '%s'\n"),
							 vpninfo->cafile);
				report_ssl_errors(vpninfo);
				close(ssl_sock);
				return -ENOMEM;
			}

			X509_STORE *cert_ctx = X509_STORE_new();
			if (cert_ctx == NULL) {
				vpn_progress(vpninfo, PRG_ERR,
							 _("X509_STORE_new failed\n"));
				report_ssl_errors(vpninfo);
				close(ssl_sock);
				return -ENOMEM;
			}

			int i;
			for (i = 0; i < sk_X509_INFO_num(stack); ++i) {
				X509_INFO *info = sk_X509_INFO_value(stack, i);
				if (info->x509) {
					X509_STORE_add_cert(cert_ctx, info->x509);
				}
				if (info->crl) {
					X509_STORE_add_crl(cert_ctx, info->crl);
				}
			}
			sk_X509_INFO_pop_free(stack, X509_INFO_free);

			SSL_CTX_set_cert_store(vpninfo->https_ctx, cert_ctx);
#endif
		}
	}
	https_ssl = SSL_new(vpninfo->https_ctx);
	workaround_openssl_certchain_bug(vpninfo, https_ssl);

	https_bio = BIO_new_socket(ssl_sock, BIO_NOCLOSE);
	SSL_set_bio(https_ssl, https_bio, https_bio);

	vpn_progress(vpninfo, PRG_INFO, _("SSL negotiation with %s\n"),
		     vpninfo->hostname);

	if (SSL_connect(https_ssl) <= 0) {
		vpn_progress(vpninfo, PRG_ERR, _("SSL connection failure\n"));
		report_ssl_errors(vpninfo);
		SSL_free(https_ssl);
		close(ssl_sock);
		return -EINVAL;
	}

	if (verify_peer(vpninfo, https_ssl)) {
		SSL_free(https_ssl);
		close(ssl_sock);
		return -EINVAL;
	}

	vpninfo->ssl_fd = ssl_sock;
	vpninfo->https_ssl = https_ssl;

	vpn_progress(vpninfo, PRG_INFO, _("Connected to HTTPS on %s\n"),
		     vpninfo->hostname);

	return 0;
}

void openconnect_close_https(struct openconnect_info *vpninfo)
{
	SSL_free(vpninfo->https_ssl);
	vpninfo->https_ssl = NULL;
	close(vpninfo->ssl_fd);
	FD_CLR(vpninfo->ssl_fd, &vpninfo->select_rfds);
	FD_CLR(vpninfo->ssl_fd, &vpninfo->select_wfds);
	FD_CLR(vpninfo->ssl_fd, &vpninfo->select_efds);
	vpninfo->ssl_fd = -1;
}

void openconnect_init_openssl(void)
{
	SSL_library_init ();
	ERR_clear_error ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms ();
}

#if defined(__sun__) || defined(__NetBSD__) || defined(__DragonFly__)
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statvfs buf;

	if (statvfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpn_progress(vpninfo, PRG_ERR, _("statvfs: %s\n"),
			     strerror(errno));
		return -err;
	}
	if (asprintf(&vpninfo->cert_password, "%lx", buf.f_fsid))
		return -ENOMEM;
	return 0;
}
#else
int openconnect_passphrase_from_fsid(struct openconnect_info *vpninfo)
{
	struct statfs buf;
	unsigned *fsid = (unsigned *)&buf.f_fsid;
	unsigned long long fsid64;

	if (statfs(vpninfo->sslkey, &buf)) {
		int err = errno;
		vpn_progress(vpninfo, PRG_ERR, _("statfs: %s\n"),
			     strerror(errno));
		return -err;
	}
	fsid64 = ((unsigned long long)fsid[0] << 32) | fsid[1];

	if (asprintf(&vpninfo->cert_password, "%llx", fsid64))
		return -ENOMEM;
	return 0;
}
#endif
