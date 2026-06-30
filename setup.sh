#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2021 grommunio GmbH
# Interactive grommunio setup

DATADIR="${0%/*}"
if [ "${DATADIR}" = "$0" ]; then
	DATADIR="/usr/share/grommunio-setup"
else
	DATADIR="$(readlink -f "$0")"
	DATADIR="${DATADIR%/*}"
	DATADIR="$(readlink -f "${DATADIR}")"
fi
LOGFILE="/var/log/grommunio-setup.log"
if ! test -e "$LOGFILE"; then
	true >"$LOGFILE"
	chmod 0600 "$LOGFILE"
fi
# shellcheck source=common/helpers
. "${DATADIR}/common/helpers"
# shellcheck source=common/dialogs
. "${DATADIR}/common/dialogs"
# shellcheck source=common/roles
. "${DATADIR}/common/roles"
TMPF=$(mktemp /tmp/grommunio-setup.XXXXXXXX)
trap 'rm -f "${TMPF}"' EXIT

writelog "Welcome dialog"
dialog_welcome

# Load persisted state from any previous run (FQDN, secrets, installed roles).
state_load

# Determine which roles are currently installed (WAS_<ROLE>), preferring the
# recorded state and falling back to package detection for installs that
# predate the state file.
detect_was()
{
	local r u val pkg
	for r in ${ALL_ROLES} ; do
		u=$(echo "$r" | tr '[:lower:]' '[:upper:]')
		eval "val=\${FT_${u}:-}"
		if [ -n "${val}" ] ; then
			eval "WAS_${u}=${val}"
			continue
		fi
		case "$r" in
			chat)    pkg=grommunio-chat ;;
			meet)    pkg=jitsi-videobridge ;;
			files)   pkg=grommunio-files ;;
			office)  pkg=grommunio-office ;;
			archive) pkg=grommunio-archive ;;
		esac
		if pkg_installed "${pkg}" ; then
			eval "WAS_${u}=true"
		else
			eval "WAS_${u}=false"
		fi
	done
}
# An installation is only considered "existing" once it has fully completed
# (the setup_done marker is written at the very end). This way an aborted first
# run - which may have left a partial state file - is correctly retried as a
# fresh install rather than a broken reconfigure.
SETUP_MODE="fresh"
if [ -e "/etc/grommunio-common/setup_done" ] ; then
	detect_was
	choose_setup_mode
	if [ "${SETUP_ACTION}" = "scratch" ] ; then
		DELCONFIRM=$(dialog --no-mouse --colors --backtitle "grommunio Setup" --title "grommunio Setup: reset from scratch" --cr-wrap --inputbox \
'You chose to reset everything and set up from scratch.

To confirm deletion of ALL data, type "removealldata" to continue.

\Z1If you continue, ALL data will be removed!\Z1' \
0 0 3>&1 1>&2 2>&3)
		dialog_exit $?

		if [ "${DELCONFIRM}" != "removealldata" ] ; then
			writelog "Aborted reset after detected existing installation"
			exit 0
		fi
		writelog "Deleting existing installation after confirmation"
		echo "drop database if exists grommunio;" | mysql
		for r in ${ALL_ROLES} ; do
			u=$(echo "$r" | tr '[:lower:]' '[:upper:]')
			eval "rdb=\${${u}_MYSQL_DB:-}"
			[ -n "${rdb}" ] && echo "drop database if exists \`${rdb}\`;" | mysql
		done
		for rdb in grochat grofiles groffice groarchive ; do
			echo "drop database if exists \`${rdb}\`;" | mysql
		done
		rm -rf /var/lib/gromox/user/* /var/lib/gromox/domain/* /etc/grommunio-common/ssl/* /etc/grommunio-common/setup_done
		rm -rf /var/lib/prosody/*
		rm -rf "${ROLE_BACKUP_BASE}"
		rm -f "${STATE_FILE}"
		# Tear down any archive postfix wiring so the wiped system does not keep
		# bcc-copying mail to a now-dropped archive (the core postconf block below
		# resets smtpd_recipient_restrictions). Harmless if archive was not set up.
		postconf -X always_bcc >>"${LOGFILE}" 2>&1
		rm -f /etc/postfix/transport /etc/postfix/transport.db /etc/postfix/grommunio-archiver-envelope.cf
		unset CHAT_MYSQL_PASS FILES_MYSQL_PASS OFFICE_MYSQL_PASS ARCHIVE_MYSQL_PASS
		SETUP_MODE="fresh"
	else
		SETUP_MODE="reconfigure"
	fi
fi

# For a fresh/clean run (incl. the from-scratch reset) every selected role is
# configured from scratch, so forget any prior role state.
if [ "${SETUP_MODE}" = "fresh" ] ; then
	for r in ${ALL_ROLES} ; do
		u=$(echo "$r" | tr '[:lower:]' '[:upper:]')
		eval "WAS_${u}=false"
	done
fi
writelog "Setup mode: ${SETUP_MODE}"

memory_check()
{

  local HAVE=$(perl -lne 'print $1 if m{^MemTotal:\s*(\d+)}i' </proc/meminfo)
  # Install the threshold a little lower than what we ask, to account for
  # FW/OS (Vbox with 4194304 KB ends up with MemTotal of about 4020752 KB)
  local THRES=4000000
  local ASK=4096000
  if [ -z "${HAVE}" ] || [ "${HAVE}" -ge "${THRES}" ]; then
    return 0
  fi
  writelog "Memory check"
  memory_notice $((HAVE/1024)) $((ASK/1024))

}

memory_check

# In reconfigure mode, the previously chosen values (and secrets) are reused.
# Fill in anything missing from the live system configuration so that installs
# predating the state file reconfigure correctly.
load_core_from_system()
{
	local v
	v=$(getconf_val /etc/gromox/mysql_adaptor.cfg mysql_username) ; [ -n "${v}" ] && MYSQL_USER="${v}"
	v=$(getconf_val /etc/gromox/mysql_adaptor.cfg mysql_password) ; [ -n "${v}" ] && MYSQL_PASS="${v}"
	v=$(getconf_val /etc/gromox/mysql_adaptor.cfg mysql_dbname)   ; [ -n "${v}" ] && MYSQL_DB="${v}"
	v=$(getconf_val /etc/gromox/mysql_adaptor.cfg mysql_host)     ; [ -n "${v}" ] && MYSQL_HOST="${v}"
	MYSQL_HOST="${MYSQL_HOST:-localhost}"
	MYSQL_USER="${MYSQL_USER:-grommunio}"
	MYSQL_DB="${MYSQL_DB:-grommunio}"
	if [ -z "${MYSQL_INSTALL_TYPE}" ] ; then
		if [ "${MYSQL_HOST}" != "localhost" ] ; then MYSQL_INSTALL_TYPE=2 ; else MYSQL_INSTALL_TYPE=1 ; fi
	fi
	v=$(getconf_val /etc/gromox/http.cfg host_id)         ; [ -n "${v}" ] && FQDN="${v}"
	v=$(getconf_val /etc/gromox/http.cfg default_domain)  ; [ -n "${v}" ] && DOMAIN="${v}"
	v=$(getconf_val /etc/gromox/autodiscover.cfg x500_org_name) ; [ -n "${v}" ] && X500="${v}"
	[ -z "${X500}" ] && X500=$(getconf_val /etc/gromox/midb.cfg x500_org_name)
	[ -z "${FQDN}" ] && FQDN=$(hostname -f)
	[ -z "${DOMAIN}" ] && DOMAIN=$(hostname -d)
	[ -z "${RELAYHOST}" ] && RELAYHOST=$(postconf -h relayhost 2>/dev/null)
	FQDN="${FQDN,,}"
	DOMAIN="${DOMAIN,,}"
}

if [ "${SETUP_MODE}" = "fresh" ] ; then
	unset MYSQL_DB MYSQL_HOST MYSQL_USER MYSQL_PASS
	unset CHAT_MYSQL_DB CHAT_MYSQL_HOST CHAT_MYSQL_USER CHAT_MYSQL_PASS CHAT_ADMIN_PASS
	unset FILES_MYSQL_DB FILES_MYSQL_HOST FILES_MYSQL_USER FILES_MYSQL_PASS FILES_ADMIN_PASS
	unset ARCHIVE_MYSQL_DB ARCHIVE_MYSQL_HOST ARCHIVE_MYSQL_USER ARCHIVE_MYSQL_PASS ARCHIVE_ADMIN_PASS ARCHIVE_AUDIT_PASS
	unset OFFICE_MYSQL_DB OFFICE_MYSQL_HOST OFFICE_MYSQL_USER OFFICE_MYSQL_PASS
	unset ADMIN_PASS FQDN DOMAIN X500 SSL_BUNDLE SSL_KEY
fi

get_features

set_repo() {

  writelog "Dialog: repository"
  dialog --no-mouse --colors --backtitle "grommunio Setup" --title "Repository configuration" --ok-label "Submit" \
         --form "\nIf you have a subscription, enter your credentials here.\n\nLeave empty for community (unsupported) repositories." 0 0 0 \
  "Subscription username:    " 1 1 "${REPO_USER}"         1 25 25 0 \
  "Subscription password:    " 2 1 "${REPO_PASS}"         2 25 25 0 2>"${TMPF}"
  dialog_exit $?

}

set_repo
REPO_USER=$(sed -n '1{p;q}' "${TMPF}")
REPO_PASS=$(sed -n '2{p;q}' "${TMPF}")
state_set REPO_USER "${REPO_USER}"
state_set REPO_PASS "${REPO_PASS}"
writelog "Installation / update of packages"
# shellcheck source=common/repo
PACKAGES="gromox grommunio-admin-api grommunio-admin-web grommunio-antispam \
  grommunio-common grommunio-web grommunio-sync grommunio-dav \
  mariadb php-fpm cyrus-sasl-saslauthd cyrus-sasl-plain postfix jq"
PACKAGES="$PACKAGES $FT_PACKAGES"
. "${DATADIR}/common/repo"
setup_repo

# The database must be up before any database operation below (core schema as
# well as the chat/files/office/archive roles which are configured before the
# core service block runs its own start).
writelog "Ensuring mariadb is running"
systemctl enable mariadb >>"${LOGFILE}" 2>&1
systemctl start mariadb >>"${LOGFILE}" 2>&1

if [ "${SETUP_MODE}" = "reconfigure" ] ; then
  load_core_from_system
  # Refuse to continue if the existing core DB password could not be recovered,
  # rather than blanking the account / breaking the install.
  if [ "${MYSQL_INSTALL_TYPE}" != "2" ] && [ -z "${MYSQL_PASS}" ] ; then
    dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "grommunio Setup" --msgbox \
"The existing database password could not be determined from /etc/gromox/mysql_adaptor.cfg.\n\nReconfiguration has been aborted to avoid breaking the installation. Inspect the configuration, or use the from-scratch reset if you intend to reinstall." 0 0
    writelog "Reconfigure aborted: core MYSQL_PASS could not be recovered"
    exit 1
  fi
  # Ensure the local database, user and grant are still in place (self-healing,
  # never destructive). The password is reused, not regenerated.
  if [ "${MYSQL_INSTALL_TYPE}" != "2" ] ; then
    ensure_db localhost "${MYSQL_USER}" "${MYSQL_PASS}" "${MYSQL_DB}"
  fi
  writelog "MySQL configuration (reused): Host: ${MYSQL_HOST}, User: ${MYSQL_USER}, Database: ${MYSQL_DB}"
else
  MYSQL_HOST="localhost"
  MYSQL_USER="grommunio"
  MYSQL_PASS=$(randpw)
  MYSQL_DB="grommunio"

  set_mysql_param(){

    writelog "Dialog: mysql configuration"
    dialog --no-mouse --colors --backtitle "grommunio Setup" --title "MariaDB/MySQL database credentials" --ok-label "Submit" \
           --form "Enter the database credentials." 0 0 0   \
           "Host:    " 1 1 "${MYSQL_HOST}"         1 17 25 0 \
           "User:    " 2 1 "${MYSQL_USER}"         2 17 25 0 \
           "Password:" 3 1 "${MYSQL_PASS}"         3 17 25 0 \
           "Database:" 4 1 "${MYSQL_DB}"           4 17 25 0 2>"${TMPF}"
    dialog_exit $?

  }

  writelog "Dialog: mysql installation type"
  MYSQL_INSTALL_TYPE=$(dialog --no-mouse --colors --backtitle "grommunio Setup" --title "grommunio Setup: Database" \
                             --menu "Choose database setup type" 0 0 0 \
                             "1" "Create database locally (default)" \
                             "2" "Connect to existing database (advanced users)" 3>&1 1>&2 2>&3)
  dialog_exit $?

  writelog "Selected MySQL installation type: ${MYSQL_INSTALL_TYPE}"

  RETCMD=1
  if [ "${MYSQL_INSTALL_TYPE}" = "2" ]; then
    while [ ${RETCMD} -ne 0 ]; do
      set_mysql_param "Existing database"
      MYSQL_HOST=$(sed -n '1{p;q}' "${TMPF}")
      MYSQL_USER=$(sed -n '2{p;q}' "${TMPF}")
      MYSQL_PASS=$(sed -n '3{p;q}' "${TMPF}")
      MYSQL_DB=$(sed -n '4{p;q}' "${TMPF}")
      if [ -n "${MYSQL_HOST}" ] && [ -n "${MYSQL_USER}" ] && [ -z "${MYSQL_PASS}" ] && [ -n "${MYSQL_DB}" ]; then
        echo "show tables;" | mysql -h"${MYSQL_HOST}" -u"${MYSQL_USER}" "${MYSQL_DB}" >/dev/null 2>&1
        writelog "mysql -h${MYSQL_HOST} -u${MYSQL_USER} ${MYSQL_DB}"
      elif [ -n "${MYSQL_HOST}" ] && [ -n "${MYSQL_USER}" ] && [ -n "${MYSQL_PASS}" ] && [ -n "${MYSQL_DB}" ]; then
        echo "show tables;" | mysql -h"${MYSQL_HOST}" -u"${MYSQL_USER}" -p"${MYSQL_PASS}" "${MYSQL_DB}" >/dev/null 2>&1
        writelog "mysql -h${MYSQL_HOST} -u${MYSQL_USER} -p${MYSQL_PASS} ${MYSQL_DB}"
      else
        failonme 1
      fi
      RETCMD=$?
      if [ ${RETCMD} -ne 0 ]; then
        dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "MySQL database credentials" --msgbox 'No connection could be established with the database using the provided credentials. Verify that the credentials are correct and that a connection to the database is possible from this system.' 0 0
        dialog_exit $?
      fi
    done
  else
    while [ ${RETCMD} -ne 0 ]; do
      set_mysql_param "Create database"
      MYSQL_HOST=$(sed -n '1{p;q}' "${TMPF}")
      MYSQL_USER=$(sed -n '2{p;q}' "${TMPF}")
      MYSQL_PASS=$(sed -n '3{p;q}' "${TMPF}")
      MYSQL_DB=$(sed -n '4{p;q}' "${TMPF}")
      if [ -n "${MYSQL_HOST}" ] && [ -n "${MYSQL_USER}" ] && [ -n "${MYSQL_PASS}" ] && [ -n "${MYSQL_DB}" ]; then
        ensure_db "${MYSQL_HOST}" "${MYSQL_USER}" "${MYSQL_PASS}" "${MYSQL_DB}"
        mysql_db_exists "${MYSQL_DB}"
      else
        failonme 1
      fi
      RETCMD=$?
      if [ ${RETCMD} -ne 0 ]; then
        dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "MySQL connection failed" --msgbox 'Could not set up the database. Make sure it is reachable and re-run the creation process.' 0 0
        dialog_exit $?
      fi
    done
  fi
  writelog "MySQL configuration: Host: ${MYSQL_HOST}, User: ${MYSQL_USER}, Password: ${MYSQL_PASS}, Database: ${MYSQL_DB}"

  dialog_adminpass

  set_fqdn(){

    writelog "Dialog: FQDN"
    dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "Fully Qualified Domain Name (FQDN)" --cr-wrap --inputbox \
"Tell us this system's fully qualified domain name (FQDN). This is used, for example, by Outlook clients to connect.

Example: grommunio.example.com

This name will be part of the certificates later generated. / This name will have to be present in imported certificates." 0 0 "$(hostname -f)" 3>&1 1>&2 2>&3
    dialog_exit $?

  }

  ORIGFQDN=$(set_fqdn)
  FQDN="${ORIGFQDN,,}"

  while [[ ${FQDN} =~ / ]] ; do
    dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "Fully Qualified Domain Name (FQDN)" --msgbox 'The FQDN is invalid. Enter a valid FQDN.' 0 0
    FQDN=$(set_fqdn)
    dialog_exit $?
  done
  writelog "Configured FQDN: ${FQDN}"

  set_maildomain(){

    DFL=$(hostname -d)
    if [ -z "${DFL}" ]; then
      DFL="${FQDN}"
    fi
    writelog "Dialog: mail domain"
    dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "Mail domain" --cr-wrap --inputbox \
"Tell us the default mail domain this system serves up. This is used, for example, for Non-Delivery Reports and for generation of some simple TLS certificates. Specify ONLY ONE domain here.

Example: example.com" 0 0 "${DFL}" 3>&1 1>&2 2>&3
    dialog_exit $?

  }

  ORIGDOMAIN=$(set_maildomain)
  DOMAIN=${ORIGDOMAIN,,}

  while [[ ${DOMAIN} =~ / ]] ; do
    dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "Mail domain" --msgbox 'The entered mail domain is invalid. Enter a valid mail domain.' 0 0
    dialog_exit $?
    ORIGDOMAIN=$(set_maildomain)
    DOMAIN=${ORIGDOMAIN,,}
  done
  writelog "Configured mail domain: ${DOMAIN}"

  RELAYHOST=$(get_relayhost)
  writelog "Got relayhost: ${RELAYHOST}"

  X500="i$(printf "%llx" "$(date +%s)")"
fi

[ -e "/etc/grommunio-common/ssl" ] || mkdir -p "/etc/grommunio-common/ssl"

# Configure config.json of admin-web
cat > /etc/grommunio-admin-common/nginx.d/web-config.conf <<EOF
location /config.json {
  alias /etc/grommunio-admin-common/config.json;
}
EOF

# shellcheck source=common/ssl_setup
. "${DATADIR}/common/ssl_setup"

if [ "${SETUP_MODE}" = "fresh" ] ; then

  choose_ssl_install_type() {

    writelog "Dialog: ssl installation type"
    SSL_INSTALL_TYPE=$(dialog --no-mouse --colors --backtitle "grommunio Setup" --title "grommunio Setup: TLS" \
                             --menu "Choose your TLS setup type" 0 0 0 \
                             "0" "Create self-signed certificate" \
                             "1" "Create own CA and certificate" \
                             "2" "Import an existing TLS certificate from files" \
                             "3" "Automatically generate Let's Encrypt certificate"  3>&1 1>&2 2>&3)
    dialog_exit $?

  }

  choose_ssl_install_type
  writelog "Selected TLS installation type: ${SSL_INSTALL_TYPE}"

  SSL_COUNTRY="XX"
  SSL_STATE="XX"
  SSL_LOCALITY="X"
  SSL_ORG="grommunio Appliance"
  SSL_OU="IT"
  SSL_EMAIL="admin@${DOMAIN}"
  SSL_DAYS=30
  SSL_PASS=$(randpw)

  choose_ssl_fullca(){

    writelog "Dialog: data for Full CA"
    dialog --no-mouse --colors --backtitle "grommunio Setup" --title "TLS certificate (Full CA)" --ok-label "Submit" \
           --form "Enter TLS related data" 0 0 0 \
           "Country:        " 1 1 "${SSL_COUNTRY}"      1 17 25 0 \
           "State:          " 2 1 "${SSL_STATE}"        2 17 25 0 \
           "Locality:       " 3 1 "${SSL_LOCALITY}"     3 17 25 0 \
           "Organization:   " 4 1 "${SSL_ORG}"          4 17 25 0 \
           "Org Unit:       " 5 1 "${SSL_OU}"           5 17 25 0 \
           "E-Mail:         " 6 1 "${SSL_EMAIL}"        6 17 25 0 \
           "Validity (days):" 7 1 "${SSL_DAYS}"         7 17 25 0 2>"${TMPF}"
    dialog_exit $?

  }

  choose_ssl_selfprovided(){

    writelog "Dialog: data for self-provided TLS cert"
    dialog --no-mouse --colors --backtitle "grommunio Setup" --title "TLS certificate (self-provided)" --ok-label "Submit" \
           --form "Enter the paths to the TLS certificates" 0 0 0 \
           "PEM encoded certificate bundle:  " 1 1 "${SSL_BUNDLE}"   1 35 80 0 \
           "PEM encoded private key:         " 2 1 "${SSL_KEY}"      2 35 80 0 2>"${TMPF}"
    dialog_exit $?

  }

  set_letsencryptmail(){

    writelog "Dialog: Let's Encrypt"
    dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "TLS certificate (Let's Encrypt)" --cr-wrap --inputbox \
"Specify an email adress that Let's Encrypt can contact for when there is an issue with the certificates

Example: ${SSL_EMAIL}" 0 0 "${SSL_EMAIL}" 3>&1 1>&2 2>&3
    dialog_exit $?

  }

  choose_ssl_letsencrypt(){

    writelog "Dialog: Let's Encrypt domains"
  	LE_TERMS_URL=$(curl -Lsk https://acme-v02.api.letsencrypt.org/directory | grep termsOfService | sed 's#\(.*\)\(https://.*\)\",#\2#')
    if [ "${FQDN}" = "${DOMAIN}" ]; then
      dialog --no-mouse --colors --backtitle "grommunio Setup" --title "TLS certificate (Let's Encrypt)" --ok-label "Submit" \
             --checklist "Choose the Let's Encrypt certificates to request.\nBy requesting certificates from Let's Encrypt, you agree to the terms of service at ${LE_TERMS_URL}.\nThe DNS records should be set accordingly before proceeding."  0 0  0 \
             "${DOMAIN}"              "recommended" on  \
             "autodiscover.${DOMAIN}" "recommended" on  \
             "mail.${DOMAIN}"         "optional"    off 2>"${TMPF}"
    else
      if [ "${FQDN}" = "mail.${DOMAIN}" ]; then
        dialog --no-mouse --colors --backtitle "grommunio Setup" --title "TLS certificate (Let's Encrypt)" --ok-label "Submit" \
               --checklist "Choose the Let's Encrypt certificates to request.\nBy requesting certificates from Let's Encrypt, you agree to the terms of service at ${LE_TERMS_URL}.\nThe DNS records should be set accordingly before proceeding."  0 0  0 \
               "${DOMAIN}"              "recommended" on  \
               "${FQDN}"                "recommended" on  \
               "autodiscover.${DOMAIN}" "recommended" off 2>"${TMPF}"
      else
        dialog --no-mouse --colors --backtitle "grommunio Setup" --title "TLS certificate (Let's Encrypt)" --ok-label "Submit" \
               --checklist "Choose the Let's Encrypt certificates to request.\nBy requesting certificates from Let's Encrypt, you agree to the terms of service at ${LE_TERMS_URL}.\nThe DNS records should be set accordingly before proceeding."  0 0  0 \
               "${DOMAIN}"              "recommended" on  \
               "autodiscover.${DOMAIN}" "recommended" on  \
               "${FQDN}"                "recommended" on  \
               "mail.${DOMAIN}"         "optional"    off 2>"${TMPF}"
      fi
    fi
    dialog_exit $?

  }

  RETCMD=1
  if [ "${SSL_INSTALL_TYPE}" = "0" ]; then
    clear
    if ! selfcert; then
      dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "TLS certificate (self-signed)" --msgbox "Certificate generation not successful. See ${LOGFILE}.\nContinue installation or press ESC to abort setup." 0 0
      dialog_exit $?
    fi
  elif [ "${SSL_INSTALL_TYPE}" = "1" ]; then
    while [ -z "${SSL_COUNTRY}" ] || [ -z "${SSL_STATE}" ] || [ -z "${SSL_LOCALITY}" ] || [ -z "${SSL_ORG}" ] || [ -z "${SSL_OU}" ] || [ -z "${SSL_EMAIL}" ] || [ -z "${SSL_DAYS}" ] || [ "${RETCMD}" = "1" ] ; do
      choose_ssl_fullca
      RETCMD=0
    done
    SSL_COUNTRY=$(sed -n '1{p;q}' "${TMPF}")
    SSL_STATE=$(sed -n '2{p;q}' "${TMPF}")
    SSL_LOCALITY=$(sed -n '3{p;q}' "${TMPF}")
    SSL_ORG=$(sed -n '4{p;q}' "${TMPF}")
    SSL_OU=$(sed -n '5{p;q}' "${TMPF}")
    SSL_EMAIL=$(sed -n '6{p;q}' "${TMPF}")
    SSL_DAYS=$(sed -n '7{p;q}' "${TMPF}")
    fullca
    writelog "TLS configuration: Country: ${SSL_COUNTRY} State: ${SSL_STATE} Locality: ${SSL_LOCALITY} Organization: ${SSL_ORG} Org Unit: ${SSL_OU} E-Mail: ${SSL_EMAIL} Validity (days): ${SSL_DAYS}"
  elif [ "${SSL_INSTALL_TYPE}" = "2" ]; then
    choose_ssl_selfprovided
    SSL_BUNDLE=$(sed -n '1{p;q}' "${TMPF}")
    SSL_KEY=$(sed -n '2{p;q}' "${TMPF}")
    while [ ${RETCMD} -ne 0 ]; do
      owncert
      RETCMD=$?
    done
    writelog "TLS configuration: Bundle: ${SSL_BUNDLE} Key: ${SSL_KEY}"
  elif [ "${SSL_INSTALL_TYPE}" = "3" ]; then
    choose_ssl_letsencrypt
    SSL_DOMAINS=$(sed 's# #,#g' "${TMPF}" | tr '[:upper:]' '[:lower:]')
    while [ -z "${SSL_DOMAINS}" ] ; do
      dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "TLS certificate (Let's encrypt)" --msgbox "No valid domains have been chosen for the TLS certificates. Select valid domains." 0 0
      dialog_exit $?
      choose_ssl_letsencrypt
      SSL_DOMAINS=$(sed 's# #,#g' "${TMPF}" | tr '[:upper:]' '[:lower:]')
    done

    SSL_EMAIL=$(set_letsencryptmail)
    while ! [[ ${SSL_EMAIL} =~ ^.*\@.*$ ]] ; do
      dialog --no-mouse --clear --colors --backtitle "grommunio Setup" --title "TLS certificate (Let's Encrypt)" --msgbox "The provided email address is invalid. Enter a valid email address." 0 0
      SSL_EMAIL=$(set_letsencryptmail)
      dialog_exit $?
    done
    letsencrypt
    writelog "TLS configuration: Let's Encrypt ${SSL_EMAIL}"
  fi
else
  writelog "Reconfigure mode: preserving existing TLS certificates (${SSL_BUNDLE_T})."
fi

# Base postfix recipient restrictions (the archive role extends these and the
# removal path resets them back to this value).
CORE_RCPT_RESTRICTIONS="permit_sasl_authenticated,permit_mynetworks,reject_unknown_recipient_domain,reject_non_fqdn_hostname,reject_non_fqdn_sender,reject_non_fqdn_recipient,reject_unauth_destination,reject_unauth_pipelining"

# ---------------------------------------------------------------------------
# Reconcile optional roles: remove the ones that were deselected (data kept).
# ---------------------------------------------------------------------------
for r in ${ALL_ROLES} ; do
  if [ "$(role_action "$r")" = "remove" ] ; then
    remove_role "$r"
  fi
done

# Chat and meet are configured before the core services (matching the original
# ordering); files/office/archive are configured afterwards.
if [ "$FT_CHAT" == "true" ] ; then
  setup_role_chat
fi

if [ "$FT_MEET" == "true" ] ; then
  setup_role_meet
fi

MEMCACHE_UNIT=$(get_memcache_unit)
writelog "Memcache backend unit: ${MEMCACHE_UNIT}"

progress 0
writelog "Config stage: zypper install of possible missing dependencies"
# Facilitate setup.sh being run from a pristine Leap (i.e. without grommunio-iso)
zypper install -y mariadb php-fpm cyrus-sasl-saslauthd cyrus-sasl-plain postfix postfix-mysql >>"${LOGFILE}" 2>&1

progress 10
writelog "Config stage: enable all services"
systemctl enable "${MEMCACHE_UNIT}" gromox-delivery.service gromox-event.service \
  gromox-http.service gromox-imap.service gromox-midb.service gromox-pop3.service \
  gromox-delivery-queue.service gromox-timer.service gromox-zcore.service grommunio-antispam.service \
  php-fpm.service nginx.service grommunio-admin-api.service saslauthd.service mariadb >>"${LOGFILE}" 2>&1

progress 20
writelog "Config stage: start db"
systemctl start mariadb >>"${LOGFILE}" 2>&1

writelog "Config stage: put php files into place"
PHP_DIR=$(get_php_fpm_dir)
if [ -n "${PHP_DIR}" ]; then
  if [ -e "${PHP_DIR}/fpm/php-fpm.conf.default" ] ; then
    mv "${PHP_DIR}/fpm/php-fpm.conf.default" "${PHP_DIR}/fpm/php-fpm.conf"
  fi
  cp -f /usr/share/gromox/fpm-gromox.conf.sample "${PHP_DIR}/fpm/php-fpm.d/gromox.conf"
fi

writelog "Config stage: gromox config"
setconf /etc/gromox/gromox.cfg http_remote_host_hdr X-Real-IP
setconf /etc/gromox/http.cfg listen_port 10080
setconf /etc/gromox/http.cfg http_support_ssl true
setconf /etc/gromox/http.cfg listen_ssl_port 10443
setconf /etc/gromox/http.cfg host_id ${FQDN}

setconf /etc/gromox/smtp.cfg listen_port 24

writelog "Config stage: pam config"
progress 30
# Keep the original pam config the first time around only, so re-runs do not
# overwrite the genuine backup with an already-modified file.
[ -e /etc/pam.d/smtp.save ] || cp /etc/pam.d/smtp /etc/pam.d/smtp.save
cat > /etc/pam.d/smtp <<EOF
#%PAM-1.0
auth required pam_gromox.so
account required pam_permit.so service=smtp
EOF

writelog "Config stage: database creation"
progress 40
if [ "${MYSQL_INSTALL_TYPE}" != "2" ] ; then
  ensure_db localhost "${MYSQL_USER}" "${MYSQL_PASS}" "${MYSQL_DB}"
fi

writelog "Config stage: database configuration"
setconf /etc/gromox/mysql_adaptor.cfg mysql_username "${MYSQL_USER}"
setconf /etc/gromox/mysql_adaptor.cfg mysql_password "${MYSQL_PASS}"
setconf /etc/gromox/mysql_adaptor.cfg mysql_dbname "${MYSQL_DB}"
if [ "$MYSQL_INSTALL_TYPE" = 1 ]; then
setconf /etc/gromox/mysql_adaptor.cfg schema_upgrade "host:${FQDN}"
fi
if [ "${MYSQL_INSTALL_TYPE}" = "2" ]; then
setconf /etc/gromox/mysql_adaptor.cfg mysql_host "${MYSQL_HOST}"
fi

writelog "Config stage: autodiscover configuration"
progress 50
if [ -n "${X500}" ] ; then
cat >/etc/gromox/autodiscover.cfg <<EOF
x500_org_name = ${X500}
EOF
fi

writelog "Config stage: database initialization"
# gromox-dbop -C is not idempotent (fails on an existing schema); use -U to
# upgrade an existing installation.
if [ "${SETUP_MODE}" = "fresh" ] ; then
  gromox-dbop -C >>"${LOGFILE}" 2>&1
else
  gromox-dbop -U >>"${LOGFILE}" 2>&1
fi

cat > /etc/grommunio-admin-api/conf.d/database.yaml <<EOF
DB:
  host: '${MYSQL_HOST}'
  user: '${MYSQL_USER}'
  pass: '${MYSQL_PASS}'
  database: '${MYSQL_DB}'
EOF

progress 60
if [ "${SETUP_MODE}" = "fresh" ] ; then
  writelog "Config stage: admin password set"
  grommunio-admin passwd --password "${ADMIN_PASS}" >>"${LOGFILE}" 2>&1
  rspamadm pw -p "${ADMIN_PASS}" | sed -e 's#^#password = "#' -e 's#$#";#' > /etc/grommunio-antispam/local.d/worker-controller.inc
else
  writelog "Config stage: preserving existing admin and antispam passwords"
fi

writelog "Config stage: gromox tls configuration"
setconf /etc/gromox/http.cfg http_certificate_path "${SSL_BUNDLE_T}"
setconf /etc/gromox/http.cfg http_private_key_path "${SSL_KEY_T}"

setconf /etc/gromox/imap.cfg imap_support_starttls true
setconf /etc/gromox/imap.cfg listen_ssl_port 993
setconf /etc/gromox/imap.cfg imap_certificate_path "${SSL_BUNDLE_T}"
setconf /etc/gromox/imap.cfg imap_private_key_path "${SSL_KEY_T}"

setconf /etc/gromox/pop3.cfg pop3_support_stls true
setconf /etc/gromox/pop3.cfg listen_ssl_port 995
setconf /etc/gromox/pop3.cfg pop3_certificate_path "${SSL_BUNDLE_T}"
setconf /etc/gromox/pop3.cfg pop3_private_key_path "${SSL_KEY_T}"

cat > /etc/grommunio-common/nginx/ssl_certificate.conf <<EOF
ssl_certificate ${SSL_BUNDLE_T};
ssl_certificate_key ${SSL_KEY_T};
EOF
[ -e /etc/grommunio-admin-common/nginx-ssl.conf ] || ln -s /etc/grommunio-common/nginx/ssl_certificate.conf /etc/grommunio-admin-common/nginx-ssl.conf
chown gromox:gromox /etc/grommunio-common/ssl/*

# Domain and X500
writelog "Config stage: gromox domain and x500 configuration"
for SERVICE in http midb zcore imap pop3 smtp delivery ; do
  setconf /etc/gromox/${SERVICE}.cfg default_domain "${DOMAIN}"
done
if [ -n "${X500}" ] ; then
for CFG in midb.cfg zcore.cfg exmdb_local.cfg exmdb_provider.cfg exchange_emsmdb.cfg exchange_nsp.cfg ; do
  setconf "/etc/gromox/${CFG}" x500_org_name "${X500}"
done
fi
chown grommunio:gromoxcf /etc/gromox/*.cfg
chmod 0640 /etc/gromox/*.cfg

writelog "Config stage: postfix configuration"
progress 80

cat > /etc/postfix/grommunio-virtual-mailbox-domains.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT 1 FROM domains WHERE domain_status=0 AND domainname=_utf8mb4'%s' COLLATE utf8mb4_general_ci
EOF

cat > /etc/postfix/grommunio-virtual-mailbox-alias-maps.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT mainname FROM aliases WHERE aliasname=_utf8mb4'%s' COLLATE utf8mb4_general_ci UNION SELECT destination FROM forwards WHERE username=_utf8mb4'%s' COLLATE utf8mb4_general_ci AND forward_type = 1
EOF

cat > /etc/postfix/grommunio-virtual-mailbox-maps.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT 1 FROM users WHERE username=_utf8mb4'%s' COLLATE utf8mb4_general_ci
EOF

cat > /etc/postfix/grommunio-bcc-forwards.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT destination FROM forwards WHERE username=_utf8mb4'%s' COLLATE utf8mb4_general_ci AND forward_type = 0
EOF

postconf -e \
  myhostname="${FQDN}" \
  virtual_mailbox_domains="mysql:/etc/postfix/grommunio-virtual-mailbox-domains.cf" \
  virtual_mailbox_maps="mysql:/etc/postfix/grommunio-virtual-mailbox-maps.cf" \
  virtual_alias_maps="mysql:/etc/postfix/grommunio-virtual-mailbox-alias-maps.cf" \
  recipient_bcc_maps="mysql:/etc/postfix/grommunio-bcc-forwards.cf" \
  unverified_recipient_reject_code=550 \
  virtual_transport="smtp:[::1]:24" \
  relayhost="${RELAYHOST}" \
  inet_interfaces=all \
  smtpd_helo_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_invalid_hostname,reject_non_fqdn_hostname \
  smtpd_sender_restrictions=reject_non_fqdn_sender,permit_sasl_authenticated,permit_mynetworks \
  smtpd_recipient_restrictions="${CORE_RCPT_RESTRICTIONS}" \
  smtpd_data_restrictions=reject_unauth_pipelining \
  smtpd_discard_ehlo_keywords=chunking \
  smtpd_tls_security_level=may \
  smtpd_tls_auth_only=no \
  smtpd_tls_cert_file="${SSL_BUNDLE_T}" \
  smtpd_tls_key_file="${SSL_KEY_T}" \
  smtpd_tls_received_header=yes \
  smtpd_tls_session_cache_timeout=3600s \
  smtpd_use_tls=yes \
  tls_random_source=dev:/dev/urandom \
  smtpd_sasl_auth_enable=yes \
  broken_sasl_auth_clients=yes \
  smtpd_sasl_security_options=noanonymous \
  smtpd_sasl_local_domain=\
  smtpd_milters=inet:localhost:11332 \
  milter_default_action=accept \
  smtp_tls_security_level=may \
  smtp_use_tls=yes \
  milter_protocol=6
postconf -M tlsmgr/unix="tlsmgr unix - - n 1000? 1 tlsmgr"
postconf -M submission/inet="submission inet n - n - - smtpd"
postconf -P submission/inet/syslog_name="postfix/submission"
postconf -P submission/inet/smtpd_tls_security_level=encrypt
postconf -P submission/inet/smtpd_sasl_auth_enable=yes
postconf -P submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject
postconf -P submission/inet/milter_macro_daemon_name=ORIGINATING

writelog "Config stage: postfix enable and restart"
systemctl enable postfix.service >>"${LOGFILE}" 2>&1
systemctl restart postfix.service >>"${LOGFILE}" 2>&1

systemctl enable grommunio-fetchmail.timer >>"${LOGFILE}" 2>&1
systemctl start grommunio-fetchmail.timer >>"${LOGFILE}" 2>&1

writelog "Config stage: open required firewall ports"
{
  firewall-cmd --add-service=https --zone=public --permanent
  firewall-cmd --add-port=25/tcp --zone=public --permanent
  firewall-cmd --add-port=80/tcp --zone=public --permanent
  firewall-cmd --add-port=110/tcp --zone=public --permanent
  firewall-cmd --add-port=143/tcp --zone=public --permanent
  firewall-cmd --add-port=587/tcp --zone=public --permanent
  firewall-cmd --add-port=993/tcp --zone=public --permanent
  firewall-cmd --add-port=995/tcp --zone=public --permanent
  firewall-cmd --add-port=8080/tcp --zone=public --permanent
  firewall-cmd --add-port=8443/tcp --zone=public --permanent
  firewall-cmd --reload
} >>"${LOGFILE}" 2>&1

progress 90
writelog "Config stage: restart all required services"
systemctl restart "${MEMCACHE_UNIT}" nginx.service php-fpm.service gromox-delivery.service \
  gromox-event.service gromox-http.service gromox-imap.service gromox-midb.service \
  gromox-pop3.service gromox-delivery-queue.service gromox-timer.service gromox-zcore.service \
  grommunio-admin-api.service saslauthd.service grommunio-antispam.service >>"${LOGFILE}" 2>&1

if [ "$FT_FILES" == "true" ] ; then
  setup_role_files
fi

if [ "$FT_OFFICE" == "true" ] ; then
  setup_role_office
fi

if [ "$FT_ARCHIVE" == "true" ] ; then
  setup_role_archive
fi

# ---------------------------------------------------------------------------
# Rebuild admin-common config.json from the final set of enabled roles so that
# removed roles disappear and added ones are present.
# ---------------------------------------------------------------------------
build_config_json()
{
  local cfg
  cfg=$(LANG=en_US.UTF-8 jq -n \
    --arg mail "https://${FQDN}/web" \
    --arg rspamd "https://${FQDN}:8443/antispam/" \
    '{mailWebAddress: $mail, rspamdWebAddress: $rspamd}')
  [ "$FT_CHAT" == "true" ]    && cfg=$(echo "${cfg}" | jq --arg u "https://${FQDN}/chat"  '.chatWebAddress = $u')
  [ "$FT_MEET" == "true" ]    && cfg=$(echo "${cfg}" | jq --arg u "https://${FQDN}/meet"  '.videoWebAddress = $u')
  [ "$FT_FILES" == "true" ]   && cfg=$(echo "${cfg}" | jq --arg u "https://${FQDN}/files" '.fileWebAddress = $u')
  [ "$FT_ARCHIVE" == "true" ] && cfg=$(echo "${cfg}" | jq --arg u "https://${FQDN}/archive" '.archiveWebAddress = $u')
  echo "${cfg}" > /etc/grommunio-admin-common/config.json
}
build_config_json
systemctl restart grommunio-admin-api.service

# ---------------------------------------------------------------------------
# Persist state for idempotent future runs.
# ---------------------------------------------------------------------------
state_set FQDN "${FQDN}"
state_set DOMAIN "${DOMAIN}"
state_set X500 "${X500}"
state_set RELAYHOST "${RELAYHOST}"
state_set MYSQL_HOST "${MYSQL_HOST}"
state_set MYSQL_USER "${MYSQL_USER}"
state_set MYSQL_PASS "${MYSQL_PASS}"
state_set MYSQL_DB "${MYSQL_DB}"
state_set MYSQL_INSTALL_TYPE "${MYSQL_INSTALL_TYPE}"
[ -n "${SSL_INSTALL_TYPE}" ] && state_set SSL_INSTALL_TYPE "${SSL_INSTALL_TYPE}"
for r in ${ALL_ROLES} ; do
  u=$(echo "$r" | tr '[:lower:]' '[:upper:]')
  eval "fv=\${FT_${u}}"
  state_set "FT_${u}" "${fv}"
done

# Mark the installation as fully completed only now, at the very end, so an
# aborted run is retried as fresh rather than as a broken reconfigure.
echo "# Do not delete this file unless you know what you do!" > /etc/grommunio-common/setup_done

progress 100
writelog "Config stage: completed"
setup_done

exit 0
