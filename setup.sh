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
TMPF=$(mktemp /tmp/grommunio-setup.XXXXXXXX)

writelog "Welcome dialog"
dialog_welcome

if [ -e "/etc/grommunio-common/setup_done" ] ; then
DELCONFIRM=$(dialog --no-mouse --colors --backtitle "grommunio Setup" --title "grommunio Setup already completed" --cr-wrap --inputbox \
'grommunio Setup was already run.

You can abort or delete all data and setup everything from scratch. If so, confirm this operation by typing "removealldata" to continue.

\Z1If you continue, ALL data wil be removed!\Z1' \
0 0 3>&1 1>&2 2>&3)
dialog_exit $?

if [ "${DELCONFIRM}" != "removealldata" ] ; then
  writelog "Aborted deletion after detected existing installation"
  exit 0
else
  writelog "Deleting existing installation after confirmation"
  echo "drop database grommunio;" | mysql
  rm -rf /var/lib/gromox/user/* /var/lib/gromox/domain/* /etc/grommunio-common/ssl/* /etc/grommunio-common/setup_done
fi
fi

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

unset MYSQL_DB
unset MYSQL_HOST
unset MYSQL_USER
unset MYSQL_PASS
unset CHAT_MYSQL_DB
unset CHAT_MYSQL_HOST
unset CHAT_MYSQL_USER
unset CHAT_MYSQL_PASS
unset CHAT_ADMIN_PASS
unset FILES_MYSQL_DB
unset FILES_MYSQL_HOST
unset FILES_MYSQL_USER
unset FILES_MYSQL_PASS
unset FILES_ADMIN_PASS
unset ARCHIVE_MYSQL_DB
unset ARCHIVE_MYSQL_HOST
unset ARCHIVE_MYSQL_USER
unset ARCHIVE_MYSQL_PASS
unset ARCHIVE_ADMIN_PASS
unset ARCHIVE_AUDIT_PASS
unset OFFICE_MYSQL_DB
unset OFFICE_MYSQL_HOST
unset OFFICE_MYSQL_USER
unset OFFICE_MYSQL_PASS
unset ADMIN_PASS
unset FQDN
unset DOMAIN
unset X500
unset SSL_BUNDLE
unset SSL_KEY
unset REPO_USER
unset REPO_PASS
unset REPO_PATH

get_features

set_repo() {

  writelog "Dialog: repository"
  dialog --no-mouse --colors --backtitle "grommunio Setup" --title "Repository configuration" --ok-label "Submit" \
         --form "\nIf you have a subscription, enter your credentials here.\n\nLeave empty for community (unsupported) repositories." 0 0 0 \
  "Subscription username:    " 1 1 "${REPO_USER}"         1 25 25 0 \
  "Subscription password:    " 2 1 "${REPO_PASS}"         2 25 25 0 2>"${TMPF}"
  dialog_exit $?

}

# Check if we already have credentials populated by any other means.
if [[ -e /etc/grommunio-admin-common/license/credentials.txt ]]; then
  CREDENTIALS=$(cat /etc/grommunio-admin-common/license/credentials.txt)
  if grommunio-repo supported > /dev/null 2>&1; then
    REPO_USER="${CREDENTIALS%:*}"
    REPO_PASS="${CREDENTIALS#*:}"
  fi
fi

set_repo
REPO_USER=$(sed -n '1{p;q}' "${TMPF}")
REPO_PASS=$(sed -n '2{p;q}' "${TMPF}")
writelog "Installation / update of packages"
# shellcheck source=common/repo
PACKAGES="gromox grommunio-admin-api grommunio-admin-web grommunio-antispam \
  grommunio-common grommunio-web grommunio-sync grommunio-dav \
  mariadb php-fpm cyrus-sasl-saslauthd cyrus-sasl-plain postfix jq"
PACKAGES="$PACKAGES $FT_PACKAGES"
. "${DATADIR}/common/repo"
setup_repo


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
      echo "drop database if exists ${MYSQL_DB}; create database ${MYSQL_DB}; grant all on ${MYSQL_DB}.* to '${MYSQL_USER}'@'${MYSQL_HOST}' identified by '${MYSQL_PASS}';" | mysql >/dev/null 2>&1
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
writelog "Configured mail domain: ${FQDN}"

RELAYHOST=$(get_relayhost)
writelog "Got relayhost: ${RELAYHOST}"

X500="i$(printf "%llx" "$(date +%s)")"

[ -e "/etc/grommunio-common/ssl" ] || mkdir -p "/etc/grommunio-common/ssl"

# Configure config.json of admin-web
cat > /etc/grommunio-admin-common/nginx.d/web-config.conf <<EOF
location /config.json {
  alias /etc/grommunio-admin-common/config.json;
}
EOF

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

# shellcheck source=common/ssl_setup
. "${DATADIR}/common/ssl_setup"
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

LANG="en_US.UTF-8" echo "{ \"mailWebAddress\": \"https://${FQDN}/web\", \"rspamdWebAddress\": \"https://${FQDN}:8443/antispam/\" }" | jq > /tmp/config.json

if [ "$FT_CHAT" == "true" ] ; then

  systemctl stop grommunio-chat
  CHAT_MYSQL_HOST="localhost"
  CHAT_MYSQL_USER="grochat"
  CHAT_MYSQL_PASS=$(randpw)
  CHAT_MYSQL_DB="grochat"
  CHAT_CONFIG="/etc/grommunio-chat/config.json"
  set_chat_mysql_param
  if [ "${CHAT_MYSQL_HOST}" == "localhost" ] ; then
    echo "drop database if exists ${CHAT_MYSQL_DB}; \
          create database ${CHAT_MYSQL_DB}; \
          grant all on ${CHAT_MYSQL_DB}.* to '${CHAT_MYSQL_USER}'@'${CHAT_MYSQL_HOST}' identified by '${CHAT_MYSQL_PASS}';" | mysql >/dev/null 2>&1
  else
    echo "drop database if exists ${CHAT_MYSQL_DB}; \
          create database ${CHAT_MYSQL_DB};" | mysql -h"${CHAT_MYSQL_HOST}" -u"${CHAT_MYSQL_USER}" -p"${CHAT_MYSQL_PASS}" "${CHAT_MYSQL_DB}" >/dev/null 2>&1
  fi

  CHAT_DB_CON="${CHAT_MYSQL_USER}:${CHAT_MYSQL_PASS}@tcp\(${CHAT_MYSQL_HOST}:3306\)\/${CHAT_MYSQL_DB}?charset=utf8mb4,utf8\&readTimeout=30s\&writeTimeout=30s"
  sed -i 's#^.*"DataSource":.*#        "DataSource": "'${CHAT_DB_CON}'",#g' "${CHAT_CONFIG}"
  sed -i 's#^.*"DriverName": "postgres".*#        "DriverName": "mysql",#g' "${CHAT_CONFIG}"
  sed -i 's#^.*"EnableAPIUserDeletion":.*#        "EnableAPIUserDeletion": true,#g' "${CHAT_CONFIG}"
  sed -i 's|"SiteURL": "",|"SiteURL": "https://'${FQDN}'/chat",|g' "${CHAT_CONFIG}"
  touch "/var/log/grommunio-chat/mattermost.log"
  chown -R grochat:grochat "/etc/grommunio-chat/" "/usr/share/grommunio-chat/logs" "/usr/share/grommunio-chat/config" "/var/log/grommunio-chat" "/var/lib/grommunio-chat/"
  chmod 644 ${CHAT_CONFIG}
  systemctl enable grommunio-chat
  systemctl restart grommunio-chat
  dialog_chat_adminpass
  # wait for the grommunio-chat unix socket, sometimes a second restart required for bind (db population)
  if ! [ -e "/var/tmp/grommunio-chat_local.socket" ] ; then
    systemctl restart grommunio-chat
    for n in $(seq 1 30) ; do
      if [ -e "/var/tmp/grommunio-chat_local.socket" ] ; then
        writelog "chat socket /var/tmp/grommunio-chat_local.socket appeared after $((n*3)) seconds."
        break
      fi
      sleep 3
    done
  fi
  pushd /usr/share/grommunio-chat/ || return
    MMCTL_LOCAL_SOCKET_PATH=/var/tmp/grommunio-chat_local.socket bin/grommunio-chat-ctl --local user create --email admin@localhost --username admin --password "${CHAT_ADMIN_PASS}" --system-admin >>"${LOGFILE}" 2>&1
  popd || return

  if [ "${SSL_INSTALL_TYPE}" = "0" ] || [ "${SSL_INSTALL_TYPE}" = "1" ] ; then

cat > /etc/grommunio-admin-api/conf.d/chat.yaml <<EOCHAT
chat:
  connection:
    login_id: admin
    password: '${CHAT_ADMIN_PASS}'
    url: ${FQDN}
    basepath: /chat/api/v4
    port: 443
    scheme: https
    verify: False
EOCHAT

  else

cat > /etc/grommunio-admin-api/conf.d/chat.yaml <<EOVCHAT
chat:
  connection:
    login_id: admin
    password: '${CHAT_ADMIN_PASS}'
    url: ${FQDN}
    basepath: /chat/api/v4
    port: 443
    scheme: https
    verify: False
EOVCHAT

  fi

  chmod 640 ${CHAT_CONFIG}
  jq '.chatWebAddress |= "https://'${FQDN}'/chat"' /tmp/config.json > /tmp/config-new.json
  mv /tmp/config-new.json /tmp/config.json

fi

if [ "$FT_MEET" == "true" ] ; then
  writelog "Config feature meet: Starting to setup meet."

  . "${DATADIR}/parts/grommunio-meet.sh"

  jq '.videoWebAddress |= "https://'${FQDN}'/meet"' /tmp/config.json > /tmp/config-new.json
  mv /tmp/config-new.json /tmp/config.json

  writelog "Config feature meet: Meet setup finished."
fi

progress 0
writelog "Config stage: zypper install of possible missing dependencies"
# Facilitate setup.sh being run from a pristine Leap (i.e. without grommunio-iso)
zypper install -y mariadb php-fpm cyrus-sasl-saslauthd cyrus-sasl-plain postfix postfix-mysql >>"${LOGFILE}" 2>&1

progress 10
writelog "Config stage: enable all services"
systemctl enable redis@grommunio.service gromox-delivery.service gromox-event.service \
  gromox-http.service gromox-imap.service gromox-midb.service gromox-pop3.service \
  gromox-delivery-queue.service gromox-timer.service gromox-zcore.service grommunio-antispam.service \
  php-fpm.service nginx.service grommunio-admin-api.service saslauthd.service mariadb >>"${LOGFILE}" 2>&1

progress 20
writelog "Config stage: start db"
systemctl start mariadb >>"${LOGFILE}" 2>&1

writelog "Config stage: put php files into place"
if [ -d /etc/php8 ]; then
  if [ -e "/etc/php8/fpm/php-fpm.conf.default" ] ; then
    mv /etc/php8/fpm/php-fpm.conf.default /etc/php8/fpm/php-fpm.conf
  fi
  cp -f /usr/share/gromox/fpm-gromox.conf.sample /etc/php8/fpm/php-fpm.d/gromox.conf
elif [ -d /etc/php7 ]; then
  if [ -e "/etc/php7/fpm/php-fpm.conf.default" ] ; then
    mv /etc/php7/fpm/php-fpm.conf.default /etc/php7/fpm/php-fpm.conf
  fi
  cp -f /usr/share/gromox/fpm-gromox.conf.sample /etc/php7/fpm/php-fpm.d/gromox.conf
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
cp /etc/pam.d/smtp /etc/pam.d/smtp.save
cat > /etc/pam.d/smtp <<EOF
#%PAM-1.0
auth required pam_gromox.so
account required pam_permit.so service=smtp
EOF

writelog "Config stage: database creation"
progress 40
echo "create database grommunio; grant all on grommunio.* to 'grommunio'@'localhost' identified by '${MYSQL_PASS}';" | mysql
echo "# Do not delete this file unless you know what you do!" > /etc/grommunio-common/setup_done

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
cat >/etc/gromox/autodiscover.cfg <<EOF
x500_org_name = ${X500}
EOF

writelog "Config stage: database initialization"
gromox-dbop -C >>"${LOGFILE}" 2>&1

cat > /etc/grommunio-admin-api/conf.d/database.yaml <<EOF
DB:
  host: '${MYSQL_HOST}'
  user: '${MYSQL_USER}'
  pass: '${MYSQL_PASS}'
  database: '${MYSQL_DB}'
EOF

writelog "Config stage: admin password set"
progress 60
grommunio-admin passwd --password "${ADMIN_PASS}" >>"${LOGFILE}" 2>&1

rspamadm pw -p "${ADMIN_PASS}" | sed -e 's#^#password = "#' -e 's#$#";#' > /etc/grommunio-antispam/local.d/worker-controller.inc

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
ln -s /etc/grommunio-common/nginx/ssl_certificate.conf /etc/grommunio-admin-common/nginx-ssl.conf
chown gromox:gromox /etc/grommunio-common/ssl/*

# Domain and X500
writelog "Config stage: gromox domain and x500 configuration"
for SERVICE in http midb zcore imap pop3 smtp delivery ; do
  setconf /etc/gromox/${SERVICE}.cfg default_domain "${DOMAIN}"
done
for CFG in midb.cfg zcore.cfg exmdb_local.cfg exmdb_provider.cfg exchange_emsmdb.cfg exchange_nsp.cfg ; do
  setconf "/etc/gromox/${CFG}" x500_org_name "${X500}"
done
chown grommunio:gromoxcf /etc/gromox/*.cfg
chmod 0640 /etc/gromox/*.cfg

writelog "Config stage: postfix configuration"
progress 80

cat > /etc/postfix/grommunio-virtual-mailbox-domains.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT 1 FROM domains WHERE domain_status=0 AND domainname='%s'
EOF

cat > /etc/postfix/grommunio-virtual-mailbox-alias-maps.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT mainname FROM aliases WHERE aliasname='%s' UNION select destination FROM forwards WHERE username='%s' AND forward_type = 1
EOF

cat > /etc/postfix/grommunio-virtual-mailbox-maps.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT 1 FROM users WHERE username='%s'
EOF

cat > /etc/postfix/grommunio-bcc-forwards.cf <<EOF
user = ${MYSQL_USER}
password = ${MYSQL_PASS}
hosts = ${MYSQL_HOST}
dbname = ${MYSQL_DB}
query = SELECT destination FROM forwards WHERE username='%s' AND forward_type = 0
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
  smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unknown_recipient_domain,reject_non_fqdn_hostname,reject_non_fqdn_sender,reject_non_fqdn_recipient,reject_unauth_destination,reject_unauth_pipelining \
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
systemctl restart redis@grommunio.service nginx.service php-fpm.service gromox-delivery.service \
  gromox-event.service gromox-http.service gromox-imap.service gromox-midb.service \
  gromox-pop3.service gromox-delivery-queue.service gromox-timer.service gromox-zcore.service \
  grommunio-admin-api.service saslauthd.service grommunio-antispam.service >>"${LOGFILE}" 2>&1

if [ "$FT_FILES" == "true" ] ; then

  FILES_MYSQL_HOST="localhost"
  FILES_MYSQL_USER="grofiles"
  FILES_MYSQL_PASS=$(randpw)
  FILES_MYSQL_DB="grofiles"
  set_files_mysql_param
  if [ "${FILES_MYSQL_HOST}" == "localhost" ] ; then
    echo "drop database if exists ${FILES_MYSQL_DB}; \
          create database ${FILES_MYSQL_DB}; \
          grant all on ${FILES_MYSQL_DB}.* to '${FILES_MYSQL_USER}'@'${FILES_MYSQL_HOST}' identified by '${FILES_MYSQL_PASS}';" | mysql >/dev/null 2>&1
  else
    echo "drop database if exists ${FILES_MYSQL_DB}; \
          create database ${FILES_MYSQL_DB};" | mysql -h"${FILES_MYSQL_HOST}" -u"${FILES_MYSQL_USER}" -p"${FILES_MYSQL_PASS}" "${FILES_MYSQL_DB}" >/dev/null 2>&1
  fi
  dialog_files_adminpass

cat > /usr/share/grommunio-files/config/config.php <<'EOFILESCONF'
<?php
$CONFIG = array (
  'overwritewebroot' => '/files',
  'datadirectory' => '/var/lib/grommunio-files/data',
  'logfile' => '/var/log/grommunio-files/files.log',
  'theme' => 'theme-grommunio',
  'logtimezone' => 'UTC',
  'apps_paths' =>
  array (
    0 =>
    array (
      'path' => '/usr/share/grommunio-files/apps',
      'url' => '/apps',
      'writable' => false,
    ),
    1 =>
    array (
      'path' => '/var/lib/grommunio-files/apps-external',
      'url' => '/apps-external',
      'writable' => true,
    ),
  ),
  'memcache.local' => '\\OC\\Memcache\\Redis',
  'filelocking.enabled' => true,
  'memcache.locking' => '\\OC\\Memcache\\Redis',
  'upgrade.disable-web' => true,
  'upgrade.automatic-app-update' => true,
  'updater.server.url' => '127.0.0.1',
  'integrity.check.disabled' => false,
);
EOFILESCONF

  pushd /usr/share/grommunio-files
    rm -rf data/admin >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n maintenance:install --database=mysql --database-name=${FILES_MYSQL_DB} --database-user=${FILES_MYSQL_USER} --database-pass=${FILES_MYSQL_PASS} --admin-user=admin --admin-pass="${FILES_ADMIN_PASS}" --data-dir=/var/lib/grommunio-files/data >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set trusted_domains 1 --value="${FQDN}" >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set trusted_domains 2 --value="${DOMAIN}" >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set trusted_domains 3 --value="mail.${DOMAIN}" >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n app:enable user_external >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set user_backends 0 arguments 0 --value="https://${FQDN}/dav" >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set user_backends 0 class --value='\OCA\UserExternal\BasicAuth' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n app:enable onlyoffice >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set integrity.check.disabled --type boolean --value true >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config name 'grommunio Files' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config logo /usr/share/grommunio-files/logo.svg >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config logoheader /usr/share/grommunio-files/logo.svg >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config favicon /usr/share/grommunio-files/favicon.svg >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config background /usr/share/grommunio-files/background.jpg >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config disable-user-theming true >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config slogan 'filesync & sharing' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config url 'https://grommunio.com' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n theming:config color '#0072B0' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set mail_from_address --value='admin' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set mail_smtpmode --value='sendmail' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set mail_sendmailmode --value='smtp' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set mail_domain --value="${DOMAIN}" >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set mail_smtphost --value='localhost' >>"${LOGFILE}" 2>&1
    sudo -u grofiles ./occ -q -n config:system:set mail_smtpport --value='25' >>"${LOGFILE}" 2>&1
  popd || return

  systemctl enable grommunio-files-cron.service >>"${LOGFILE}" 2>&1
  systemctl enable grommunio-files-cron.timer >>"${LOGFILE}" 2>&1
  systemctl start grommunio-files-cron.timer >>"${LOGFILE}" 2>&1

  jq '.fileWebAddress |= "https://'${FQDN}'/files"' /tmp/config.json > /tmp/config-new.json
  mv /tmp/config-new.json /tmp/config.json

fi

if [ "$FT_OFFICE" == "true" ] ; then
  writelog "Config stage: install office"
  OFFICE_MYSQL_HOST="localhost"
  OFFICE_MYSQL_USER="groffice"
  OFFICE_MYSQL_PASS=$(randpw)
  OFFICE_MYSQL_DB="groffice"
  set_office_mysql_param
  if [ "${OFFICE_MYSQL_HOST}" == "localhost" ] ; then
    echo "drop database if exists ${OFFICE_MYSQL_DB}; \
          create database ${OFFICE_MYSQL_DB}; \
          grant all on ${OFFICE_MYSQL_DB}.* to '${OFFICE_MYSQL_USER}'@'${OFFICE_MYSQL_HOST}' identified by '${OFFICE_MYSQL_PASS}';" | mysql >/dev/null 2>&1
  else
    echo "drop database if exists ${OFFICE_MYSQL_DB}; \
          create database ${OFFICE_MYSQL_DB};" | mysql -h"${OFFICE_MYSQL_HOST}" -u"${OFFICE_MYSQL_USER}" -p"${OFFICE_MYSQL_PASS}" "${OFFICE_MYSQL_DB}" >/dev/null 2>&1
  fi

  sed -i -e "/^CREATE DATABASE/d" -e "/^USE/d" /usr/libexec/grommunio-office/server/schema/mysql/createdb.sql
  mysql -h"${OFFICE_MYSQL_HOST}" -u"${OFFICE_MYSQL_USER}" -p"${OFFICE_MYSQL_PASS}" "${OFFICE_MYSQL_DB}" < /usr/libexec/grommunio-office/server/schema/mysql/createdb.sql

  jq '.services.CoAuthoring.sql.dbHost |= "'${OFFICE_MYSQL_HOST}'" | .services.CoAuthoring.sql.dbName |= "'${OFFICE_MYSQL_DB}'" | .services.CoAuthoring.sql.dbUser |= "'${OFFICE_MYSQL_USER}'" | .services.CoAuthoring.sql.dbPass |= "'${OFFICE_MYSQL_PASS}'"' /etc/grommunio-office/default.json > /tmp/default.json
  mv /tmp/default.json /etc/grommunio-office/default.json

  systemctl enable rabbitmq-server.service >>"${LOGFILE}" 2>&1
  systemctl start rabbitmq-server.service >>"${LOGFILE}" 2>&1
  systemctl start ds-themegen.service ds-fontgen.service  >>"${LOGFILE}" 2>&1
  systemctl enable ds-converter.service ds-docservice.service >>"${LOGFILE}" 2>&1
  systemctl start ds-converter.service ds-docservice.service >>"${LOGFILE}" 2>&1
  pushd /usr/share/grommunio-files || return
    sudo -u grofiles ./occ -q -n config:system:set --type boolean --value="true" csrf.disabled
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice DocumentServerUrl --value="https://${FQDN}/office/"
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice DocumentServerInternalUrl --value="https://${FQDN}/office/"
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice StorageUrl --value="https://${FQDN}/files/"
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice customizationChat --value=false
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice customizationCompactHeader --value=true
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice customizationFeedback --value=false
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice customizationToolbarNoTabs --value=true
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice preview --value=false
    sudo -u grofiles ./occ -q -n config:app:set onlyoffice sameTab --value=true
  popd || return
fi

if [ "$FT_ARCHIVE" == "true" ] ; then
  writelog "Config stage: install archive"

  ARCHIVE_MYSQL_HOST="localhost"
  ARCHIVE_MYSQL_USER="groarchive"
  ARCHIVE_MYSQL_PASS=$(randpw)
  ARCHIVE_MYSQL_DB="groarchive"
  set_archive_mysql_param
  if [ "${ARCHIVE_MYSQL_HOST}" == "localhost" ] ; then
    echo "drop database if exists ${ARCHIVE_MYSQL_DB}; \
          create database ${ARCHIVE_MYSQL_DB}; \
          grant all on ${ARCHIVE_MYSQL_DB}.* to '${ARCHIVE_MYSQL_USER}'@'${ARCHIVE_MYSQL_HOST}' identified by '${ARCHIVE_MYSQL_PASS}';" | mysql >/dev/null 2>&1
  else
    echo "drop database if exists ${ARCHIVE_MYSQL_DB}; \
          create database ${ARCHIVE_MYSQL_DB};" | mysql -h"${ARCHIVE_MYSQL_HOST}" -u"${ARCHIVE_MYSQL_USER}" -p"${ARCHIVE_MYSQL_PASS}" "${ARCHIVE_MYSQL_DB}" >/dev/null 2>&1
  fi

  dialog_archive_adminpass
  dialog_archive_auditpass

  sed -e "s#grommunioArchiveAdmin#${ARCHIVE_ADMIN_PASS}#g" -e "s#grommunioArchiveAuditor#${ARCHIVE_AUDIT_PASS}#g" /usr/share/grommunio-archive/db-mysql.sql | mysql -h"${ARCHIVE_MYSQL_HOST}" -u"${ARCHIVE_MYSQL_USER}" -p"${ARCHIVE_MYSQL_PASS}" "${ARCHIVE_MYSQL_DB}"

  sed -e "s#MYHOSTNAME#${FQDN}#g" -e "s#MYSMTP#${DOMAIN}#g" -e "s/MYSQL_HOSTNAME/${ARCHIVE_MYSQL_HOST}/" -e "s/MYSQL_DATABASE/${ARCHIVE_MYSQL_DB}/" -e "s/MYSQL_PASSWORD/${ARCHIVE_MYSQL_PASS}/" -e "s/MYSQL_USERNAME/${ARCHIVE_MYSQL_USER}/" /etc/grommunio-archive/config-site.dist.php > /etc/grommunio-archive/config-site.php

  echo "/(.*)/   prepend X-Envelope-To: \$1" > /etc/postfix/grommunio-archiver-envelope.cf
  postconf -e "smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,check_recipient_access pcre:/etc/postfix/grommunio-archiver-envelope.cf,reject_unknown_recipient_domain,reject_non_fqdn_hostname,reject_non_fqdn_sender,reject_non_fqdn_recipient,reject_unauth_destination,reject_unauth_pipelining"

  postconf -e "always_bcc=archive@${FQDN}"
  echo "archive@${FQDN} smtp:[127.0.0.1]:2693" > /etc/postfix/transport
  postmap /etc/postfix/transport

  cp -f /etc/grommunio-archive/grommunio-archive.conf.dist /etc/grommunio-archive/grommunio-archive.conf
  chgrp groarchive /etc/grommunio-archive/grommunio-archive.conf
  chmod g=r,o= /etc/grommunio-archive/grommunio-archive.conf
  setconf /etc/grommunio-archive/grommunio-archive.conf mysqluser "${ARCHIVE_MYSQL_USER}" 0
  setconf /etc/grommunio-archive/grommunio-archive.conf mysqlpwd "${ARCHIVE_MYSQL_PASS}" 0
  setconf /etc/grommunio-archive/grommunio-archive.conf mysqldb "${ARCHIVE_MYSQL_DB}" 0
  setconf /etc/grommunio-archive/grommunio-archive.conf listen_addr 0.0.0.0 0
  setconf /etc/grommunio-archive/grommunio-archive.conf storedir /var/lib/grommunio-archive/store

  php /etc/grommunio-archive/sphinx.conf.dist > /etc/sphinx/sphinx.conf

  sed -i -e "s/MYSQL_HOSTNAME/${ARCHIVE_MYSQL_HOST}/" -e "s/MYSQL_DATABASE/${ARCHIVE_MYSQL_DB}/" -e "s/MYSQL_PASSWORD/${ARCHIVE_MYSQL_PASS}/" -e "s/MYSQL_USERNAME/${ARCHIVE_MYSQL_USER}/" /etc/sphinx/sphinx.conf
  chown groarchive:sphinx /etc/sphinx/sphinx.conf
  chmod 644 /etc/sphinx/sphinx.conf
  chown groarchive:sphinx /var/lib/grommunio-archive/sphinx/ -R
  chmod 775 /var/lib/grommunio-archive/sphinx/
  sudo -u groarchive indexer --all

  < /dev/urandom head -c 56 > /etc/grommunio-archive/grommunio-archive.key

  writelog "Config stage: archive+postfix enable and restart"
  systemctl enable searchd.service grommunio-archive-smtp.service grommunio-archive.service postfix.service >>"${LOGFILE}" 2>&1
  systemctl restart searchd.service grommunio-archive-smtp.service grommunio-archive.service postfix.service >>"${LOGFILE}" 2>&1

  jq '.archiveWebAddress |= "https://'${FQDN}'/archive"' /tmp/config.json > /tmp/config-new.json
  mv /tmp/config-new.json /tmp/config.json

  writelog "groarchive admin user: admin@local"
  writelog "groarchive admin pass: ${ARCHIVE_ADMIN_PASS}"
  writelog "groarchive audit user: auditor@local"
  writelog "groarchive audit pass: ${ARCHIVE_AUDIT_PASS}"
fi

mv /tmp/config.json /etc/grommunio-admin-common/config.json
systemctl restart grommunio-admin-api.service

progress 100
writelog "Config stage: completed"
setup_done

exit 0
