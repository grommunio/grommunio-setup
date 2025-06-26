#!/bin/bash

[ -z "${FQDN}" ] && FQDN=$(hostname -f)

LOGFILE=${LOGFILE:-/var/log/grommunio-setup-meet.log}

if [ -e /etc/machine-id ]; then
        CPUID="`cat /etc/machine-id`"
else
        CPUID="`ip a | grep -i link/ether | sha256sum | awk '{ print $1 }'`"
fi

MUC_NICK=$(uuidgen)

systemctl is-active --quiet prosody && systemctl stop prosody
systemctl is-active --quiet jitsi-videobridge && systemctl stop jitsi-videobridge
systemctl is-active --quiet jitsi-jicofo && systemctl stop jitsi-jicofo

zypper install -y jitsi-jicofo jitsi-meet jitsi-meet-branding-grommunio jitsi-videobridge prosody >>"${LOGFILE}" 2>&1

mkdir -p /etc/prosody/conf.d
cat > /etc/prosody/prosody.cfg.lua <<EOPROSODYMAIN
admins = { }
modules_enabled = {
        "roster";
        "saslauth";
        "tls";
        "dialback";
        "disco";
        "carbons";
        "pep";
        "private";
        "blocklist";
        "vcard4";
        "vcard_legacy";
        "version";
        "uptime";
        "time";
        "ping";
        "register";
        "admin_adhoc";
        "bosh";
        "websocket";
        "smacks";
        "mam";
        "lastactivity";
        "pubsub";
        "adhoc";
}

modules_disabled = {
}

pidfile = "/run/prosody/prosody.pid"
allow_registration = false
c2s_require_encryption = true
s2s_require_encryption = true
s2s_secure_auth = false
authentication = "internal_hashed"
archive_expires_after = "1w" -- Remove archived messages after 1 week
log = {
        info = "/var/log/prosody/prosody.log"; -- Change 'info' to 'debug' for verbose logging
        error = "/var/log/prosody/prosody.err";
}
certificates = "certs"
VirtualHost "localhost"
Include 'conf.d/*.cfg.lua'
EOPROSODYMAIN

cat > /etc/prosody/conf.d/${FQDN}.cfg.lua <<EOPROSODYHOST
plugin_paths = { "/usr/share/jitsi/meet/prosody-plugins/" }
muc_mapper_domain_base = "${FQDN}";

-- configuration with external TURN service with authentication (coturn for example)
--external_service_secret = "averylongturnsecret";
--external_services = {
--     { type = "stun", host = "turn.example.com", port = 3478 },
--     { type = "turn", host = ""turn.example.com, port = 443, transport = "udp", secret = true, ttl = 86400, algorithm = "turn" },
--     { type = "turns", host = "turn.example.com", port = 443, transport = "tcp", secret = true, ttl = 86400, algorithm = "turn" }
--};

cross_domain_bosh = true;
cross_domain_websocket = true;
consider_bosh_secure = true;

ssl = {
        protocol = "tlsv1_2+";
        ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
}

unlimited_jids = { "focus@auth.${FQDN}", "jvb@auth.${FQDN}" }

https_certificate = "/var/lib/prosody/${FQDN}.crt";
https_key =  "/var/lib/prosody/${FQDN}.key";

VirtualHost "${FQDN}"
        authentication = "anonymous";
        ssl = {
                key = "/var/lib/prosody/${FQDN}.key";
                certificate = "/var/lib/prosody/${FQDN}.crt";
        }
        speakerstats_component = "speakerstats.${FQDN}"
        conference_duration_component = "conferenceduration.${FQDN}"
        modules_enabled = {
                "bosh";
                "smacks";
                "pubsub";
                "speakerstats";
                "external_services";
                "conference_duration";
                "muc_lobby_rooms";
                "muc_breakout_rooms";
                "av_moderation";
        }
        c2s_require_encryption = false;
        lobby_muc = "lobby.${FQDN}"
        breakout_rooms_muc = "breakout.${FQDN}"
        main_muc = "conference.${FQDN}"
        smacks_max_unacked_stanzas = 5;
        smacks_hibernation_time = 60;
        smacks_max_hibernated_sessions = 1;
        smacks_max_old_sessions = 1;

Component "breakout.${FQDN}" "muc"
        restrict_room_creation = true
        storage = "memory"
        modules_enabled = {
                "muc_meeting_id";
                "muc_domain_mapper";
                "muc_rate_limit";
        }
        admins = { "focus@auth.${FQDN}" }
        muc_room_locking = false
        muc_room_default_public_jids = true

Component "lobby.${FQDN}" "muc"
        storage = "memory"
        restrict_room_creation = true
        muc_room_locking = false
        muc_room_default_public_jids = true
        modules_enabled = {
                "muc_rate_limit";
        }

Component "conference.${FQDN}" "muc"
        modules_enabled = {
                "muc_meeting_id";
                "muc_domain_mapper";
                "ping";
        }
        admins = { "focus@auth.${FQDN}" }
        muc_room_locking = false;
        muc_room_default_public_jids = true;

Component "internal.auth.${FQDN}" "muc"
        modules_enabled = {
                "ping";
        }
        admins = { "focus@auth.${FQDN}", "jvb@auth.${FQDN}", "jigasi@auth.${FQDN}" }
        muc_room_locking = false;
        muc_room_default_public_jids = true;
        muc_room_cache_size = 1000;

VirtualHost "auth.${FQDN}"
        ssl = {
                key = "/var/lib/prosody/auth.${FQDN}.key";
                certificate = "/var/lib/prosody/auth.${FQDN}.crt";
        }
        modules_enabled = {
            "limits_exception";
        }
        authentication = "internal_plain";

Component "focus.${FQDN}" "client_proxy"
       target_address = "focus@auth.${FQDN}";

Component "speakerstats.${FQDN}" "speakerstats_component"
        muc_component = "conference.${FQDN}";

Component "conferenceduration.${FQDN}" "conference_duration_component"
        muc_component = "conference.${FQDN}";

Component "avmoderation.${FQDN}" "av_moderation_component"
        muc_component = "conference.${FQDN}";


Component "jitsi-videobridge.${FQDN}"
        component_secret = "${CPUID}";

VirtualHost "recorder.${FQDN}"
        modules_enabled = {
             "ping";
        }
        authentication = "internal_plain"

Component "lobby.${FQDN}" "muc"
        storage = "memory"
        restrict_room_creation = true
        muc_room_locking = false
        muc_room_default_public_jids = true
        modules_enabled = {
            "muc_rate_limit";
        }

VirtualHost "guest.${FQDN}"
        authentication = "anonymous"
        c2s_require_encryption = false
        modules_enabled = {
                "bosh";
                "pubsub";
                "speakerstats";
                "external_services";
                "conference_duration";
        }
EOPROSODYHOST

cat > /srv/jitsi-meet/config.js <<EOCONFIGJS
var config = {
    hosts: {
        domain: '${FQDN}',
        focus: 'focus.${FQDN}',
        muc: 'conference.${FQDN}'
    },
    bosh: '//${FQDN}/meet/http-bind',
    websocket: 'wss://${FQDN}/meet/xmpp-websocket',
    testing: {
    },
    enableNoAudioDetection: true,
    enableNoisyMicDetection: true,
    channelLastN: -1,
    requireDisplayName: true,
    enableWelcomePage: true,
    enableClosePage: true,
    prejoinConfig: {
         enabled: true,
    },
    p2p: {
        enabled: true,
        stunServers: [
            { urls: 'stun:turn.grommunio.com:443' }
        ]
    },
    analytics: {
    },
    deploymentInfo: {
    },
    mouseMoveCallbackInterval: 1000,
    makeJsonParserHappy: 'even if last key had a trailing comma'
};
EOCONFIGJS

cat > /etc/jitsi/jicofo/jitsi-jicofo.conf <<EOJICOFOCONF
JICOFO_HOST=localhost
JICOFO_HOSTNAME=${FQDN}
JICOFO_AUTH_DOMAIN=auth.${FQDN}
JICOFO_AUTH_USER=focus
JICOFO_AUTH_PASSWORD=${CPUID}
JICOFO_OPTS=""
JAVA_SYS_PROPS="-Xmx3072m\
 -Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/etc/jitsi\
 -Dnet.java.sip.communicator.SC_HOME_DIR_NAME=jicofo\
 -Dnet.java.sip.communicator.SC_LOG_DIR_LOCATION=/var/log/jitsi-jicofo\
 -Djava.util.logging.config.file=/etc/jitsi/jicofo/logging.properties"
EOJICOFOCONF

cat > /etc/jitsi/jicofo/sip-communicator.properties <<EOJICOFOSIP
org.jitsi.jicofo.BRIDGE_MUC=JvbBrewery@internal.auth.${FQDN}
org.jitsi.jicofo.SHORT_ID=55555
org.jitsi.jicofo.ALWAYS_TRUST_MODE_ENABLED=true
EOJICOFOSIP

cat > /etc/jitsi/videobridge/application.conf <<EOVBAPPCONF
stats {
  # Enable broadcasting stats/presence in a MUC
  enabled = true
  transports = [
    { type = "muc" }
  ]
}

apis {
  xmpp-client {
    configs {
      # Connect to the first XMPP server
      xmpp-server-1 {
        hostname="${FQDN}"
        domain = "auth.${FQDN}"
        username = "focus"
        password = "${CPUID}"
        muc_jids = "JvbBrewery@internal.auth.${FQDN}"
        muc_nickname = "${MUC_NICK}"
        disable_certificate_verification = true
      }
    }
  }
}

videobridge {
  http-servers {
      public {
        host = 0.0.0.0
        port = 9090
        send-server-version = false
      }
  }
  stats {
      enabled = true
  }
  websockets {
      enabled = true
      domain = "${FQDN}:443"
      tls = true
  }
}
EOVBAPPCONF

rm -rf /var/lib/prosody/*
for i in auth avmoderation breakout conference conferenceduration focus guest internal.auth jitsi-videobridge lobby recorder speakerstats; do
  echo | prosodyctl cert generate $i.${FQDN} >>"${LOGFILE}" 2>&1
done
echo | prosodyctl cert generate ${FQDN} >>"${LOGFILE}" 2>&1

ln -sf /var/lib/prosody/auth.${FQDN}.crt /etc/pki/trust/anchors/auth.${FQDN}.crt
update-ca-certificates --fresh
prosodyctl register focus auth.${FQDN} ${CPUID}
prosodyctl register jvb auth.${FQDN} ${CPUID}
prosodyctl mod_roster_command subscribe focus.${FQDN} focus@auth.${FQDN}

firewall-cmd --add-port=10000/udp --zone=public --permanent
firewall-cmd --reload

systemctl start prosody >>"${LOGFILE}" 2>&1
systemctl start jitsi-videobridge >>"${LOGFILE}" 2>&1
systemctl start jitsi-jicofo >>"${LOGFILE}" 2>&1
systemctl enable prosody >>"${LOGFILE}" 2>&1
systemctl enable jitsi-videobridge >>"${LOGFILE}" 2>&1
systemctl enable jitsi-jicofo >>"${LOGFILE}" 2>&1

