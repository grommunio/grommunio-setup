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
videobridge {
  rest {
     debug {
       enabled = true
     }
     health {
       enabled = true
     }
     shutdown {
       enabled = true
     }
     version {
       enabled = true
     }
  }
  entity-expiration {
    timeout=1 minute
    check-interval=\${videobridge.entity-expiration.timeout}
  }
  health {
    interval=60 seconds
    timeout=30 seconds
    max-check-duration=3 seconds
    sticky-failures=false
  }
  ep-connection-status {
    first-transfer-timeout=15 seconds
    max-inactivity-limit=3 seconds
    check-interval=500 milliseconds
  }
  cc {
    bwe-change-threshold=0.15
    thumbnail-max-height-px=180
    onstage-ideal-height-px=1080
    onstage-preferred-height-px=360
    onstage-preferred-framerate=30
    allow-oversend-onstage=true
    max-oversend-bitrate=500 kbps
    trust-bwe=true
    padding-period=15ms
    max-time-between-calculations = 15 seconds
    jvb-last-n = -1
  }
  apis {
    xmpp-client {
      presence-interval = \${videobridge.stats.interval}
      stats-filter {
        enabled = false
        whitelist = ["average_participant_stress", "current_timestamp", "graceful_shutdown",
           "octo_version", "region", "relay_id", "stress_level", "version"]
      }
      jid-cache-size = 1000
      configs {
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
    rest {
      enabled = true
    }
    jvb-api {
      enabled = false
    }
  }
  http-servers {
    public {
      port = 9090
      tls-port = 8444
    }
    private {
      host = 127.0.0.1
      port = 8082
      tls-port = 8445
    }
  }
  octo {
    enabled=false
    bind-port=4096
    recv-queue-size=1024
    send-queue-size=1024
  }
  load-management {
    reducer-enabled = false
    load-measurements {
      packet-rate {
        load-threshold = 50000
        recovery-threshold = 40000
      }
    }
    load-reducers {
      last-n {
        reduction-scale = .75
        recover-scale = 1.25
        impact-time = 1 minute
        minimum-last-n-value = 1
        maximum-enforced-last-n-value = 40
      }
    }
    conference-last-n-limits {
    }
    average-participant-stress = 0.01
  }
  sctp {
    enabled=true
  }
  stats {
    enabled=true
    interval = 5 seconds
    callstats {
      app-id = 0
      bridge-id = "jitsi"
      interval = \${videobridge.stats.interval}
    }
  }
  websockets {
    enabled=true
    server-id="default-id"
    enable-compression = true
    tls=true
    domain="${FQDN}"
  }
  ice {
    tcp {
      enabled = false
      port = 443
      ssltcp = true
    }
    udp {
        port = 10000
    }
    keep-alive-strategy = "selected_and_tcp"
    use-component-socket = true
    resolve-remote-candidates = false
    nomination-strategy = "NominateFirstValid"
  }
  transport {
    send {
      queue-size=1024
    }
  }
  multi-stream {
    enabled = false
  }
  speech-activity {
    recent-speakers-count = 10
  }
  loudest {
      route-loudest-only = false
      num-loudest = 3
      always-route-dominant = true
      energy-expire-time = 150 milliseconds
      energy-alpha-pct = 50
  }
  version {
    announce = false
  }
  graceful-shutdown-delay = 1 minute
}
EOVBAPPCONF

cat > /etc/jitsi/videobridge/jitsi-videobridge.conf <<EOVBCONF
JVB_HOSTNAME=${FQDN}
JVB_HOST=${FQDN}
JVB_PORT=5347
JVB_SECRET=${CPUID}
JVB_OPTS="--apis=xmpp,rest"
JAVA_SYS_PROPS="-Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/etc/jitsi\
 -Dnet.java.sip.communicator.SC_HOME_DIR_NAME=videobridge\
 -Dnet.java.sip.communicator.SC_LOG_DIR_LOCATION=/var/log/jitsi-videobridge\
 -Djava.util.logging.config.file=/etc/jitsi/videobridge/logging.properties\
 -Dconfig.file=/etc/jitsi/videobridge/application.conf"
EOVBCONF

cat > /etc/jitsi/videobridge/sip-communicator.properties <<EOVBSIP
org.jitsi.videobridge.ENABLE_STATISTICS=true
org.jitsi.videobridge.STATISTICS_TRANSPORT=muc,colibri,pubsub
org.jitsi.videobridge.xmpp.user.xmppserver2.HOSTNAME=localhost
org.jitsi.videobridge.xmpp.user.xmppserver2.DOMAIN=auth.${FQDN}
org.jitsi.videobridge.xmpp.user.xmppserver2.USERNAME=jvb
org.jitsi.videobridge.xmpp.user.xmppserver2.PASSWORD=${CPUID}
org.jitsi.videobridge.xmpp.user.xmppserver2.MUC_JIDS=JvbBrewery@internal.auth.${FQDN}
org.jitsi.videobridge.xmpp.user.xmppserver2.MUC=JvbBrewery@internal.auth.${FQDN}
org.jitsi.videobridge.xmpp.user.xmppserver2.MUC_NICKNAME=${MUC_NICK}
org.jitsi.videobridge.xmpp.user.xmppserver2.DISABLE_CERTIFICATE_VERIFICATION=true
org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER=true
org.jitsi.videobridge.DISABLE_TCP_HARVESTER=true
# If meet is behind NAT uncomment and configure local and public IP here
#org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=192.168.0.1
#org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=1.2.3.4
org.jitsi.videobridge.SINGLE_PORT_HARVESTER_PORT=10000
EOVBSIP

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

