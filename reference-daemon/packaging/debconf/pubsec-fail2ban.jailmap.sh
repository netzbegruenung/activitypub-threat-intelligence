# Shared by the config and postinst scripts of pubsec-fail2ban.
# build-deb.sh copies this file into both, so the table cannot drift apart.

# File that `pull` writes and the pubsecd-ban jail follows. Must match the
# logpath in jail.d/pubsecd-ban.local.
PUBSEC_BAN_LOG=/var/log/pubsec-fail2ban/ssh.log

# The jails this package ships templates for, in the order they are offered.
PUBSEC_OWN_JAILS="pubsec-apache-scan pubsec-apache-probing pubsec-apache-exploit pubsec-apache-auth-flood pubsec-nginx-scan pubsec-nginx-probing pubsec-nginx-exploit pubsec-nginx-auth-flood pubsec-haproxy-scan pubsec-haproxy-probing pubsec-haproxy-exploit pubsec-haproxy-auth-flood"

# pubsec_jail_map JAIL -> "BEHAVIOR PORT SERVICE", "-" where not applicable.
# Behaviours must be one of the ten in the AP-TI vocabulary (Section 4.2).
pubsec_jail_map() {
    case "$1" in
        sshd|dropbear|selinux-ssh)
            echo "ssh-bruteforce 22 ssh" ;;
        postfix|postfix-rbl|sendmail-reject|exim-spam|assp|qmail-rbl)
            echo "smtp-spam 25 smtp" ;;
        postfix-sasl|sendmail-auth|courier-smtp)
            echo "auth-bruteforce 25 smtp" ;;
        dovecot|courier-auth|sieve|solid-pop3d|cyrus-imap|uwimap-auth|perdition|exim)
            echo "auth-bruteforce - imap" ;;
        proftpd|pure-ftpd|vsftpd|gssftpd|wuftpd)
            echo "auth-bruteforce 21 ftp" ;;
        mysqld-auth)
            echo "auth-bruteforce 3306 mysql" ;;
        mssql-auth|mongodb-auth)
            echo "auth-bruteforce - -" ;;
        asterisk|freeswitch)
            echo "auth-bruteforce - sip" ;;
        ejabberd-auth)
            echo "auth-bruteforce - xmpp" ;;
        softethervpn)
            echo "auth-bruteforce - vpn" ;;
        named-refused|nsd)
            echo "other 53 dns" ;;
        squid|3proxy)
            echo "other - proxy" ;;
        nginx-limit-req)
            echo "ddos-source - http" ;;
        apache-shellshock|apache-modsecurity|apache-overflows|apache-fakegooglebot|suhosin|php-url-fopen)
            echo "exploit-attempt - http" ;;
        apache-badbots|apache-botsearch|apache-nohome|apache-noscript|nginx-botsearch|nginx-bad-request|nginx-forbidden)
            echo "scan - http" ;;
        apache-auth|nginx-http-auth|lighttpd-auth|roundcube-auth|drupal-auth|webmin-auth|froxlor-auth|sogo-auth|openwebmail|horde|groupoffice|tine20|openhab-auth|monit|guacamole|gitlab|grafana|bitwarden|centreon|nagios|znc-adminlog)
            echo "auth-bruteforce - http" ;;
        pubsec-*-scan|pubsec-*-probing)
            echo "scan - http" ;;
        pubsec-*-exploit)
            echo "exploit-attempt - http" ;;
        pubsec-*-auth-flood)
            echo "auth-bruteforce - http" ;;
        *)
            echo "other - -" ;;
    esac
}
