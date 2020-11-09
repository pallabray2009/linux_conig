# linux_conig

http://easylinuxtutorials.blogspot.in/2013/11/implementing-password-policies-in.html



http://easylinuxtutorials.blogspot.in/2013/11/installing-configuring-openldap-server.html



https://www.rosehosting.com/blog/how-to-install-tomcat-8-on-a-centos-6-vps/



Installing & Configuring OpenLDAP Server On CentOS 6.4



In this post I will try to explain, how to install and configure OpenLDAP Server 2.4 on CentOS 6.4. Here I have a minimal installation of CentOS 6.4 x86_64.



Pre-requisites:

Working DNS Server : If you don't know how to configure DNS, please click the link for step by step configuration of BIND DNS http://easylinuxtutorials.blogspot.com/2011/11/setting-up-dns-server-in-rhel-6.html

Server should be synced with NTP Server. Please follow my post for NTP Server configuration

Disable SELinux

Steps for Installing & Configuring OpenLDAP Server:



Install OpenLDAP server and client packages

[root@ldap1 ~]# yum install openldap openldap-servers openldap-clients -y



Installation of openldap-servers package gives a template slapd.conf with an example bdb configured. In this example, We will modify the slapd.conf to convert it to cn=config format. cn=config is a new feature of OpenLDAP 2.4 which enables dynamic changes to configuration without requiring to restart.



Copy the example slapd.conf to /etc/openldap/

[root@ldap1 ~]# cp /usr/share/openldap-servers/slapd.conf.obsolete /etc/openldap/slapd.conf



Generate the encrypted password for rootdn to use in /etc/openldap/slapd.conf

[root@ldap1 ~]# slappasswd

New password:

Re-enter new password:

{SSHA}GtG8bcLGeN/rf1iStKFK2pu0C2EZf/RX



Copy the generated password and edit the /etc/openldap/slapd.conf

Note: In the below slapd.conf file changes are highlighted with red colour.

[root@ldap1 ~]# vim /etc/openldap/slapd.conf

#

# See slapd.conf(5) for details on configuration options.

# This file should NOT be world readable.

#

include /etc/openldap/schema/corba.schema

include /etc/openldap/schema/core.schema

include /etc/openldap/schema/cosine.schema

include /etc/openldap/schema/duaconf.schema

include /etc/openldap/schema/dyngroup.schema

include /etc/openldap/schema/inetorgperson.schema

include /etc/openldap/schema/java.schema

include /etc/openldap/schema/misc.schema

include /etc/openldap/schema/nis.schema

include /etc/openldap/schema/openldap.schema

include /etc/openldap/schema/ppolicy.schema

include /etc/openldap/schema/collective.schema



# Allow LDAPv2 client connections. This is NOT the default.

allow bind_v2



# Do not enable referrals until AFTER you have a working directory

# service AND an understanding of referrals.

#referral ldap://root.openldap.org



pidfile /var/run/openldap/slapd.pid

argsfile /var/run/openldap/slapd.args



# Load dynamic backend modules

# - modulepath is architecture dependent value (32/64-bit system)

# - back_sql.la overlay requires openldap-server-sql package

# - dyngroup.la and dynlist.la cannot be used at the same time



# modulepath /usr/lib/openldap

# modulepath /usr/lib64/openldap



# moduleload accesslog.la

# moduleload auditlog.la

# moduleload back_sql.la

# moduleload chain.la

# moduleload collect.la

# moduleload constraint.la

# moduleload dds.la

# moduleload deref.la

# moduleload dyngroup.la

# moduleload dynlist.la

# moduleload memberof.la

# moduleload pbind.la

# moduleload pcache.la

# moduleload ppolicy.la

# moduleload refint.la

# moduleload retcode.la

# moduleload rwm.la

# moduleload seqmod.la

# moduleload smbk5pwd.la

# moduleload sssvlv.la

# moduleload syncprov.la

# moduleload translucent.la

# moduleload unique.la

# moduleload valsort.la



# The next three lines allow use of TLS for encrypting connections using a

# dummy test certificate which you can generate by running

# /usr/libexec/openldap/generate-server-cert.sh. Your client software may balk

# at self-signed certificates, however.

#TLSCACertificatePath /etc/openldap/certs

#TLSCertificateFile "\"OpenLDAP Server\""

#TLSCertificateKeyFile /etc/openldap/certs/password



# Sample security restrictions

# Require integrity protection (prevent hijacking)

# Require 112-bit (3DES or better) encryption for updates

# Require 63-bit encryption for simple bind

# security ssf=1 update_ssf=112 simple_bind=64



# Sample access control policy:

# Root DSE: allow anyone to read it

# Subschema (sub)entry DSE: allow anyone to read it

# Other DSEs:

# Allow self write access

# Allow authenticated users read access

# Allow anonymous users to authenticate

# Directives needed to implement policy:

# access to dn.base="" by * read

# access to dn.base="cn=Subschema" by * read

# access to *

# by self write

# by users read

# by anonymous auth

#

# if no access controls are present, the default policy

# allows anyone and everyone to read anything but restricts

# updates to rootdn. (e.g., "access to * by * read")

#

# rootdn can always read and write EVERYTHING!



# enable on-the-fly configuration (cn=config)

database config

access to *

        by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage

        by * none



# enable server status monitoring (cn=monitor)

database monitor

access to *

        by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" read

        by dn.exact="cn=Manager,dc=example,dc=com" read

        by * none



#######################################################################

# database definitions

#######################################################################



database bdb

suffix "dc=example,dc=com"

checkpoint 1024 15

rootdn "cn=Manager,dc=example,dc=com"

rootpw {SSHA}GtG8bcLGeN/rf1iStKFK2pu0C2EZf/RX

loglevel 256

sizelimit unlimited

# Cleartext passwords, especially for the rootdn, should

# be avoided. See slappasswd(8) and slapd.conf(5) for details.

# Use of strong authentication encouraged.

# rootpw secret

# rootpw {crypt}ijFYNcSNctBYg



# The database directory MUST exist prior to running slapd AND

# should only be accessible by the slapd and slap tools.

# Mode 700 recommended.

directory /var/lib/ldap



# Indices to maintain for this database

index objectClass eq,pres

index ou,cn,mail,surname,givenname eq,pres,sub

index uidNumber,gidNumber,loginShell eq,pres

index uid,memberUid eq,pres,sub

index nisMapName,nisMapEntry eq,pres,sub



# Replicas of this database

#replogfile /var/lib/ldap/openldap-master-replog

#replica host=ldap-1.example.com:389 starttls=critical

# bindmethod=sasl saslmech=GSSAPI

# authcId=host/ldap-master.example.com@EXAMPLE.COM



Clean up all content and previous existing LDAP configuration and files, incase if exists. And re-initialize them.

[root@ldap1 ~]# rm -rf /var/lib/ldap/*

[root@ldap1 ~]# rm -rf /etc/openldap/slapd.d/*



Copy the sample DB_CONFIG file to /var/lib/ldap/

[root@ldap1 ~]# cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG



Check for errors in /etc/openldap/slapd.conf using the below command

[root@ldap1 ~]# slaptest -u

config file testing succeeded



Convert configuration file into dynamic configuration under /etc/openldap/slapd.d/ directory

[root@ldap1 ~]# slaptest -f /etc/openldap/slapd.conf -F /etc/openldap/slapd.d

config file testing succeeded



Set permission on /var/lib/ldap/ and /etc/openldap/slapd.d/ to ldap

[root@ldap1 ~]# chown -Rf ldap. /etc/openldap/slapd.d/

[root@ldap1 ~]# chown -Rf ldap. /var/lib/ldap/

[root@ldap1 ~]# chmod 700 /var/lib/ldap/

[root@ldap1 ~]# chmod 700 /etc/openldap/slapd.d/



Start the slapd process and service at system bootup

[root@ldap1 ~]# service slapd start

Starting slapd: [ OK ]

[root@ldap1 ~]# chkconfig slapd on

  

Confirm the slapd process is running using the below commands

[root@ldap1 ~]# service slapd status

slapd (pid 1301) is running...[root@ldap1 ~]# netstat -ntlup | grep slapd

tcp 0 0 0.0.0.0:389 0.0.0.0:* LISTEN 1301/slapd

tcp 0 0 :::389 :::* LISTEN 1301/slapd

[root@ldap1 ~]# ps -ef | grep slapd

ldap 1301 1 0 08:21 ? 00:00:00 /usr/sbin/slapd -h ldap:/// ldapi:/// -u ldap

root 1318 1208 0 08:23 pts/1 00:00:00 grep slapd



If you the get the output as above it means, your slapd is running with any problem. All connections to the server from the client are in plain text without encryption. The problem here is if anybody on the network using a packet sniffing tool such as ethereal can view the data that is transmitted between server and client, so he can view all the sensitive information. To eradicate such problem we are going to use slapd with SASL/TLS connection. For this we will use self signed certificates



Enabling encrypted connection for slapd using self-signed certificates



Install the openssl package using yum

[root@ldap1 ~]# yum install openssl -y



Generate the keypair using the below command

[root@ldap1 ~]# openssl req -newkey rsa:1024 -x509 -nodes -out /etc/pki/tls/certs/ldap1_pubkey.pem -keyout /etc/pki/tls/certs/ldap1_privkey.pem -days 3650

Generating a 1024 bit RSA private key

....++++++

....++++++

writing new private key to '/etc/pki/tls/certs/ldap1_privkey.pem'

-----

You are about to be asked to enter information that will be incorporated

into your certificate request.

What you are about to enter is what is called a Distinguished Name or a DN.

There are quite a few fields but you can leave some blank

For some fields there will be a default value,

If you enter '.', the field will be left blank.

-----

Country Name (2 letter code) [XX]:IN

State or Province Name (full name) []:Andhra Pradesh

Locality Name (eg, city) [Default City]:Hyderabad

Organization Name (eg, company) [Default Company Ltd]:Example Inc.,

Organizational Unit Name (eg, section) []:ITD

Common Name (eg, your name or your server's hostname) []:ldap1.example.com

Email Address []:root@ldap1.example.com



Set permission on the generated certificates to ldap

[root@ldap1 ~]# chown ldap. /etc/pki/tls/certs/ldap1_p*

[root@ldap1 ~]# ll /etc/pki/tls/certs/ldap1_p*

-rw-r--r-- 1 ldap ldap 912 Oct 27 08:40 /etc/pki/tls/certs/ldap1_privkey.pem

-rw-r--r-- 1 ldap ldap 1131 Oct 27 08:40 /etc/pki/tls/certs/ldap1_pubkey.pem



Change the setting for the certificate files in the following config file. It is highlighted with red colour font

[root@ldap1 ~]# vim /etc/openldap/slapd.d/cn\=config/olcDatabase\=\{0\}config.ldif

dn: olcDatabase={0}config

objectClass: olcDatabaseConfig

olcDatabase: {0}config

olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=externa

 l,cn=auth" manage by * none

olcAddContentAcl: TRUE

olcLastMod: TRUE

olcMaxDerefDepth: 15

olcReadOnly: FALSE

olcRootDN: cn=config

olcSyncUseSubentry: FALSE

olcTLSCertificateFile: /etc/pki/tls/certs/ldap1_pubkey.pem

olcTLSCertificateKeyFile: /etc/pki/tls/certs/ldap1_privkey.pem

olcMonitoring: FALSE

structuralObjectClass: olcDatabaseConfig

entryUUID: 4e47724a-d2fd-1032-8616-41f003d9fb12

creatorsName: cn=config

createTimestamp: 20131027024329Z

entryCSN: 20131027024329.230729Z#000000#000#000000

modifiersName: cn=config

modifyTimestamp: 20131027024329Z



Modify the setting for SLAPD as below in file /etc/sysconfig/ldap

[root@ldap1 ~]# vim /etc/sysconfig/ldap

SLAPD_LDAP=no

SLAPD_LDAPI=no

SLAPD_LDAPS=yes



Restart the SLAPD process

[root@ldap1 ~]# service slapd restart

Stopping slapd: [ OK ]

Starting slapd: [ OK ]



Check the service is running on LDAPS port or not

[root@ldap1 ~]# netstat -ntlup | grep slapd

tcp 0 0 0.0.0.0:389 0.0.0.0:* LISTEN 1402/slapd

tcp 0 0 :::389 :::* LISTEN 1402/slapd



Modify the iptables configuration to allow LDAP ports

[root@ldap1 ~]# iptables -I INPUT -p udp -s 192.168.124.0/24 --dport 389 -j ACCEPT

[root@ldap1 ~]# iptables -I INPUT -p tcp -s 192.168.124.0/24 --dport 389 -j ACCEPT

[root@ldap1 ~]# iptables -I INPUT -p udp -s 192.168.124.0/24 --dport 636 -j ACCEPT

[root@ldap1 ~]# iptables -I INPUT -p tcp -s 192.168.124.0/24 --dport 636 -j ACCEPT

[root@ldap1 ~]# service iptables save

iptables: Saving firewall rules to /etc/sysconfig/iptables:[ OK ]



Create a base for the DIT (Directory Information Tree) using the following file.

[root@ldap1 ~]# vim dit.ldif

# Creates a base for DIT

dn: dc=example,dc=com

objectClass: top

objectClass: dcObject

objectclass: organization

o: Example Organization

dc: Example

description: Example Inc DIT



# Creates a Users OU (Organizational Unit)

dn: ou=Users,dc=example,dc=com

objectClass: organizationalUnit

ou: Users



# Creates a Groups OU

dn: ou=Groups,dc=example,dc=com

objectClass: organizationalUnit

ou: Groups



dn: ou=Admins,dc=example,dc=com

objectClass: organizationalUnit

ou: Admins



# Create a user student1 with some basic info

dn: uid=student1,ou=Users,dc=example,dc=com

uid: student1

cn: student1

sn: 1

objectClass: top

objectClass: posixAccount

objectClass: inetOrgPerson

loginShell: /bin/bash

homeDirectory: /home/student1

uidNumber: 15000

gidNumber: 10000

userPassword: {SSHA}CQG5KHc6b1ii+qopaVCsNa14v9+r14r5

mail: student1@example.com

gecos: Student1 User



# Create a user student2 with some basic info

dn: uid=student2,ou=Users,dc=example,dc=com

uid: student2

cn: student2

sn: 2

objectClass: top

objectClass: posixAccount

objectClass: inetOrgPerson

loginShell: /bin/bash

homeDirectory: /home/student2

uidNumber: 15001

gidNumber: 10000

userPassword: {SSHA}CQG5KHc6b1ii+qopaVCsNa14v9+r14r5

mail: student2@example.com

gecos: Student2 User



# Creates a ldapusers group under Groups OU

dn: cn=ldapusers,ou=Groups,dc=example,dc=com

objectClass: posixGroup

objectClass: top

cn: ldapusers

userPassword: {crypt}x

gidNumber: 10000

memberuid: uid=student1

memberuid: uid=student2



Change the /etc/openldap/ldap.conf file as below

[root@ldap1 ~]# vim /etc/openldap/ldap.conf

#

# LDAP Defaults

#

# See ldap.conf(5) for details

# This file should be world readable but not world writable.

#BASE dc=example,dc=com

#URI ldap://ldap.example.com ldap://ldap-master.example.com:666



#SIZELIMIT 12

#TIMELIMIT 15

#DEREF never



#TLS_CACERTDIR /etc/openldap/certs

ssl start_tls

TLS_REQCERT allow

BASE dc=example,dc=com

URI ldaps://ldap.example.com

HOST 192.168.124.251



Populate the DIT with the values in the file dit.ldif

[root@ldap1 ~]# ldapadd -x -D "cn=Manager,dc=example,dc=com" -W -f dit.ldif -H ldaps://ldap1.example.comEnter LDAP Password:

adding new entry "dc=example,dc=com"



adding new entry "ou=Users,dc=example,dc=com"



adding new entry "ou=Groups,dc=example,dc=com"



adding new entry "uid=student1,ou=Users,dc=example,dc=com"



adding new entry "uid=student2,ou=Users,dc=example,dc=com"



adding new entry "cn=ldapusers,ou=Groups,dc=example,dc=com"



Search the DIT using the following command to find the newly added values

[root@ldap1 ~]# ldapsearch -x -b "dc=example,dc=com" -H ldaps://ldap1.example.com

# extended LDIF

#

# LDAPv3

# base <dc=example,dc=com> with scope subtree

# filter: (objectclass=*)

# requesting: ALL

#



# example.com

dn: dc=example,dc=com

objectClass: top

objectClass: dcObject

objectClass: organization

o: Example Organization

dc: Example

description: Example Inc DIT



# Users, example.com

dn: ou=Users,dc=example,dc=com

objectClass: organizationalUnit

ou: Users



# Groups, example.com

dn: ou=Groups,dc=example,dc=com

objectClass: organizationalUnit

ou: Groups



# student1, Users, example.com

dn: uid=student1,ou=Users,dc=example,dc=com

uid: student1

cn: student1

sn: 1

objectClass: top

objectClass: posixAccount

objectClass: inetOrgPerson

loginShell: /bin/bash

homeDirectory: /home/student1

uidNumber: 14583100

gidNumber: 14564100

userPassword:: e1NTSEF9Q1FHNUtIYzZiMWlpK3FvcGFWQ3NOYTE0djkrcjE0cjU=

mail: student1@example.com

gecos: Student1 User



# student2, Users, example.com

dn: uid=student2,ou=Users,dc=example,dc=com

uid: student2

cn: student2

sn: 2

objectClass: top

objectClass: posixAccount

objectClass: inetOrgPerson

loginShell: /bin/bash

homeDirectory: /home/student2

uidNumber: 14583101

gidNumber: 14564100

userPassword:: e1NTSEF9Q1FHNUtIYzZiMWlpK3FvcGFWQ3NOYTE0djkrcjE0cjU=

mail: student2@example.com

gecos: Student2 User



# ldapusers, Groups, example.com

dn: cn=ldapusers,ou=Groups,dc=example,dc=com

objectClass: posixGroup

objectClass: top

cn: ldapusers

userPassword:: e2NyeXB0fXg=

gidNumber: 14564100

memberUid: uid=student1

memberUid: uid=student2



# search result

search: 2

result: 0 Success



# numResponses: 8

# numEntries:7



Configure Rsyslog to log the LDAP to LOCAL4

[root@ldap1 ~]# vim /etc/rsyslog.conf

# At the end of file write the below

local4.* /var/log/ldap

[root@ldap1 ~]# service rsyslog restart



Now all LDAP log will be in the file /var/log/ldap



Client Side Configuration



Configure the client to allow LDAP users to log into the system

[root@client ~]# yum install openldap-clients sssd -y

[root@client ~]# vim /etc/openldap/ldap.conf

ssl start_tls

TLS_REQCERT allow

TLS_CACERTDIR /etc/openldap/cacerts

BASE dc=example,dc=com

URI ldaps://ldap1.example.com

HOST 192.168.124.251



Copy the LDAP public certificate into the client system at /etc/openldap/cacerts

[root@client ~]# scp ldap:/etc/pki/tls/certs/ldap.pem /etc/openldap/cacerts



Create a sssd.conf file at this location /etc/sssd/sssd.conf

[root@client ~]# vim /etc/sssd/sssd.conf

[sssd]

config_file_version = 2

services = nss, pam

domains = default



[nss]

filter_users = root,ldap,named,avahi,haldaemon,dbus,radiusd,news,nscd



[pam]



[domain/default]

ldap_tls_reqcert = never

auth_provider = ldap

ldap_schema = rfc2307bis

krb5_realm = EXAMPLE.COM

ldap_search_base = dc=example,dc=com

ldap_group_member = uniquemember

id_provider = ldap

ldap_id_use_start_tls = True

chpass_provider = ldap

ldap_uri = ldaps://ldap1.example.com/

ldap_chpass_uri = ldaps://.ldap1.example.com/

krb5_kdcip = ldap1.example.com

cache_credentials = True

ldap_tls_cacertdir = /etc/openldap/cacerts

entry_cache_timeout = 600

ldap_network_timeout = 3

krb5_server = ldap1.example.com



Configure the System to use LDAP authentication

[root@client ~]# authconfig-tui

  

Click Next

  

Click OK

Starting sssd: [ OK ]

[root@client ~]# authconfig --enablesssd --enablesssdauth --enablelocauthorize --enablemkhomedir --update

[root@client ~]# getent passwd student1

student1:*:15000:10000:Student1 User:/home/student1:/bin/bash

[root@client ~]# id student1

uid=15000(student1) gid=10000(ldapusers) groups=10000(ldapusers)



Now login to the system with any LDAP user

[root@client ~]# su - student1

Creating directory '/home/student1'.

[student1@client ~]$ pwd

/home/student1



Troubleshooting:

Incase you get error as below:

bdb_db_open: database "dc=example,dc=com": db_open(/var/lib/ldap/id2entry.bdb) failed: No such file or directory (2).



Then initialize DB files for content in /var/lib/ldap directory

[root@ldap1 ~]# echo "" | slapadd -f /etc/openldap/slapd.conf

After this again run the command

[root@ldap1 ~]# slaptest -f /etc/openldap/sla



Implementing Password Policies in OpenLDAP Server On CentOS 6.4

In this post I am going to show you how to configure password policies in OpenLDAP server. The ppolicy overlay module provides some better functionalities for enforcing password policies within our OpenLDAP Server domain.

ppolicy module and schema is by installed by default with openldap-servers package in CentOS 6.4

Copy the below text into /etc/openldap/slapd.conf at the end of the file 
[root@ldap1 ~]# vim /etc/openldap/slapd.conf
# Uncomment the module in the modules section
moduleload ppolicy.la  
# Password Policy Configuration
overlay ppolicy
ppolicy_default "cn=default,ou=Policies,dc=example,dc=com"
ppolicy_use_lockout
ppolicy_hash_cleartext

# ACL Entry for Password Policies
access to attrs=userPassword
        by self write
        by anonymous auth
        by * none
access to *
        by self write
        by * read

Convert the slapd.conf to cn=config format and re-initialize the slapd.d folder
[root@ldap1 ~]# rm -rf /etc/openldap/slapd.d/* 
[root@ldap1 ~]# slaptest -u 
[root@ldap1 ~]# slaptest -f /etc/openldap/slapd.conf -F /etc/openldap/slapd.d/

Change the permissions on the /etc/openldap/slapd.d/ to ldap
[root@ldap1 ~]# chown -R ldap. /etc/openldap/slapd.d/  

Restart the slapd service
[root@ldap1 ~]# service slapd restart 

Create a LDIF file with the details as below
[root@ldap1 ~]# vim pwdpolicy.ldif
# Creates a Policies OU (Organizational Unit)
dn: ou=Policies,dc=example,dc=com
objectClass: organizationalUnit
ou: Policies

# Creates a Policy object in Policies OU (Organizational Unit)
dn: cn=default,ou=Policies,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMaxAge: 3888000
pwdExpireWarning: 604800
pwdInHistory: 3
pwdCheckQuality: 1
pwdMinLength: 8
pwdMaxFailure: 5
pwdLockout: TRUE
pwdLockoutDuration: 86400
pwdGraceAuthNLimit: 0
pwdFailureCountInterval: 0
pwdMustChange: TRUE
pwdAllowUserChange: TRUE
pwdSafeModify: FALSE 

Add the ldif file created to the DIT using ldapadd command
[root@ldap1 ~]# ldapadd -x -D "cn=manager,dc=example,dc=com" -wredhat -f pwdpolicy.ldif

Password policy is turned on for all accounts
 
The above definition of password policy as below
pwdMaxAge: Number of days users password is valid for i.e 3888000 seconds (45 days)
pwdExpireWarning: No. of days before to warn the user (7 days)
pwdInHistory: No. of password that are kept in history which can't be used continously
pwdCheckQuality: If it is 0, we can use plain passwords, if it is 1 then password should be complex i.e. combination of numbers and alpahbets and special characters
pwdMinLength: Defines the minimum number of characters for setting the password. It can't be less than 8 characters here
pwdMaxFailure: If user tries to enter incorrect password for 5 times then his/her account will be locked
pwdLockoutDuration: Defines the time the account will be locked ie. 1 day. This setting will be valid only if pwdLockout is set to TRUE

For more information and settings on password policy please refer to this link below
http://www.zytrax.com/books/ldap/ch6/ppolicy.html



