<?php
#==============================================================================
# LTB Self Service Password
#
# Copyright (C) 2009 Clement OUDOT
# Copyright (C) 2009 LTB-project.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# GPL License: http://www.gnu.org/licenses/gpl.txt
#
#==============================================================================


#==============================================================================
# Gather configuration values from envrionment
#==============================================================================

#
# ldap configuration
#

# set the ldap url (required)
$ENV_LDAP_URL = getenv("LDAP_URL");
if (empty($ENV_LDAP_URL)) {
  exit("LDAP_URL not defined");
}
# set tls or not
$ENV_LDAP_STARTTLS = getenv("LDAP_STARTTLS");
if (empty($ENV_LDAP_STARTTLS)) {
  $ENV_LDAP_STARTTLS = false;
} elseif (strtolower($ENV_LDAP_STARTTLS) == "true") {
  $ENV_LDAP_STARTTLS = true;
} else {
  $ENV_LDAP_STARTTLS = false;
}
# set binddn (required)
$ENV_LDAP_BINDDN = getenv("LDAP_BINDDN");
if (empty($ENV_LDAP_BINDDN)) {
  exit("LDAP_BINDDN not defined");
}
# set bindpw (required)
$ENV_LDAP_BINDPW = getenv("LDAP_BINDPW");
if (empty($ENV_LDAP_BINDPW)) {
  exit("LDAP_BINDPW not defined");
}
# get the ldap search base (required)
$ENV_LDAP_BASE = getenv("LDAP_BASE");
if (empty($ENV_LDAP_BASE)) {
  exit("LDAP_BASE not defined");
}

# set the user object attribute
$ENV_LDAP_LOGIN_ATTRIBUTE = getenv("LDAP_LOGIN_ATTRIBUTE");
if (empty($ENV_LDAP_LOGIN_ATTRIBUTE)) {
  $ENV_LDAP_LOGIN_ATTRIBUTE = "uid";
}
# set the full name attribute
$ENV_LDAP_FULLNAME_ATTRIBUTE = getenv("LDAP_FULLNAME_ATTRIBUTE");
if (empty($ENV_LDAP_FULLNAME_ATTRIBUTE)) {
  $ENV_LDAP_FULLNAME_ATTRIBUTE = "uid";
}

# set the ldap filter
$ENV_LDAP_FILTER = getenv("LDAP_FILTER");
if (empty($ENV_LDAP_FILTER)) {
  $ENV_LDAP_FILTER = "(&(objectClass=person)($ldap_login_attribute={login}))";
}

#
# password hash options
#

$ENV_HASH= getenv("HASH");
if (empty($ENV_HASH)) {
  $ENV_HASH = "auto";
}

#
# password change options
#

$ENV_USE_CHANGE = getenv("USE_CHANGE");
if (empty($ENV_USE_CHANGE)) {
  $ENV_USE_CHANGE = false;
} elseif (strtolower($ENV_USE_CHANGE) == "true") {
  $ENV_USE_CHANGE = true;
} else {
  $ENV_USE_CHANGE = false;
}

$ENV_USE_QUESTION = getenv("USE_QUESTION");
if (empty($ENV_USE_QUESTION)) {
  $ENV_USE_QUESTION = false;
} elseif (strtolower($ENV_USE_QUESTION) == "true") {
  $ENV_USE_QUESTION = true;
} else {
  $ENV_USE_QUESTION = false;
}

$ENV_USE_TOKENS = getenv("USE_TOKENS");
if (empty($ENV_USE_TOKENS)) {
  $ENV_USE_TOKENS = false;
} elseif (strtolower($ENV_USE_TOKENS) == "true") {
  $ENV_USE_TOKENS = true;
} else {
  $ENV_USE_TOKENS = false;
}

$ENV_USE_SMS = getenv("USE_SMS");
if (empty($ENV_USE_SMS)) {
  $ENV_USE_SMS = false;
} elseif (strtolower($ENV_USE_SMS) == "true") {
  $ENV_USE_SMS = true;
} else {
  $ENV_USE_SMS = false;
}

#
# mail configuration
#
$ENV_MAIL_ATTRIBUTE = getenv("MAIL_ATTRIBUTE");
if (empty($ENV_MAIL_ATTRIBUTE)) {
  $ENV_MAIL_ATTRIBUTE = "mail";
}

$ENV_MAIL_FROM = getenv("MAIL_FROM");
if (empty($ENV_MAIL_FROM)) {
  exit("MAIL_FROM not defined");
}

$ENV_MAIL_FROM_NAME = getenv("MAIL_FROM_NAME");
if (empty($ENV_MAIL_FROM_NAME)) {
  $ENV_MAIL_FROM_NAME = "Self Service Password";
}

$ENV_NOTIFY_ON_CHANGE = getenv("NOTIFY_ON_CHANGE");
if (empty($ENV_NOTIFY_ON_CHANGE)) {
  $ENV_NOTIFY_ON_CHANGE = false;
} elseif (strtolower($ENV_NOTIFY_ON_CHANGE) == "true") {
  $ENV_NOTIFY_ON_CHANGE = true;
} else {
  $ENV_NOTIFY_ON_CHANGE = false;
}

$ENV_MAIL_SENDMAILPATH = getenv("MAIL_SENDMAILPATH");
if (empty($ENV_MAIL_SENDMAILPATH)) {
  $ENV_MAIL_SENDMAILPATH = '/usr/sbin/sendmail';
}

$ENV_MAIL_PROTOCOL = getenv("MAIL_PROTOCOL");
if (empty($ENV_MAIL_PROTOCOL)) {
  $ENV_MAIL_PROTOCOL = "smtp";
}

$ENV_MAIL_SMTP_DEBUG = getenv("MAIL_SMTP_DEBUG");
if (empty($ENV_MAIL_SMTP_DEBUG)) {
  $ENV_MAIL_SMTP_DEBUG = 0;
}

$ENV_MAIL_DEBUG_FORMAT = getenv("MAIL_DEBUG_FORMAT");
if (empty($ENV_MAIL_DEBUG_FORMAT)) {
  $ENV_MAIL_DEBUG_FORMAT = 'html';
}

$ENV_MAIL_SMTP_HOST = getenv("MAIL_SMTP_HOST");
if (empty($ENV_MAIL_SMTP_HOST)) {
  exit("MAIL_SMTP_HOST not defined");
}

$ENV_MAIL_SMTP_AUTH = getenv("MAIL_SMTP_AUTH");
if (empty($ENV_MAIL_SMTP_AUTH)) {
  $ENV_MAIL_SMTP_AUTH = false;
} elseif (strtolower($ENV_MAIL_SMTP_AUTH) == "true") {
  $ENV_MAIL_SMTP_AUTH = true;
} else {
  $ENV_MAIL_SMTP_AUTH = false;
}
$ENV_MAIL_SMTP_USER = getenv("MAIL_SMTP_USER");
$ENV_MAIL_SMTP_PASS = getenv("MAIL_SMTP_PASS");

$ENV_MAIL_SMTP_PORT = getenv("MAIL_SMTP_PORT");
if (empty($ENV_MAIL_SMTP_PORT)) {
  $ENV_MAIL_SMTP_PORT = 25;
}

$ENV_MAIL_SMTP_TIMEOUT = getenv("MAIL_SMTP_TIMEOUT");
if (empty($ENV_MAIL_SMTP_TIMEOUT)) {
  $ENV_MAIL_SMTP_TIMEOUT = 30;
}

$ENV_MAIL_SMTP_KEEPALIVE = getenv("MAIL_SMTP_KEEPALIVE");
if (empty($ENV_MAIL_SMTP_KEEPALIVE)) {
  $ENV_MAIL_SMTP_KEEPALIVE = false;
} elseif (strtolower($ENV_MAIL_SMTP_KEEPALIVE) == "true") {
  $ENV_MAIL_SMTP_KEEPALIVE = true;
} else {
  $ENV_MAIL_SMTP_KEEPALIVE = false;
}

$ENV_MAIL_SMTP_SECURE = getenv("MAIL_SMTP_SECURE");
if (empty($ENV_MAIL_SMTP_SECURE)) {
  $ENV_MAIL_SMTP_SECURE = 'tls';
}

$ENV_MAIL_CONTENTTYPE = getenv("MAIL_CONTENTTYPE");
if (empty($ENV_MAIL_CONTENTTYPE)) {
  $ENV_MAIL_CONTENTTYPE = 'text/plain';
}

$ENV_MAIL_CHARSET = getenv("MAIL_CHARSET");
if (empty($ENV_MAIL_CHARSET)) {
  $ENV_MAIL_CHARSET = 'utf-8';
}

$ENV_MAIL_PRIORITY = getenv("MAIL_PRIORITY");
if (empty($ENV_MAIL_PRIORITY)) {
  $ENV_MAIL_PRIORITY = 3;
}


#
# re-captcha configuraiton
#
$ENV_USE_RECAPTCHA = getenv("USE_RECAPTCHA");
if (empty($ENV_USE_RECAPTCHA)) {
  $ENV_USE_RECAPTCHA = false;
} elseif (strtolower($ENV_USE_RECAPTCHA) == "true") {
  $ENV_USE_RECAPTCHA = true;
} else {
  $ENV_USE_RECAPTCHA = false;
}

$ENV_RECAPTCHA_PUBLICKEY = getenv("RECAPTCHA_PUBLICKEY");
$ENV_RECAPTCHA_PRIVATEKEY = getenv("RECAPTCHA_PRIVATEKEY");

#
# debug mode
#

# password change options
$ENV_DEBUG = getenv("DEBUG");
if (empty($ENV_DEBUG)) {
  $ENV_USE_CHANGE = false;
} elseif (strtolower($ENV_DEBUG) == "true") {
  $ENV_DEBUG = true;
} else {
  $ENV_DEBUG = false;
}

#
# reset url if behind reverse proxy
#

$ENV_RESET_URL = getenv("RESET_URL");
if  (strtolower($ENV_DEBUG) == "true") {
  $reset_url = $_SERVER['HTTP_X_FORWARDED_PROTO'] . "://" . $_SERVER['HTTP_X_FORWARDED_HOST'] . $_SERVER['SCRIPT_NAME'];
}


#==============================================================================
# Configuration
#==============================================================================
# LDAP
$ldap_url = $ENV_LDAP_URL;
$ldap_starttls = $ENV_LDAP_STARTTLS;
$ldap_binddn = $ENV_LDAP_BINDDN;
$ldap_bindpw = $ENV_LDAP_BINDPW;
$ldap_base = $ENV_LDAP_BASE;
$ldap_login_attribute = $ENV_LDAP_LOGIN_ATTRIBUTE;
$ldap_fullname_attribute = $ENV_LDAP_FULLNAME_ATTRIBUTE;
$ldap_filter = $ENV_LDAP_FILTER;

# Active Directory mode
# true: use unicodePwd as password field
# false: LDAPv3 standard behavior
$ad_mode = false;
# Force account unlock when password is changed
$ad_options['force_unlock'] = false;
# Force user change password at next login
$ad_options['force_pwd_change'] = false;
# Allow user with expired password to change password
$ad_options['change_expired_password'] = false;

# Samba mode
# true: update sambaNTpassword and sambaPwdLastSet attributes too
# false: just update the password
$samba_mode = false;
# Set password min/max age in Samba attributes
#$samba_options['min_age'] = 5;
#$samba_options['max_age'] = 45;

# Shadow options - require shadowAccount objectClass
# Update shadowLastChange
$shadow_options['update_shadowLastChange'] = false;

# Hash mechanism for password:
# SSHA
# SHA
# SMD5
# MD5
# CRYPT
# clear (the default)
# auto (will check the hash of current password)
# This option is not used with ad_mode = true
$hash = $ENV_HASH;

# Prefix to use for salt with CRYPT
$hash_options['crypt_salt_prefix'] = "$6$";

# Local password policy
# This is applied before directory password policy
# Minimal length
$pwd_min_length = 0;
# Maximal length
$pwd_max_length = 0;
# Minimal lower characters
$pwd_min_lower = 0;
# Minimal upper characters
$pwd_min_upper = 0;
# Minimal digit characters
$pwd_min_digit = 0;
# Minimal special characters
$pwd_min_special = 0;
# Definition of special characters
$pwd_special_chars = "^a-zA-Z0-9";
# Forbidden characters
#$pwd_forbidden_chars = "@%";
# Don't reuse the same password as currently
$pwd_no_reuse = true;
# Check that password is different than login
$pwd_diff_login = true;
# Complexity: number of different class of character required
$pwd_complexity = 0;
# Show policy constraints message:
# always
# never
# onerror
$pwd_show_policy = "never";
# Position of password policy constraints message:
# above - the form
# below - the form
$pwd_show_policy_pos = "above";

# Who changes the password?
# Also applicable for question/answer save
# user: the user itself
# manager: the above binddn
$who_change_password = "user";

## Standard change
# Use standard change form?
$use_change = $ENV_USE_CHANGE;

## Questions/answers
# Use questions/answers?
# true (default)
# false
$use_questions = $ENV_USE_QUESTION;

# Answer attribute should be hidden to users!
$answer_objectClass = "extensibleObject";
$answer_attribute = "info";

# Extra questions (built-in questions are in lang/$lang.inc.php)
#$messages['questions']['ice'] = "What is your favorite ice cream flavor?";

## Token
# Use tokens?
# true (default)
# false
$use_tokens = $ENV_USE_TOKENS;
# Crypt tokens?
# true (default)
# false
$crypt_tokens = true;
# Token lifetime in seconds
$token_lifetime = "3600";

## Mail
# LDAP mail attribute
$mail_attribute = $ENV_MAIL_ATTRIBUTE;
# Who the email should come from
$mail_from = $ENV_MAIL_FROM;
$mail_from_name = $ENV_MAIL_FROM_NAME;
# Notify users anytime their password is changed
$notify_on_change = $ENV_NOTIFY_ON_CHANGE;
# PHPMailer configuration (see https://github.com/PHPMailer/PHPMailer)
$mail_sendmailpath = $ENV_MAIL_SENDMAILPATH;
$mail_protocol = $ENV_MAIL_PROTOCOL;
$mail_smtp_debug = $ENV_MAIL_SMTP_DEBUG;
$mail_debug_format = $ENV_MAIL_DEBUG_FORMAT;
$mail_smtp_host = $ENV_MAIL_SMTP_HOST;
$mail_smtp_auth = $ENV_MAIL_SMTP_AUTH;
$mail_smtp_user = $ENV_MAIL_SMTP_USER;
$mail_smtp_pass = $ENV_MAIL_SMTP_PASS;
$mail_smtp_port = $ENV_MAIL_SMTP_PORT;
$mail_smtp_timeout = $ENV_MAIL_SMTP_TIMEOUT;
$mail_smtp_keepalive = $ENV_MAIL_SMTP_KEEPALIVE;
$mail_smtp_secure = $ENV_MAIL_SMTP_SECURE;
$mail_contenttype = $ENV_MAIL_CONTENTTYPE;
$mail_charset = $ENV_MAIL_CHARSET;
$mail_priority = $ENV_MAIL_PRIORITY;
$mail_newline = PHP_EOL;


## SMS
# Use sms
$use_sms = $ENV_USE_SMS;
# GSM number attribute
$sms_attribute = "mobile";
# Partially hide number
$sms_partially_hide_number = true;
# Send SMS mail to address
$smsmailto = "{sms_attribute}@service.provider.com";
# Subject when sending email to SMTP to SMS provider
$smsmail_subject = "Provider code";
# Message
$sms_message = "{smsresetmessage} {smstoken}";

# SMS token length
$sms_token_length = 6;

# Max attempts allowed for SMS token
$max_attempts = 3;

# Reset URL (if behind a reverse proxy)
#$reset_url = $_SERVER['HTTP_X_FORWARDED_PROTO'] . "://" . $_SERVER['HTTP_X_FORWARDED_HOST'] . $_SERVER['SCRIPT_NAME'];

# Display help messages
$show_help = true;

# Language
$lang ="en";

# Display menu on top
$show_menu = true;

# Logo
$logo = "images/ltb-logo.png";

# Background image
$background_image = "images/unsplash-space.jpeg";

# Debug mode
$debug = $ENV_DEBUG;

# Encryption, decryption keyphrase
$keyphrase = "secret";

# Where to log password resets - Make sure apache has write permission
# By default, they are logged in Apache log
#$reset_request_log = "/var/log/self-service-password";

# Invalid characters in login
# Set at least "*()&|" to prevent LDAP injection
# If empty, only alphanumeric characters are accepted
$login_forbidden_chars = "*()&|";

## CAPTCHA
# Use Google reCAPTCHA (http://www.google.com/recaptcha)
$use_recaptcha = $ENV_USE_RECAPTCHA;
# Go on the site to get public and private key
$recaptcha_publickey = $ENV_RECAPTCHA_PUBLICKEY;
$recaptcha_privatekey = $ENV_RECAPTCHA_PRIVATEKEY;
# Customization (see https://developers.google.com/recaptcha/docs/display)
$recaptcha_theme = "light";
$recaptcha_type = "image";
$recaptcha_size = "normal";

## Default action
# change
# sendtoken
# sendsms
$default_action = "change";

## Extra messages
# They can also be defined in lang/ files
#$messages['passwordchangedextramessage'] = NULL;
#$messages['changehelpextramessage'] = NULL;

# Launch a posthook script after successful password change
#$posthook = "/usr/share/self-service-password/posthook.sh";

?>