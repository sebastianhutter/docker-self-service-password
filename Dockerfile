FROM php:7.1-apache

#
# simple httpd container running 'self-service-password'
# https://ltb-project.org/documentation/self-service-password
#

ARG SELFSERVICEPASSWORD_VERSION=1.0

RUN apt-get update && apt-get install -y \
  libldb-dev libldap2-dev libmcrypt-dev gettext sendmail \
  && ln -s /usr/lib/x86_64-linux-gnu/libldap.so /usr/lib/libldap.so \
  && docker-php-ext-install mcrypt \
  && docker-php-ext-install ldap \
  && rm -rf /var/lib/apt/lists/*

RUN curl -Lo /tmp/ltb-project-self-service-password-${SELFSERVICEPASSWORD_VERSION}.tar.gz \
    https://ltb-project.org/archives/ltb-project-self-service-password-${SELFSERVICEPASSWORD_VERSION}.tar.gz \
  && tar -xzf /tmp/ltb-project-self-service-password-${SELFSERVICEPASSWORD_VERSION}.tar.gz -C /tmp \
  && rm -f /tmp/ltb-project-self-service-password-${SELFSERVICEPASSWORD_VERSION}.tar.gz \
  && mv /tmp/ltb-project-self-service-password-${SELFSERVICEPASSWORD_VERSION}/* /var/www/html/

ADD build/var/www/html/conf/config.inc.php /var/www/html/conf/config.inc.php

RUN  chown -R www-data:www-data /var/www/html/*
