FROM httpd:2.4.58@sha256:42ed559bb8529283236b537155e345b47051ed082200c7d7e155405b3e169235

COPY ./deploy/modules /usr/local/apache2/my_modules
COPY ./deploy/custom.conf /usr/local/apache2/conf/custom.conf
COPY ./deploy/flag /flag

RUN echo "\nInclude conf/custom.conf" >> /usr/local/apache2/conf/httpd.conf