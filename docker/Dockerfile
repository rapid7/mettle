# To build the dev environment.
# docker build -t rapid7/build:mettle .

FROM ubuntu:16.04
MAINTAINER Brent Cook <bcook@rapid7.com> (@busterbcook)

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get dist-upgrade -y && \
	    apt-get -y install curl build-essential git autoconf automake libtool bison flex gcc ruby rake bundler git mingw-w64 && \
		apt-get clean && \
		rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV JENKINS_HOME /var/jenkins_home
RUN useradd -d "$JENKINS_HOME" -u 1001 -m -s /bin/sh jenkins
VOLUME "$JENKINS_HOME"
RUN chown -R jenkins "$JENKINS_HOME"
RUN echo "jenkins:jenkins" | chpasswd && adduser jenkins sudo
RUN sed -i.bak -e 's/%sudo\s\+ALL=(ALL\(:ALL\)\?)\s\+ALL/%sudo ALL=NOPASSWD:ALL/g' /etc/sudoers
