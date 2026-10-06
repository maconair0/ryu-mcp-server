# Ryu and Mininet in one image. Ryu does not install on Python 3.12, and Mininet
# needs root and Open vSwitch; a container gives both without touching the host.
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        mininet openvswitch-switch openvswitch-common iproute2 iputils-ping \
        net-tools python3-pip python3-setuptools ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# Ryu 4.34 is the last release; it needs an eventlet old enough to still ship
# eventlet.wsgi.ALREADY_HANDLED.
RUN pip3 install --no-cache-dir "eventlet==0.30.2" "ryu==4.34" "dnspython<2.0" "mininet==2.3.0.dev6"
# Ubuntu's mininet package supplies mnexec but not a Python 3 library.
COPY topo.py start.sh /lab/
RUN chmod +x /lab/start.sh
EXPOSE 8080 6653
CMD ["/lab/start.sh"]
