#!/bin/bash -e
echo "start server"
export IPAM_HOME=$(cd $(dirname $0); pwd)

LISTEN_PORT=8000

OPTS="-b 0.0.0.0:${LISTEN_PORT} -w 1 app:app"
OPTS="$OPTS --keyfile ${IPAM_HOME}/server.key --certfile ${IPAM_HOME}/server.crt"
OPTS="$OPTS --access-logfile ${IPAM_HOME}/access.log"

# cleanup
cd $IPAM_HOME
rm -f *.pyc


# configure
export IPAM_CONFIG=$IPAM_HOME/ipam.cfg


# start
echo "Application directory: $IPAM_HOME"
. .venv/bin/activate
gunicorn $OPTS
