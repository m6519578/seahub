#!/bin/bash

echo ""

SCRIPT=$(readlink -f "$0")
PARENTDIR=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${PARENTDIR}")
INSTALLPATH=$TOPDIR/seafile-server-latest
default_ccnet_conf_dir=${TOPDIR}/ccnet

manage_py=${INSTALLPATH}/seahub/manage.py
gunicorn_conf=${INSTALLPATH}/runtime/seahub.conf
pidfile=${INSTALLPATH}/runtime/seahub.pid
errorlog=${INSTALLPATH}/runtime/error.log
accesslog=${INSTALLPATH}/runtime/access.log

pro_pylibs_dir=${INSTALLPATH}/pro/python


function read_seafile_data_dir () {
    seafile_ini=${default_ccnet_conf_dir}/seafile.ini
    if [[ ! -f ${seafile_ini} ]]; then
        echo "${seafile_ini} not found. Now quit"
        exit 1
    fi
    seafile_data_dir=$(cat "${seafile_ini}")
    if [[ ! -d ${seafile_data_dir} ]]; then
        echo "Your seafile server data directory \"${seafile_data_dir}\" is invalid or doesn't exits."
        echo "Please check it first, or create this directory yourself."
        echo ""
        exit 1;
    fi
}

read_seafile_data_dir;

export LANG='en_US.UTF-8'
export LC_ALL='en_US.UTF-8'
export SEAHUB_LOG_DIR=${TOPDIR}/logs
export CCNET_CONF_DIR=${default_ccnet_conf_dir}
export SEAFILE_CONF_DIR=${seafile_data_dir}
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.6/site-packages:${INSTALLPATH}/seafile/lib64/python2.6/site-packages:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH
export PYTHONPATH=$PYTHONPATH:$pro_pylibs_dir
export PYTHONPATH=$PYTHONPATH:${INSTALLPATH}/seahub-extra/
export PYTHONPATH=$PYTHONPATH:${INSTALLPATH}/seahub-extra/thirdparts
export PYTHONPATH=/usr/lib64/python2.6/site-packages/pymssql-2.1.1-py2.6-linux-x86_64.egg:$PYTHONPATH
export SEAFES_DIR=$pro_pylibs_dir/seafes
PYTHON=python2.6
$PYTHON "${manage_py}" migrate_verify_result
