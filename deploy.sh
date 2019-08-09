tau_path=libtaurus.so
pre_file=/etc/ld.so.preload
prebak_file=/etc/ld.so.preload.bak
conf_path=/etc/taurus.config
confbak_path=/etc/taurus.config.backup
tau_soc=/tmp/taurus.lock
rot_path=/etc/logrotate.d/taurus
logconf_path=/etc/rsyslog.d/taurus.conf
log_path=/var/log/taurus.log
service_path=/etc/init.d/taurus
bin_path=/usr/bin/taurus_starter
status_file=/etc/taurus.status

# 0 - 停机                      1 - 单用户模式          2 - 多用户，没有 NFS
# 3 - 完全多用户模式    4 – 系统保留的          5 - X11                 6 - 重新启动

insert_boot_before_x() {
  i=99 # default to rc.local index
  for f in /etc/rc${1}.d/*; do
    fn=$(basename $f)
    if [[ ${fn:3} == ${2} && ${fn:0:1} == 'S' ]]; then
      i=$((${fn:1:2}-1)) # index
    fi
  done
  np=/etc/rc${1}.d/S${i}${3}
  ln -s ${service_path} ${np}
}

delete_boot_x() {
  for f in /etc/rc${1}.d/*; do
    fn=$(basename $f)
    if [[ ${fn:3} == ${2} ]]; then
      rm $f
    fi
  done
}

if [[ $(uname -m) != 'x86_64' ]]; then 
    echo must be 64bit system
    exit
fi

if [ x$2 = xwithlog ]; then
  tau_path = libtaurus_withlog.so
fi

if [ x$1 = xundeploy ]; then
  if grep -q ${pre_file} /etc/mtab; then
    umount ${pre_file}
  fi
  #ps aux | grep taurus | grep -v grep | awk '{print $2}' | while read proc; do
  #  kill -9 ${proc}
  #done
  rm -f ${status_file}
  delete_boot_x 3 taurus
  delete_boot_x 5 taurus
  rm -rf /etc/taurus*
  rm -f ${log_path} ${rot_path} ${logconf_path} ${service_path} ${tau_soc}
elif [ x$1 = xdeploy ]; then
  if grep -q libsocket ${pre_file}; then
    echo "libsocket.so found in ${pre_file}"
    exit # our libtaurus.so conflict with libsocket.so
  fi
  if grep -q ${pre_file} /etc/mtab; then
    umount ${pre_file}
  fi
  touch ${prebak_file} ${pre_file}
  mkdir -p ${conf_path} ${confbak_path}
  echo -e "${log_path} {" > ${rot_path}
  echo -e "\tdaily" >> ${rot_path}
  echo -e "\tmissingok" >> ${rot_path}
  echo -e "\tcreate 0600 root root" >> ${rot_path}
  echo -e "\trotate 30" >> ${rot_path}
  echo -e "\tmaxsize 100M" >> ${rot_path}
  echo -e "\tcompress" >> ${rot_path}
  echo -e "\tdelaycompress" >> ${rot_path}
  echo -e "}" >> ${rot_path}
  echo :programname,startswith,\"taurus\" -${log_path} > ${logconf_path}
  service rsyslog restart
  chmod 600 ${log_path}
  cp -f ${pre_file} ${prebak_file}
  echo ${tau_path} >> ${prebak_file}
  # mount --bind ${prebak_file} ${pre_file} # 避免taurus本身加载so
elif [ x$1 = xaddservice ]; then
  if [ ! -f ${service_path} ]; then 
    ln -s ${bin_path} ${service_path}
  fi
  find /etc/rc.d | grep taurus | xargs rm -f
  echo ${bin_path} "\"\$@\"" > ${service_path}
  chmod +x ${service_path}
  insert_boot_before_x 3 noah taurus
  insert_boot_before_x 5 noah taurus
else
  echo unknown command $1
fi
