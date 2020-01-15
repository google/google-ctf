FROM tsuro/nsjail
COPY files /home/user
#COPY tmpflag /flag
CMD /bin/sh -c "/usr/bin/setup_cgroups.sh && su user -c '/usr/bin/nsjail -Ml --port 1337 --chroot / --user 1000 --group 1000 --cgroup_mem_max 209715200 --cgroup_pids_max 100 --cgroup_cpu_ms_per_sec 100 --rlimit_as max --rlimit_cpu max --rlimit_nofile max --rlimit_nproc max -- /usr/bin/stdbuf -i0 -o0 -e0  /usr/bin/maybe_pow.sh /home/user/chal'"
