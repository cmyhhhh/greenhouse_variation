kill -9 $(ps -ef | grep qemu | awk '{print $3}')
kill -9 $(ps -ef | grep qemu | awk '{print $2}')
kill -9 $(ps -ef | grep /gh | awk '{print $2}')