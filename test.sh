/usr/bin/bash -c "/usr/bin/sleep 1; /usr/bin/touch /tmp/foo1" &
/usr/bin/sleep 1
/usr/bin/mkdir /tmp/bar
/usr/bin/echo foo >> /tmp/foo
/usr/bin/echo foo > /tmp/foo
/usr/bin/rm -r /tmp/bar
/usr/bin/rm /tmp/foo
test -f /tmp/foo222 && echo foo
readlink /etc/localtime
/usr/bin/bash -c "/usr/bin/sleep 1; /usr/bin/touch /tmp/foo1" &
