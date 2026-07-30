FROM alpine:3

RUN apk add --no-cache openssh bash procps ncurses-terminfo \
 && adduser -D -s /bin/bash test \
 && echo 'test:testpass' | chpasswd \
 && ssh-keygen -A \
 && printf 'PasswordAuthentication yes\nAllowTcpForwarding yes\n' > /etc/ssh/sshd_config.d/99-e2e.conf

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
