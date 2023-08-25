FROM node:18
WORKDIR /home
RUN useradd --system ${uid:+--uid "$uid"} --user-group --shell /sbin/nologin --create-home --home-dir /home test
RUN chown test:test /home
USER test
