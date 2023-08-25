FROM ghcr.io/nilfoundation/evm-solana-verification/environment:latest
RUN useradd --system ${uid:+--uid "$uid"} --user-group --shell /sbin/nologin --create-home --home-dir /home test
RUN chown test:test /home
USER test
