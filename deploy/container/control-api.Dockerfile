FROM scratch
# Compiler inherits the outer secret-safe umask 077; make this *single*
# health-only binary executable for the non-root runtime UID explicitly.
COPY --chmod=0755 target/x86_64-unknown-linux-musl/release/control-api /control-api
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/control-api"]
