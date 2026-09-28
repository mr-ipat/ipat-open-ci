FROM scratch
# The secret-safe outer umask must not make the non-root app binary
# unexecutable in the scratch image; set only this file's mode explicitly.
COPY --chmod=0755 target/x86_64-unknown-linux-musl/release/usp-controller /usp-controller
USER 65532:65532
EXPOSE 3100
ENTRYPOINT ["/usp-controller"]
