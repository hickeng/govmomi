# golang:1.18.0-buster amd64
FROM golang:1.19 AS interpose-build

WORKDIR /usr/local/go/src/app
RUN go install github.com/go-delve/delve/cmd/dlv@latest

ADD . .
RUN go build -o interpose app/cmd/interpose


# construct the mock-esx filesystem
FROM photon:5.0  AS rpm-installer

COPY --from=interpose-build /go/bin/dlv /go/bin/
COPY --from=interpose-build /usr/local/go/src/app/interpose /opt/

#COPY mocks /.shadow/overrides
COPY esx-filesystem-manifest.json /opt/
# TODO: remove direct tdnf invocation once the interpose installer logic is done
#RUN /opt/interpose --install --target / --default-source /.shadow/content --override-source /.shadow/overrides --config /opt/esx-filesystem-manifest.json

RUN tdnf makecache && tdnf -y update && tdnf install -y rpm

# construct the base portions of the mock filesystem that we have no flex on because of linux conventions.
RUN mkdir -p /mnt/shadow/{base/.shadow/meta,extras} && tdnf install -y --installroot /mnt/shadow/base --releasever=5.0 filesystem
RUN mkdir /download && tdnf install -y --nodeps --downloadonly --downloaddir=/download --installroot=/download --releasever 5.0 glibc glibc-libs
RUN cd /mnt/shadow/base && rpm2cpio /download/glibc-2*.rpm | cpio -idmu && rpm2cpio /download/glibc-libs-2*.rpm | cpio -idmu

# construct the shadow portion of the mock image that we can reference indirectly
RUN tdnf install -y --installroot /mnt/shadow/extras --releasever=5.0 toybox bash

RUN rm -fr /mnt/shadow/{base,extras}/var/cache/tdnf


FROM scratch
# copy additional libraries in from extras and set up rtld load path to search them
COPY --from=rpm-installer /mnt/shadow/extras/ /.shadow/content/
ENV LD_LIBRARY_PATH=/.shadow/content/lib:/.shadow/content/usr/lib:/.shadow/content/lib64:/.shadow/content/usr/lib64:$LD_LIBRARY_PATH

# glibc/lib needs to match precise versions with ld-linux.so.2 and the absolute path to that is hardcoded into binaries.
# so we need to have those in the expected abs location for invoking anything from the shadow content
COPY --from=rpm-installer /mnt/shadow/base /
#COPY --from=rpm-installer /mnt/shadow/extras/usr/lib/ld-linux-x86-64.so.2 /usr/lib
#COPY --from=rpm-installer /mnt/shadow/extras/usr/lib/libc.* /usr/lib
ENV LD_LIBRARY_PATH=/lib:/usr/lib:/lib64:/usr/lib64:$LD_LIBRARY_PATH

COPY --from=interpose-build /go/bin/dlv /.shadow/content/go/bin/

# bootstrap the utils needed to create symlinks instead of copies.
# "ln" first as we use invocation name to determine function in toybox, and "ln" allows us to determine that.
COPY --from=interpose-build /usr/local/go/src/app/interpose /bin/ln
# RUN [...] avoids the "/bin/sh" interpreter wrapping as we don't currently have a /bin/sh to wrap with
RUN [ "/bin/ln", "/bin/ln", "/.shadow/meta/interpose" ]
RUN [ "/bin/ln", "-s", "/.shadow/meta/interpose", "/bin/sh" ]

# TODO: figure out which of these is needed after manifest is in place.
# This pivots the "ln" from being a hardlink to a symlink after it's been used to place the interpose binary
# Wouldn't bother but inspecting inodes shows that hardlinks are being broken by the Dockerbuild layers for some reason
RUN for i in /usr/bin/{ln,ls,toybox,du,rm}; do ln -sf /.shadow/meta/interpose $i;done

COPY *.json /.shadow/meta/


#TODO: figure out if we need to/how we can/ run multiple processes in the 'host'
#TODO: figure out if we should leave it to the test to invoke a primary host process other than "pause"

# Require test authors to specify via Dockerfile what they want to run in the sim host?
# Fake a jumpstart and run that?

#? create a Go process that's the base mock logger. If run as logger it sits there waiting for invocations
# all missing execs are linked to the base program - if run not as logger, it pushes the invocation to the logger to act on
# this can be run as a basic process, or via delve allowing arbitrary debug/interception.
# this allows us a single point where we can inject failures, route how the mock should be handled, etc.
# provides an easy way to say; this command gets directed back to test harness, run this script, etc.
#? will this be an issue from a process tree standpoint? Maybe - if necessary, some commands could result in a backflow of logic, whether a socket to use, command to execve with, etc.

ENTRYPOINT [ "/bin/sh" ]