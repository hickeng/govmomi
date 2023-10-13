FROM photon:5.0  AS rpm-installer

RUN mkdir -p /mnt/shadow/{base,extras} && tdnf install -y --installroot /mnt/shadow/base --releasever=5.0 filesystem glibc
RUN tdnf install -y --installroot /mnt/shadow/extras/ --releasever=5.0 toybox


# golang:1.18.0-buster amd64
FROM golang:1.19 AS interpose-build

WORKDIR /usr/local/go/src/app
RUN go install github.com/go-delve/delve/cmd/dlv@latest

ADD . .
RUN go build -o interpose app/cmd/interpose



FROM busybox
#FROM scratch

#TODO: add dlv - we'll want debugging support in the simhost

# copy additional libraries in from extras and set up rtld load path to search them
COPY --from=rpm-installer /mnt/shadow/extras/ /.shadow/content/
ENV LD_LIBRARY_PATH=/.shadow/content/lib:/.shadow/content/usr/lib:/.shadow/content/lib64:/.shadow/content/usr/lib64:$LD_LIBRARY_PATH

# glibc/lib needs to match precise versions with ld-linux.so.2 and the absolute path to that is hardcoded into binaries.
# so we need to have those in the expected abs location for invoking anything from the shadow content
COPY --from=rpm-installer /mnt/shadow/base/ /
ENV LD_LIBRARY_PATH=/lib:/usr/lib:/lib64:/usr/lib64:$LD_LIBRARY_PATH

COPY --from=interpose-build /go/bin/dlv /.shadow/content/go/bin/
COPY --from=interpose-build /usr/local/go/src/app/interpose /.shadow/meta/

#TODO: replace with symlink/hardlink when shell is available
COPY --from=interpose-build /usr/local/go/src/app/interpose /usr/bin/toybox

COPY *.json /.shadow/meta/

#COPY mocks /.shadow/overrides
#COPY base-esx-filesystem-manifest.json /.shadow/meta/

#RUN /.shadow/meta/interceptor --install --target / --default-source /.shadow/content --override-source /.shadow/overrides --config /.shadow/meta/esx-filesystem-manifest.json

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


#ENTRYPOINT [ "/bin/toybox" ]
#CMD [  ]
