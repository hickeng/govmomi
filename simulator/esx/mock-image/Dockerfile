FROM photon:5.0  AS rpm-installer

RUN mkdir -p /mnt/shadow-install && tdnf install -y --installroot /mnt/shadow-install/ --releasever=5.0 \
    filesystem toybox python3

# golang:1.18.0-buster amd64
FROM golang@sha256:7d39537344486528f8cdb3bd8adb98ab7f0f4236044b6944fed8631da35a4ce5 AS golang-build

WORKDIR /usr/local/go/src/app

ADD . .
RUN go build app/cmd/interceptor
# TODO: what's the purpose of the temporary temp dir in Dockerfile.vcsim?

FROM scratch

COPY --from=rpm-installer / /.shadow/content
COPY --from=golang-build /usr/local/go/src/app/interceptor /.shadow/meta/
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

