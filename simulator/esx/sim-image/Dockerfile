FROM golang:1.19 as interpose-build

WORKDIR /src

COPY . /src

RUN go build -o interpose .


FROM photon:5.0

RUN mkdir -p /.interpose/bin
COPY --from=interpose-build /src/interpose /.interpose/bin

RUN ln -s /.interpose/bin/interpose /bin/test-bin && ln /.interpose/bin/interpose /bin/test-bin-hard

CMD /bin/bash


