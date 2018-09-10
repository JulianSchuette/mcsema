FROM ubuntu:16.04

############################################################################################################
# Dockerfile for building mcsema and remill
# i386 dependencies are for IDA Pro only.
# IDA is not required for building, but for running mcsema-disass with the default IDA disassembler backend
#
# Run mcsema-lift like this:
# docker run -ti --rm --name mcsema \
#              -e DISPLAY=$DISPLAY -e QT_X11_NO_MITSHM=1 -v /tmp/.X11-unix:/tmp/.X11-unix:ro 
#              -v ${PWD}:/root/data -v /opt/ida-6.8:/opt/ida \
#              mcsema:latest
#
# Or hop into the container and run mcsema-disass:
# mcsema-disass --disassembler /opt/ida/idal --arch aarch64 --os linux --output /root/data/DIVA.cfg --binary <binary> --entrypoint main
############################################################################################################
RUN dpkg --add-architecture i386 \
	&& apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y \
     git \
     curl \
     cmake \
     python2.7 python-pip python-virtualenv \
     wget \
     build-essential \
     gcc-multilib g++-multilib \
     libc6-dev-arm64-cross \
     libtinfo-dev \
     lsb-release \
     libglib2.0-dev:i386 \
     libfreetype6:i386 \
     libsm6:i386 \
     libpython2.7:i386 \
     libc6-i686:i386 libexpat1:i386 libffi6:i386 libfontconfig1:i386 libfreetype6:i386 libgcc1:i386 libglib2.0-0:i386 libice6:i386 libpcre3:i386 libpng12-0:i386 libsm6:i386 libstdc++6:i386 libuuid1:i386 libx11-6:i386 libxau6:i386 libxcb1:i386 libxdmcp6:i386 libxext6:i386 libxrender1:i386 zlib1g:i386 \
     realpath \
     zlib1g-dev \
     wget \
	&& apt-get autoremove -y \
	&& rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN git clone --depth 1 https://github.com/trailofbits/mcsema.git \
	&& export REMILL_VERSION=`cat ./mcsema/.remill_commit_id` \
	&& git clone https://github.com/trailofbits/remill.git \
	&& cd remill \
	&& git checkout -b temp ${REMILL_VERSION} \
	&& mv ../mcsema tools \
	&&  ./scripts/build.sh \
	&& cd remill-build \
	&& make install
ENV TERM xterm
ENTRYPOINT ["/usr/local/bin/mcsema-lift-4.0"]
