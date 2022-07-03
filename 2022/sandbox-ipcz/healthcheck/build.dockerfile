FROM ubuntu:20.04 as build

# install required deps
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -yq --no-install-recommends build-essential git ca-certificates python3-pkgconfig curl python3

# install depot_tools
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git /opt/depot_tools
ENV PATH="/opt/depot_tools:${PATH}"

RUN mkdir /build
RUN git clone https://github.com/krockot/ipcz.git /build/ipcz && cd /build/ipcz && git checkout 6a6ebe43c2cb86882b0df9bf888dc5d34037f015
RUN cd /build/ipcz && cp .gclient-default .gclient && gclient sync

COPY exploit.patch /build/
RUN cd /build/ipcz && patch -p1 < /build/exploit.patch

RUN mkdir /build/ipcz/src/exploit/
COPY exploit.cc BUILD.gn /build/ipcz/src/exploit/

RUN cd /build/ipcz/ && gn gen out && ninja -C out exploit

CMD /bin/true
