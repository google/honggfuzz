FROM ubuntu:rolling

RUN apt-get -y update && apt-get install -y \
    gcc \
    git \
    make \
    pkg-config \
	libipt-dev \
	libunwind8-dev \
	binutils-dev \
&& rm -rf /var/lib/apt/lists/* && rm -rf /honggfuzz

RUN git clone --depth=1 https://github.com/google/honggfuzz.git

WORKDIR /honggfuzz

RUN make && cp /honggfuzz/honggfuzz /bin
