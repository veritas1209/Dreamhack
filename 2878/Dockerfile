FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY CMakeLists.txt .
COPY src/ src/

RUN mkdir -p build \
    && cd build \
    && cmake .. \
    && cmake --build . --target mtt_server -j$(nproc)

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libstdc++6 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin ctf

COPY --from=builder /build/build/mtt_server /home/ctf/mtt_server
RUN chmod +x /home/ctf/mtt_server

RUN echo "DH{fake_flag}" > /flag \
    && chmod 444 /flag

EXPOSE 9000

USER ctf
CMD ["/home/ctf/mtt_server", "9000"]
