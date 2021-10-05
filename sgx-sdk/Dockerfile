FROM baiduxlab/sgx-rust:latest as builder

SHELL ["/bin/bash", "-c"]

WORKDIR /root/sgx

COPY buildenv.mk /root/sgx
RUN mkdir examples
COPY examples /root/sgx/examples

RUN apt-get update && apt-get install -y subversion
RUN svn export https://github.com/apache/incubator-teaclave-sgx-sdk/trunk/sgx_edl
    