FROM markadams/chromium-xvfb

ADD . /root
ADD sources.list /etc/apt/sources.list

RUN apt update \
&& apt install -y python3 python3-pip procps \
&& pip3 install simplejson requests loguru

WORKDIR /root

ENTRYPOINT ["python3","main.py"]
