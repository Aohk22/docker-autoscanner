# docker run --rm -it \
# -v "/path/to/malware/folder:/path/to/mount" \
# -v "/path/to/output-reports:/home/ltk/vt-output/html-reports" \
# <docker_image>

FROM ubuntu:25.10

# system
RUN apt-get update && apt-get install -y python3-full \
	yara clamav wget p7zip-full ssdeep file gawk && \
	rm -rf /var/lib/apt/lists/*

# add user
RUN mkdir /home/ltk
WORKDIR /home/ltk

# files
COPY autoscanner autoscanner
WORKDIR /home/ltk/autoscanner
RUN mkdir -p vt-output/html-reports

RUN chmod +x autoscan.sh
RUN chmod +x bins/trid
RUN chmod +x scripts/*
ENV PATH="/home/ltk/autoscanner:${PATH}"
ENV PATH="/home/ltk/autoscanner/bins:${PATH}"

# create venv
RUN python3 -m venv /home/ltk/venv
RUN /home/ltk/venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/home/ltk/venv/bin:${PATH}"

WORKDIR /home/ltk
CMD ["/bin/bash"]
