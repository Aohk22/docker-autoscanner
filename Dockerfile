# docker run --rm -it \
# -v "/path/to/malware/folder:/malware" \
# -v "/path/to/output:/vt_output/html_reports" \
# <docker_image>

FROM ubuntu:25.10
RUN apt-get update && apt-get install -y python3-full \
	yara clamav wget p7zip-full ssdeep file gawk && \
	rm -rf /var/lib/apt/lists/*


COPY autoscanner autoscanner
WORKDIR /autoscanner

RUN chmod +x autoscan.sh
RUN chmod +x bins/trid
RUN chmod +x scripts/*
ENV PATH="/autoscanner:${PATH}"
ENV PATH="/autoscanner/bins:${PATH}"

RUN python3 -m venv /venv
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/venv/bin:${PATH}"

CMD ["/bin/bash"]
