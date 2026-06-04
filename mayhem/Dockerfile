FROM python:3.11-slim

RUN pip install atheris

ADD . /src
WORKDIR /src
RUN python3 -m pip install .

CMD ["/src/mayhem/fuzz_numbers.py"]
