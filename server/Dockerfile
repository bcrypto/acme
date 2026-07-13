FROM btls/flask

RUN apt-get update

RUN apt-get install -y -q swig

ENV HOME /root
WORKDIR $HOME

RUN git clone --recurse-submodules https://github.com/bcrypto/bee2ports.git
WORKDIR $HOME/bee2ports/bee2
RUN mkdir build
WORKDIR $HOME/bee2ports/bee2/build
RUN cmake ..
RUN make 
RUN make install
WORKDIR $HOME/bee2ports
RUN ls -lah /
RUN swig -python -cpperraswarn -o bee2py/bee2_wrap.c -outdir bee2py bee2.i 
RUN python3 -m pip install .

COPY . /acme


