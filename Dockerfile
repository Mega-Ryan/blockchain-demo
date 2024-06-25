FROM       node:alpine 

LABEL      maintainer=https://github.com/Mega-Ryan/blockchain-demo

EXPOSE     3000

WORKDIR    /blockchain-demo 

COPY       package.json /blockchain-demo

RUN        npm install

COPY       . /blockchain-demo 

CMD        ["node", "bin/www"]