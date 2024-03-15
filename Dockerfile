FROM node:alpine

WORKDIR '/id-provider'
COPY ./package.json ./

RUN npm install 
COPY . . 

EXPOSE 3002
CMD [ "npx", "tsc" ]