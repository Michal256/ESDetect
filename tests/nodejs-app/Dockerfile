FROM node:25.2.1-trixie

WORKDIR /app
COPY ./app /app

RUN npm install


EXPOSE 3000

CMD ["node", "server.js"]
