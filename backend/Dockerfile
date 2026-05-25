FROM node:20

WORKDIR /app

COPY backend/package*.json ./

RUN npm install

COPY backend .

EXPOSE 7860

CMD ["node", "server.js"]