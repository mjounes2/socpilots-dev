FROM node:20-alpine
RUN apk add --no-cache nmap nmap-scripts
WORKDIR /app
COPY server.js .
EXPOSE 7777
CMD ["node", "server.js"]
