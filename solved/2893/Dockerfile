FROM node:22-bookworm

WORKDIR /app

COPY deploy/package.json deploy/package-lock.json ./deploy/
WORKDIR /app/deploy

RUN npm ci
RUN npx playwright install --with-deps chromium

COPY deploy/ .
COPY flag /flag

EXPOSE 3000

CMD ["npm", "start"]
