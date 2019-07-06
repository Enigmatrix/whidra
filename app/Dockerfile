FROM node:11.3-slim
EXPOSE 3000
COPY ./package.json /app/
COPY ./yarn.lock /app/
WORKDIR /app
RUN yarn install
COPY . /app/
RUN yarn build
ENTRYPOINT yarn express:run
