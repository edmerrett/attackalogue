FROM nginx:1.23.3

RUN rm /etc/nginx/nginx.conf
COPY nginx/nginx.conf /etc/nginx/
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx/project.conf /etc/nginx/conf.d/
