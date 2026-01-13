# Frontend Dockerfile - uses pre-built dist for faster builds
FROM nginx:alpine

# Copy pre-built dist files to nginx
COPY dist/ /usr/share/nginx/html/

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Note: Healthcheck is configured in docker-compose.yml (uses 127.0.0.1 to avoid IPv6 issues)

CMD ["nginx", "-g", "daemon off;"]
