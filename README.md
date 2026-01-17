# main-nav

## Docker Compose

`nano compose.yaml`

```
services:
  main-nav:
    image: ghcr.io/exltnrn/main-nav:latest
    container_name: main-nav
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - main_nav_data:/app/data

volumes:
  main_nav_data:
```

`docker compose up -d`
