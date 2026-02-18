Production deployment (fast path)

1) Requirements on target server
   - Docker & docker-compose installed
   - Port 5002 available
   - A user with SSH private key access

2) Quick manual deploy (if you have server access)
   - git clone https://github.com/CasPro48/MyLocalProjects.git
   - cd new-project
   - docker pull ghcr.io/CasPro48/new-project:latest
   - docker-compose -f docker-compose.prod.yml up -d --remove-orphans --no-build

3) Automated: GitHub Actions will build & publish an image on merge to `main`.
   - To enable automatic remote deploy add these repository secrets:
     - DEPLOY_SSH_HOST
     - DEPLOY_SSH_USER
     - DEPLOY_SSH_KEY (private key)
     - DEPLOY_SSH_PORT (optional, default 22)
     - DEPLOY_PATH (optional, default ~/new-project)

4) Healthcheck
   - The service will expose port 5002 and the workflow checks `/` after deployment.
