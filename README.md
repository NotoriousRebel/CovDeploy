# CovDeploy
## Usage
```bash
adduser -u 
git clone --recursive https://github.com/NotoriousRebel/CovDeploy
echo HOST_IP=^YOUR_IP^ >> .env
echo USERNAME=^USERNAME^ >> .env
echo PASSWORD=^PASSWORD^ >> .env
docker-compose up -d covenant 
docker-compose run elite
```
