# Docker

List all running containers:

```
$ docker ps -a
```

Stop all running containers:

```
$ docker stop `docker container ls -aq`
```

Remove stopped containers:

```
$ docker rm -v `docker container ls -aq -f status=exited`
```

Remove all images:

```
$ docker rmi `docker images -aq`
```

Attach to a running container:

```
$ docker exec -it <CONTAINER> /bin/bash
```

Unsorted:

```
$ docker start -ai <CONTAINER>
$ docker cp project/. <CONTAINER>:/root/project
$ docker run --rm -it <CONTAINER> --name <NAME> ubuntu bash
$ docker build -t <USERNAME>/<IMAGE> .
```




## Installation



### Linux


#### docker-engine

```
$ sudo apt install apt-transport-https ca-certificates curl gnupg-agent software-properties-common -y
(Ubuntu) $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
(Kali) $ curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
[$ sudo apt-key fingerprint 0EBFCD88]
(Ubuntu) $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
(Kali) $ echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list
$ sudo apt update
[$ apt-cache policy docker-ce]
$ sudo apt install docker-ce -y
[$ sudo systemctl status docker]
$ sudo usermod -aG docker ${USER}
relogin
[$ docker run --rm hello-world]
```


#### docker-compose

* [https://docs.docker.com/compose/install/#install-compose-on-linux-systems](https://docs.docker.com/compose/install/#install-compose-on-linux-systems)

```
$ sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
$ sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
```
