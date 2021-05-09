# Git

Add SSH key to the ssh-agent:

```
$ eval "$(ssh-agent -s)"
$ ssh-add ~/.ssh/id_rsa
```

Update to latest version:

```
$ sudo add-apt-repository ppa:git-core/ppa -y
$ sudo apt update
$ sudo apt install git -y
$ git version
```




## Pull Requests

Syncing a forked repository:

```
$ git remote add upstream https://github.com/original/repository.git
$ git fetch upstream
$ git checkout --track master
$ git rebase upstream/master (or git merge upstream/master)
$ git push -f origin master
```

Working with a repository during a pull request:

```
$ git remote add upstream https://github.com/original/repository.git
$ git fetch upstream
$ git rebase upstream/master
$ git checkout upstream/master
$ git checkout -b new-feature
...Make changes...
$ gc -am "Add a new feature"
$ git push -u origin new-feature
```




## Signing Git Commits

* [https://www.youtube.com/watch?v=1vVIpIvboSg](https://www.youtube.com/watch?v=1vVIpIvboSg)
* [https://www.youtube.com/watch?v=4166ExAnxmo](https://www.youtube.com/watch?v=4166ExAnxmo)

Cache passphrase in gpg agent (dirty):

```
$ cd /tmp && touch aaa && gpg --sign aaa && rm aaa aaa.gpg && cd -
```
