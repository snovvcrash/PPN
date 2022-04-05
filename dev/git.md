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
# Add remote upstream
$ git remote add upstream https://github.com/original/repository.git
$ git fetch upstream
$ git rebase upstream/master (or git merge upstream/master)

# Update fork from original repo
$ git pull upstream master

# Push the updates to fork
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

- [https://www.youtube.com/watch?v=1vVIpIvboSg](https://www.youtube.com/watch?v=1vVIpIvboSg)
- [https://www.youtube.com/watch?v=4166ExAnxmo](https://www.youtube.com/watch?v=4166ExAnxmo)

Cache passphrase in gpg agent (dirty):

```
$ cd /tmp && touch aaa && gpg --sign aaa && rm aaa aaa.gpg && cd -
```




## Submodules

- [https://tech.serhatteker.com/post/2019-01/changing-git-submodules-urlbranch-to/](https://tech.serhatteker.com/post/2019-01/changing-git-submodules-urlbranch-to/)

Edit submodule branch:

```
$ git config --file=.gitmodules -l | grep branch
$ git config --file=.gitmodules submodule.Submod.branch development
$ git submodule sync
$ git submodule update --init --recursive --remote
```
