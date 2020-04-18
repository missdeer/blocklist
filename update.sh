#!/bin/bash
git pull
env GOROOT=$HOME/go $HOME/go/bin/go build update.go
$PWD/update
git checkout -b emptybranch
git rm -rf *
git update-ref -d refs/heads/emptybranch
git add LICENSE README.md update.go update.sh *.lst .travis.yml
git commit -m "update list at $(date)"
git branch -D master
git branch -m master
git push -f origin master
