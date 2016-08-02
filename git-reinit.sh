#!/bin/bash
rm -rf .git/
git init
git remote add origin git@github.com:dejavuln/dejavuln.github.io.git
git add .
git commit -m "init"
git log
git push origin master
