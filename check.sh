#!/usr/bin/env bash

while IFS= read -r pattern; do
  if grep -qiF "$pattern" subdomains-10000.txt; then
    echo "[FOUND] $pattern"
  else
    echo "[MISS ] $pattern"
  fi
done < subs.txt
