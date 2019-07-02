%YAML 1.2
---

#===============================================================================
# Kiwi, Security tool for auditing source code
# Copyright (c) 2016 alpha1e0
# -----------------------------------------------------------------------------
# Sensitive information leaking
#===============================================================================

version: 1.0

engine: GrepEngine

scopes:
  - conan

features:
- ID: RAW_PASSWD_INFO_001
  name: "Password information leaking"
  severity: High
  confidence: High
  references: []
  patterns:
    - \([^\.0-9](?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]\d|[1-9]))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))\
