# Config-extractor karton service

Extracts static configuration from samples and memory dumps using the malduck engine.

Author: CERT.pl
Maintainers: nazywam, psrok1, msm

**Consumes:**
```
{
    "type": "sample",
    "stage": "recognized",
    "kind": "runnable",
    "platform": "win32"
},
{
    "type": "sample",
    "stage": "recognized",
    "kind": "runnable",
    "platform": "win64"
},
{
    "type": "sample",
    "stage": "recognized",
    "kind": "runnable",
    "platform": "linux"
},
{
    "type": "analysis",
    "kind": "drakrun-prod"
},
{
    "type": "analysis",
    "kind": "drakrun"
}
```

**Produces:**
```
# Dropped dumps related with static configuration
{
    "type": "sample",
    "stage": "analyzed",
    "kind": "dump",
    "platform": "win32",
    "extension": "exe"
    "payload": {
        "sample": <Resource>, # Dump where config was found
        "parent": <Resource>  # Original executable
    }
}

# Static configuration
{
    "type": "config",
    "family": <str>, # Family name
    "payload": {
        "config": <dict>,     # Static configuration
        "sample": <Resource>, # Dump where config was found
        "parent": <Resource>, # Original executable
    }
}
```
