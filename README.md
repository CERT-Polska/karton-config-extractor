# Config-extractor karton service

Extracts static configuration from samples and memory dumps using the malduck engine.

**Author**: CERT.pl

**Maintainers**: nazywam, psrok1, msm

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
    "kind": "drakrun"
},
{
    "type": "analysis",
    "kind": "joesandbox"
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


## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton

Then install karton-config-extractor from PyPi:

```shell
$ pip install karton-config-extractor

$ karton-config-extractor --modules malduck-extractor-modules/
```

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
