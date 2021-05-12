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
},
```

While `sample` type is self explanatory, the `analysis` type might be confusing. The `analysis` task is an output from
one of sandboxes: `drakvuf-sandbox`, `cuckoo`, or `joesandbox`. Analysis is a `sample` with additional memory dumps
attached.

The `analysis` type task is expected to be in format:
```
task = Task(
    headers={"type": "analysis"}
    payloads={
        "dumps_metadata": [
            {"filename": <dump1_filename>, "base_addr": <dump1_baseaddr>},
            {"filename": <dump2_filename>, "base_addr": <dump2_baseaddr>},
            {"filename": <dump3_filename>, "base_addr": <dump3_baseaddr>},
            [...]],
        },
    resources={
        "sample": <sample>
        "dumps.zip": <packed memory dumps in zip format>
    }
)
```
where `dumps_metadata` contains information about filename and base address for every memory dump in `dumps.zip`.

The extractor tries to retrieve config from each memory dump and will pick only the best candidate from each malware
family.

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
