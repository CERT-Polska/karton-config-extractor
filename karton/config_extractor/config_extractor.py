#!/usr/bin/python3
import argparse
import gc
import hashlib
import json
import os
from collections import defaultdict, namedtuple
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Tuple

from karton.core import Config, Karton, Resource, Task
from karton.core.resource import ResourceBase
from malduck.extractor import ExtractManager, ExtractorModules

from .__version__ import __version__
from .util import config_dhash

DumpInfo = namedtuple("DumpInfo", ("path", "base"))


class AnalysisExtractManager(ExtractManager):
    """
    Patched version of original ExtractManager, providing current karton interface
    """

    def __init__(self, karton: "ConfigExtractor") -> None:
        super(AnalysisExtractManager, self).__init__(karton.modules)
        self.karton = karton


def create_extractor(karton: "ConfigExtractor") -> AnalysisExtractManager:
    return AnalysisExtractManager(karton)


class ConfigExtractor(Karton):
    """
    Extracts configuration from samples and Drakvuf Sandbox analyses
    """

    identity = "karton.config-extractor"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "win32",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "win64",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "linux",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "freebsd",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "netbsd",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "openbsd",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "kind": "runnable",
            "platform": "solaris",
        },
        {"type": "analysis"},
    ]

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument(
            "--modules",
            help="Malduck extractor modules directory",
            default="extractor/modules",
        )
        parser.add_argument(
            "--tag",
            help="Add specified tag to all produced configs",
            default=[],
            nargs="+",
        )
        parser.add_argument(
            "--attribute",
            help="Add specified attribute to all produced configs (format: key=value)",
            default=[],
            nargs="+",
        )
        return parser

    @classmethod
    def config_from_args(cls, config: Config, args: argparse.Namespace) -> None:
        super().config_from_args(config, args)
        attributes: DefaultDict[str, List[str]] = defaultdict(list)
        for attr in args.attribute:
            key, value = attr.split("=", 1)
            attributes[key].append(value)
        config.load_from_dict(
            {
                "config-extractor": {
                    "modules": args.modules,
                    "result_tags": args.tag,
                    "result_attributes": attributes,
                }
            }
        )

    def __init__(self, config: Config) -> None:
        """
        Create instance of the ConfigExtractor.

        :param config: Karton configuration object
        """
        super().__init__(config)

        self.modules = ExtractorModules(config.get("config-extractor", "modules"))
        self.result_tags = config.get("config-extractor", "result_tags", fallback=[])
        self.result_attributes = config.get(
            "config-extractor", "result_attributes", fallback={}
        )

    def preprocess_config(
        self, config: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[Task]]:
        legacy_config = dict(config)
        legacy_config["type"] = config["family"]
        del legacy_config["family"]

        karton_tasks = []

        # This allows us to spawn karton tasks for special config handling
        if "store-in-karton" in legacy_config:
            self.log.info("Karton tasks found in config, sending")

            for karton_task in legacy_config["store-in-karton"]:
                task_data = karton_task["task"]
                payload_data = karton_task["payload"]
                karton_tasks.append(Task(headers=task_data, payload=payload_data))

            del legacy_config["store-in-karton"]
        return legacy_config, karton_tasks

    def report_config(
        self,
        task: Task,
        config: Dict[str, Any],
        sample: ResourceBase,
        parent: Optional[ResourceBase] = None,
    ) -> None:
        dhash = config_dhash(config)

        family = config["type"]
        task = Task(
            {
                "type": "config",
                "kind": "static",
                "family": family,
                "quality": task.headers.get("quality", "high"),
            },
            payload={
                "config": config,
                "executed_sample": sample,
                "dhash": dhash,
                "parent": parent or sample,
                "tags": self.result_tags,
                "attributes": self.result_attributes,
            },
        )
        self.send_task(task)
        if parent:
            self.send_sample_tag_task(parent, [family])
            self.send_sample_tag_task(sample, [f"ripped:{family}"])
        else:
            self.send_sample_tag_task(sample, [f"ripped:{family}", family])

    def send_sample_tag_task(self, sample: ResourceBase, tags: List[str]) -> None:
        task = Task(
            {
                "type": "sample",
                "stage": "analyzed",
            },
            payload={
                "sample": sample,
                "tags": tags,
            },
        )
        self.send_task(task)

    # analyze a standard, non-dump sample
    def analyze_sample(self, task: Task, sample: ResourceBase) -> None:
        extractor = create_extractor(self)
        with sample.download_temporary_file() as temp:  # type: ignore
            extractor.push_file(temp.name)

        for config in extractor.config:
            legacy_config, karton_tasks = self.preprocess_config(config)

            if len(legacy_config) > 1:
                self.log.info("Got config: %s", json.dumps(legacy_config))
                self.report_config(task, legacy_config, sample)

            for child_task in karton_tasks:
                child_task.payload["parent"] = sample
                self.send_task(child_task)
                self.log.info("Sending ripped task %s", task.uid)

        self.log.info("Finished processing sample")

    def analyze_dumps(
        self, task: Task, sample: ResourceBase, dump_infos: List[DumpInfo]
    ) -> None:
        """
        Analyse multiple dumps from given sample. There can be more than one
        dump from which we managed to extract config from – try to find the best
        candidate for each family.
        """
        extractor = create_extractor(self)
        dump_candidates = {}

        results = {
            "analysed": 0,
            "crashed": 0,
        }

        for i, dump_info in enumerate(dump_infos):
            dump_basename = os.path.basename(dump_info.path)
            results["analysed"] += 1
            self.log.debug(
                "Analyzing dump %d/%d %s", i, len(dump_infos), str(dump_basename)
            )

            dump_path = Path(dump_info.path)

            if not dump_path.exists():
                self.log.warning("Dump {} doesn't exist".format(dump_basename))
                continue

            dump_data = dump_path.read_bytes()

            if not dump_data:
                self.log.warning("Dump {} is empty".format(dump_basename))
                continue

            try:
                family = extractor.push_file(dump_info.path, base=dump_info.base)
                if family:
                    self.log.info("Found better %s config in %s", family, dump_basename)
                    dump_candidates[family] = (dump_basename, dump_data)
            except Exception:
                self.log.exception(
                    "Error while extracting from {}".format(dump_basename)
                )
                results["crashed"] += 1

            self.log.debug("Finished analysing dump no. %d", i)

        self.log.info("Merging and reporting extracted configs")
        for family, config in extractor.configs.items():
            dump_basename, dump_data = dump_candidates[family]
            self.log.info("* (%s) %s => %s", family, dump_basename, json.dumps(config))

            legacy_config, karton_tasks = self.preprocess_config(config)
            karton_task_parent = sample

            if len(legacy_config) > 1:
                parent = Resource(name=dump_basename, content=dump_data)
                karton_task_parent = parent
                task = Task(
                    {
                        "type": "sample",
                        "stage": "analyzed",
                        "kind": "dump",
                        "platform": "win32",
                        "extension": "exe",
                    },
                    payload={
                        "sample": parent,
                        "parent": sample,
                        "tags": ["dump:win32:exe"],
                    },
                )
                self.send_task(task)
                self.report_config(task, legacy_config, sample, parent=parent)
            else:
                self.log.info("Final config is empty, not sending it to the reporter")

            for child_task in karton_tasks:
                child_task.payload["parent"] = karton_task_parent
                self.send_task(child_task)
                self.log.info("Sending ripped task %s", task.uid)

        self.log.info("done analysing, results: {}".format(json.dumps(results)))

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        headers = task.headers

        if headers["type"] == "sample":
            self.log.info(f"Analyzing original binary: {sample.sha256}")
            self.analyze_sample(task, sample)
        elif headers["type"] == "analysis":
            sample_hash = hashlib.sha256(sample.content or b"").hexdigest()
            self.log.info(f"Processing analysis, sample: {sample_hash}")
            dumps = task.get_resource("dumps.zip")
            dumps_metadata = task.get_payload("dumps_metadata")
            with dumps.extract_temporary() as tmpdir:  # type: ignore
                dump_infos = []
                for dump_metadata in dumps_metadata:
                    dump_path = os.path.join(tmpdir, dump_metadata["filename"])
                    if not self._is_safe_path(tmpdir, dump_path):
                        self.log.warning(f"Path traversal attempt: {dump_path}")
                        continue
                    dump_base = int(dump_metadata["base_address"], 16)
                    dump_infos.append(DumpInfo(path=dump_path, base=dump_base))
                self.analyze_dumps(task, sample, dump_infos)

        self.log.debug("Printing gc stats")
        self.log.debug(gc.get_stats())

    def _is_safe_path(self, basedir, path):
        """
        Check if path points to a file within basedir.
        """
        return basedir == os.path.commonpath((basedir, os.path.realpath(path)))
