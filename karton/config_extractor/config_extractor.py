#!/usr/bin/python3
import gc
import hashlib
import json
import os
import re

from karton.core import Config, Karton, Resource, Task
from karton.core.resource import ResourceBase
from malduck.extractor import ExtractManager, ExtractorModules

from .__version__ import __version__


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
        {"type": "analysis", "kind": "drakrun-prod"},
        {"type": "analysis", "kind": "drakrun"},
    ]

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument(
            "--modules",
            help="Malduck extractor modules directory",
            default="extractor/modules",
        )
        return parser

    @classmethod
    def main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        config = Config(args.config_file)
        service = ConfigExtractor(config, modules=args.modules)
        service.loop()

    def __init__(self, config: Config, modules: str) -> None:
        super().__init__(config)
        self.modules = ExtractorModules(modules)

    def report_config(self, config, sample, parent=None):
        legacy_config = dict(config)
        legacy_config["type"] = config["family"]
        del legacy_config["family"]

        # This allows us to spawn karton tasks for special config handling
        if "store-in-karton" in legacy_config:
            self.log.info("Karton tasks found in config, sending")

            for karton_task in legacy_config["store-in-karton"]:
                task_data = karton_task["task"]
                payload_data = karton_task["payload"]
                payload_data["parent"] = parent or sample

                task = Task(headers=task_data, payload=payload_data)
                self.send_task(task)
                self.log.info("Sending ripped task %s", task.uid)

            del legacy_config["store-in-karton"]

        if len(legacy_config.items()) == 1:
            self.log.info("Final config is empty, not sending it to the reporter")
            return

        task = Task(
            {
                "type": "config",
                "kind": "static",
                "family": config["family"],
                "quality": self.current_task.headers.get("quality", "high"),
            },
            payload={
                "config": legacy_config,
                "sample": sample,
                "parent": parent or sample,
            },
        )
        self.send_task(task)

    # analyze a standard, non-dump sample
    def analyze_sample(self, sample: ResourceBase) -> None:
        extractor = create_extractor(self)
        with sample.download_temporary_file() as temp:  # type: ignore
            extractor.push_file(temp.name)
        configs = extractor.config

        if configs:
            config = configs[0]
            self.log.info("Got config: {}".format(json.dumps(config)))
            self.report_config(config, sample)
        else:
            self.log.info("Failed to get config")

    # analyze a drakrun analysis
    def analyze_drakrun(self, sample, path):
        extractor = create_extractor(self)
        dumps_path = os.path.join(path, "dumps")
        dump_candidates = {}

        results = {
            "analysed": 0,
            "crashed": 0,
        }

        analysis_dumps = sorted(os.listdir(dumps_path))
        for i, dump in enumerate(analysis_dumps):
            # catch only dumps
            if re.match(r"^[a-f0-9]{4,16}_[a-f0-9]{16}$", dump):
                results["analysed"] += 1
                self.log.debug(
                    "Analyzing dump %d/%d %s", i, len(analysis_dumps), str(dump)
                )
                dump_path = os.path.join(dumps_path, dump)

                with open(dump_path, "rb") as f:
                    dump_data = f.read()

                if not dump_data:
                    self.log.warning("Dump {} is empty".format(dump))
                    continue

                base = int(dump.split("_")[0], 16)

                try:
                    family = extractor.push_file(dump_path, base=base)
                    if family:
                        self.log.info("Found better %s config in %s", family, dump)
                        dump_candidates[family] = (dump, dump_data)
                except Exception:
                    self.log.exception("Error while extracting from {}".format(dump))
                    results["crashed"] += 1

                self.log.debug("Finished analysing dump no. %d", i)

        self.log.info("Merging and reporting extracted configs")
        for family, config in extractor.configs.items():
            dump, dump_data = dump_candidates[family]
            self.log.info("* (%s) %s => %s", family, dump, json.dumps(config))
            parent = Resource(name=dump, content=dump_data)
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
            self.report_config(config, sample, parent=parent)

        self.log.info("done analysing, results: {}".format(json.dumps(results)))

    def process(self, task: Task) -> None:  # type: ignore
        sample = task.get_resource("sample")
        headers = task.headers

        if headers["type"] == "sample":
            self.log.info("Analyzing original binary")
            self.analyze_sample(sample)
        elif headers["type"] == "analysis" and headers["kind"] == "drakrun-prod":
            analysis = task.get_resource("analysis")
            if analysis.size > 1024 * 1024 * 128:

                self.log.info("Analysis is too large, aborting")
                return

            with analysis.extract_temporary() as fpath:  # type: ignore
                with open(os.path.join(fpath, "sample.txt"), "r") as f:
                    sample_hash = f.read()

                self.log.info(
                    "Processing drakmon analysis, sample: {}".format(sample_hash)
                )
                self.analyze_drakrun(sample, fpath)
        elif headers["type"] == "analysis" and headers["kind"] == "drakrun":
            # DRAKVUF Sandbox (codename: drakmon OSS)
            sample_hash = hashlib.sha256(sample.content or b"").hexdigest()
            self.log.info(
                "Processing drakmon OSS analysis, sample: {}".format(sample_hash)
            )
            dumps = task.get_resource("dumps.zip")
            with dumps.extract_temporary() as tmpdir:  # type: ignore
                self.analyze_drakrun(sample, tmpdir)

        self.log.debug("Printing gc stats")
        self.log.debug(gc.get_stats())
