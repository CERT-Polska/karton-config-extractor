#!/usr/bin/python3
import gc
import hashlib
import json
import os
from collections import defaultdict, namedtuple
from typing import DefaultDict, Dict, List, Optional

from karton.core import Config, Karton, Resource, Task
from karton.core.resource import ResourceBase
from malduck.extractor import ExtractManager, ExtractorModules

from .__version__ import __version__

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
        parser.add_argument(
            "--identity",
            help="Override the default Karton identity",
        )
        return parser

    @classmethod
    def main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        attributes: DefaultDict[str, List[str]] = defaultdict(list)
        for attr in args.attribute:
            key, value = attr.split("=", 1)
            attributes[key].append(value)

        config = Config(args.config_file)
        service = ConfigExtractor(
            config,
            identity=args.identity,
            modules=args.modules,
            result_tags=args.tag,
            result_attributes=dict(attributes),
        )
        service.loop()

    def __init__(
        self,
        config: Config,
        identity: Optional[str],
        modules: str,
        result_tags: List[str],
        result_attributes: Dict[str, List[str]],
    ) -> None:
        """
        Create instance of the ConfigExtractor.

        :param config: Karton configuration object
        :param identity: Override the default Karton identity.
        :param modules: Path to a directory with malduck modules.
        :param result_tags: Tags to be applied to all produced configs.
        :param result_attributes: Attributes to be applied to all produced configs.
        """

        # Identity must be overriden before the super() call, because parent
        # constructor uses implicit default identity (from the class field).
        if identity is not None:
            self.identity = identity

        super().__init__(config)

        self.modules = ExtractorModules(modules)
        self.result_tags = result_tags
        self.result_attributes = result_attributes

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
                "tags": self.result_tags,
                "attributes": self.result_attributes,
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

    def analyze_dumps(self, sample, dump_infos):
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

            with open(dump_info.path, "rb") as f:
                dump_data = f.read()

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
            parent = Resource(name=dump_basename, content=dump_data)
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
                self.analyze_dumps(sample, dump_infos)

        self.log.debug("Printing gc stats")
        self.log.debug(gc.get_stats())

    def _is_safe_path(self, basedir, path):
        """
        Check if path points to a file within basedir.
        """
        return basedir == os.path.commonpath((basedir, os.path.realpath(path)))
