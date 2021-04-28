#!/usr/bin/python3
import gc
import hashlib
import json
import os
import re
import tempfile
import zipfile
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
        {"type": "analysis", "kind": "drakrun"},
        {"type": "analysis", "kind": "joesandbox"},
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
        super().__init__(config)
        if identity is not None:
            self.identity = identity
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

    def get_base_from_drakrun_dump(self, dump_name):
        """
        Drakrun dumps come in form: <base>_<hash> e.g. 405000_688f58c58d798ecb,
        that can be read as a dump from address 0x405000 with a content hash
        equal to 688f58c58d798ecb.
        """
        return int(dump_name.split("_")[0], 16)

    def analyze_drakrun(self, sample, dumps):
        with dumps.extract_temporary() as tmpdir:  # type: ignore
            dumps_path = os.path.join(tmpdir, "dumps")
            dump_infos = []
            for fname in os.listdir(dumps_path):
                # Drakrun stores meta information in seperate file for each dump.
                # Filter it as we want to analyse only dumps.
                if not re.match(r"^[a-f0-9]{4,16}_[a-f0-9]{16}$", fname):
                    continue
                dump_path = os.path.join(dumps_path, fname)
                dump_base = self.get_base_from_drakrun_dump(fname)
                dump_infos.append(DumpInfo(path=dump_path, base=dump_base))
            self.analyze_dumps(sample, dump_infos)

    def get_base_from_joesandbox_dump(self, dump_name):
        """
        JoeSandbox dumps come in three formats:
        1) raw dumps with .sdmp extension, e.g.
            00000002.00000003.385533966.003C0000.00000004.00000001.sdmp
        2) dumps that start with 0x4d5a bytes
            2.1) unmodified with .raw.unpack extension, e.g.
                0.0.tmpi0shwswy.exe.1290000.0.raw.unpack
            2.2) modified by joesandbox engine with .unpack extension, e.g.
                0.0.tmpi0shwswy.exe.1290000.0.unpack
        """
        if "sdmp" in dump_name:
            return int(dump_name.split(".")[3], 16)
        elif "raw.unpack" in dump_name:
            return int(dump_name.split(".")[4], 16)
        elif "unpack" in dump_name:
            return int(dump_name.split(".")[4], 16)

    def analyze_joesandbox(self, sample, dumps):
        with tempfile.TemporaryDirectory() as tmpdir:
            dumpsf = os.path.join(tmpdir, "dumps.zip")
            dumps.download_to_file(dumpsf)
            zipf = zipfile.ZipFile(dumpsf)
            dumps_path = tmpdir + "/dumps"
            zipf.extractall(dumps_path, pwd=b"infected")
            dump_infos = []
            for fname in os.listdir(dumps_path):
                dump_path = os.path.join(dumps_path, fname)
                dump_base = self.get_base_from_joesandbox_dump(fname)
                dump_infos.append(DumpInfo(path=dump_path, base=dump_base))
            self.analyze_dumps(sample, dump_infos)

    def process(self, task: Task) -> None:  # type: ignore
        sample = task.get_resource("sample")
        headers = task.headers

        if headers["type"] == "sample":
            self.log.info("Analyzing original binary")
            self.analyze_sample(sample)
        elif headers["type"] == "analysis" and headers["kind"] == "drakrun":
            # DRAKVUF Sandbox (codename: drakmon OSS)
            sample_hash = hashlib.sha256(sample.content or b"").hexdigest()
            self.log.info(
                "Processing drakmon OSS analysis, sample: {}".format(sample_hash)
            )
            dumps = task.get_resource("dumps.zip")
            self.analyze_drakrun(sample, dumps)
        elif headers["type"] == "analysis" and headers["kind"] == "joesandbox":
            sample_hash = hashlib.sha256(sample.content or b"").hexdigest()
            self.log.info(f"Processing joesandbox analysis, sample: {sample_hash}")
            dumps = task.get_resource("dumps.zip")
            self.analyze_joesandbox(sample, dumps)

        self.log.debug("Printing gc stats")
        self.log.debug(gc.get_stats())
