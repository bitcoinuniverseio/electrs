"""Observe existing Docker metadata after failed user network isolation; no launch."""
import importlib.util
import json
import pathlib

path = pathlib.Path(__file__).with_name('native-preflight.py')
spec = importlib.util.spec_from_file_location('metadata', path)
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def collect():
    report = metadata.collect()
    report['dockerAvailability'] = metadata.docker_metadata()
    report['previousScopeProof'] = {'run': 38017693834, 'passed': False,
                                  'networkNamespaceEnforced': False}
    report['alternativeIsolationQualified'] = False
    report['containersStarted'] = False
    report['buildInvoked'] = False
    return report


if __name__ == '__main__':
    print(json.dumps(collect()), flush=True)
