import json
import tarfile

import pytest

from provisioner.config_templates import ConfigTemplateError, load_config_template


def test_load_config_template_reads_json_object(tmp_path):
    path = tmp_path / "template.json"
    path.write_text(json.dumps({"system": {"hostname": "ap-1"}}))

    loaded = load_config_template(str(path))

    assert loaded.source_type == "json"
    assert loaded.member_name is None
    assert loaded.config == {"system": {"hostname": "ap-1"}}
    assert loaded.top_level_keys == ["system"]


def test_load_config_template_reads_tar_config_json(tmp_path):
    config_path = tmp_path / "config.json"
    control_path = tmp_path / "CONTROL"
    tar_path = tmp_path / "export.tar"
    config_path.write_text(json.dumps({"network": {}, "version": 3}))
    control_path.write_text("CONTROL\n")

    with tarfile.open(tar_path, "w") as tar:
        tar.add(control_path, arcname="CONTROL")
        tar.add(config_path, arcname="config.json")

    loaded = load_config_template(str(tar_path))

    assert loaded.source_type == "tar"
    assert loaded.member_name == "config.json"
    assert loaded.config == {"network": {}, "version": 3}
    assert loaded.top_level_keys == ["network", "version"]


def test_load_config_template_rejects_non_object_json(tmp_path):
    path = tmp_path / "template.json"
    path.write_text(json.dumps(["not", "an", "object"]))

    with pytest.raises(ConfigTemplateError, match="JSON object"):
        load_config_template(str(path))


def test_load_config_template_rejects_placeholders(tmp_path):
    path = tmp_path / "template.json"
    path.write_text(json.dumps({"system": {"hostname": "tw{{tower}}-north"}}))

    with pytest.raises(ConfigTemplateError, match=r"placeholder at \$\.system\.hostname"):
        load_config_template(str(path))


def test_load_config_template_rejects_tar_without_config_json(tmp_path):
    readme_path = tmp_path / "README"
    tar_path = tmp_path / "export.tar"
    readme_path.write_text("missing config\n")

    with tarfile.open(tar_path, "w") as tar:
        tar.add(readme_path, arcname="README")

    with pytest.raises(ConfigTemplateError, match="No config.json"):
        load_config_template(str(tar_path))
