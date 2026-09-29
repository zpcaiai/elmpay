"""Fail-closed product OCI build and release bindings.

The source manifest is repository policy.  A product release index is external
execution evidence: it is accepted only when every image, base image, SBOM,
scan, provenance and signature bundle is bound to the same source commit and
release manifest.  This module never turns a local source check into execution
or certification evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .common import (
    ValidationError,
    canonical_json,
    require_exact_keys,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .kubernetes import IMAGE_PATTERN


DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
ENVIRONMENT_NAME = re.compile(r"^ELMPAY_[A-Z0-9_]+$")
MAIN_CLASS = re.compile(r"^com\.elmpay(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
ABSOLUTE_EXECUTABLE = re.compile(r"^/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+$")
ZERO_DIGEST = "0" * 64
PRODUCT_MANIFEST_PATH = Path("platform/oci/product-images.json")
ADMISSION_POLICY_PATH = Path("platform/kubernetes/image-admission-policy.json")
CANONICAL_DOCKERIGNORE_DIGEST = (
    "70910e5884557538de83ce4d68f15c89fe987fe22978e9198082a38fb23531c0"
)
CANONICAL_JAVA_LAUNCHER_DIGEST = (
    "5880f8b364d458bb55fb9d3dc1574c020d3f7483cfb87935b58c8412ea67a87e"
)
CANONICAL_CONTAINERFILE_DIGESTS = {
    "platform/oci/java-runtime.Containerfile": (
        "4893ce8336a8978b4dec9860451af36ce069ae0bc41aae51ae05eb5636c60f50"
    ),
    "platform/oci/checkout-web.Containerfile": (
        "05612036eabb62773b3d89da6b6c157ab050390b441db669f8ab26c8f9f550c0"
    ),
    "platform/oci/admin-web.Containerfile": (
        "2e4f5266826cc39dbd5ec4ad3edc935956f490af915ded0ed0c691adb9ec17f2"
    ),
}


def product_image_manifest_digest(document: Mapping[str, Any]) -> str:
    validate_manifest_shape(document)
    return sha256_json(document)


def admission_policy_digest(document: Mapping[str, Any]) -> str:
    validate_admission_policy(document)
    return sha256_json(document)


def validate_product_image_manifest(
    root: Path,
    document: Mapping[str, Any],
    workload_policy: Mapping[str, Any],
) -> None:
    """Validate exact source/build/runtime coverage for every production image."""

    validate_manifest_shape(document)
    services = [
        require_mapping(value, "workload service")
        for value in require_list(workload_policy.get("services"), "workload services")
    ]
    service_names = [require_text(value.get("name"), "workload service.name") for value in services]
    if len(service_names) != len(set(service_names)):
        raise ValidationError("workload service names must be unique")
    images = [
        require_mapping(value, "product image")
        for value in require_list(document.get("images"), "product images")
    ]
    image_names = [require_text(value.get("name"), "product image.name") for value in images]
    if image_names != service_names:
        raise ValidationError("product image order and names must exactly match workload services")

    base_images = {
        require_text(value.get("id"), "base image.id"): value
        for value in (
            require_mapping(raw, "base image")
            for raw in require_list(document.get("baseImages"), "baseImages")
        )
    }
    if len(base_images) != len(require_list(document.get("baseImages"), "baseImages")):
        raise ValidationError("base image ids must be unique")
    build_source = _read_regular(root, Path("tools/paygov/buildgen.py"), "build generator").read_text(
        encoding="utf-8"
    )
    generated_build = _read_regular(root, Path("build.gradle.kts"), "generated build").read_text(
        encoding="utf-8"
    )
    java_launcher = _read_regular(root, Path("platform/oci/java-main"), "Java launcher")
    launcher_digest = hashlib.sha256(java_launcher.read_bytes()).hexdigest()
    if launcher_digest != CANONICAL_JAVA_LAUNCHER_DIGEST:
        raise ValidationError("Java launcher differs from the exact reviewed runtime contract")
    launcher_text = java_launcher.read_text(encoding="utf-8")
    for marker in (
        "JAVA_EXECUTABLE='/opt/java/openjdk/bin/java'",
        "APPLICATION_CLASSPATH='/opt/elmpay/app/lib/*'",
        "DEFAULT_MAIN_CLASS_FILE='/opt/elmpay/etc/default-main-class'",
        "ALLOWED_MAIN_CLASSES_FILE='/opt/elmpay/etc/allowed-main-classes'",
        "Java main class is not in the immutable image allowlist",
        "exec \"${JAVA_EXECUTABLE}\" -cp \"${APPLICATION_CLASSPATH}\"",
    ):
        if marker not in launcher_text:
            raise ValidationError("Java launcher does not enforce the governed runtime/classpath")

    context_policy = require_mapping(document.get("contextPolicy"), "contextPolicy")
    dockerignore_relative = Path(require_text(
        context_policy.get("dockerignore"), "contextPolicy.dockerignore"
    ))
    dockerignore = _read_regular(root, dockerignore_relative, "product Docker ignore policy")
    dockerignore_digest = hashlib.sha256(dockerignore.read_bytes()).hexdigest()
    if context_policy != {
        "dockerignore": ".dockerignore",
        "dockerignoreDigest": CANONICAL_DOCKERIGNORE_DIGEST,
        "mode": "EXACT_ALLOWLIST",
    } or dockerignore_digest != CANONICAL_DOCKERIGNORE_DIGEST:
        raise ValidationError("product build context is not the exact governed allowlist")

    for image in images:
        _validate_image_source(root, image, base_images, build_source, generated_build)

    by_name = {str(value["name"]): value for value in images}
    job_mains: dict[str, list[str]] = {name: [] for name in by_name}
    workload_jobs = [
        *require_list(workload_policy.get("jobs", []), "workload jobs"),
        *require_list(workload_policy.get("cronJobs", []), "workload cronJobs"),
    ]
    for raw_job in workload_jobs:
        job = require_mapping(raw_job, "workload job")
        image_from = require_text(job.get("imageFrom"), "workload job.imageFrom")
        source = by_name.get(image_from)
        if source is None or source.get("kind") != "java-install-dist":
            raise ValidationError("Java jobs must reuse a declared Java installDist image")
        runtime = require_mapping(job.get("runtime"), "workload job.runtime")
        launcher = require_text(runtime.get("launcher"), "workload job.runtime.launcher")
        if launcher != source.get("launcher"):
            raise ValidationError("workload job launcher must equal its reused image launcher")
        main_class = require_text(runtime.get("mainClass"), "workload job.runtime.mainClass")
        if main_class not in require_list(source.get("mainClasses"), "image.mainClasses"):
            raise ValidationError("workload job mainClass is not shipped by its reused image")
        expected_source = Path(str(source["sourcePath"])) / "src/main/java" / Path(
            *main_class.split(".")
        ).with_suffix(".java")
        if runtime.get("entrypoint") != expected_source.as_posix():
            raise ValidationError("workload job source entrypoint differs from its exact mainClass")
        if main_class not in job_mains[image_from]:
            job_mains[image_from].append(main_class)
    for image in images:
        if image.get("kind") != "java-install-dist":
            if job_mains[str(image["name"])]:
                raise ValidationError("Node product images cannot host Java GitOps jobs")
            continue
        classes = require_list(image.get("mainClasses"), "image.mainClasses")
        expected_classes = [classes[0], *[
            value for value in job_mains[str(image["name"])] if value != classes[0]
        ]]
        if classes != expected_classes:
            raise ValidationError(
                "Java image mainClasses must exactly equal its default plus all GitOps jobs"
            )


def validate_manifest_shape(document: Mapping[str, Any]) -> None:
    require_exact_keys(
        document,
        required={
            "schemaVersion", "targetPlatform", "registry", "runtimeUser", "buildEngine",
            "contextPolicy", "publicationTool", "baseImages", "images", "evidence",
        },
        optional=set(),
        field="product image manifest",
    )
    if document.get("schemaVersion") != 1:
        raise ValidationError("product image manifest schemaVersion must be 1")
    if document.get("targetPlatform") != "linux/amd64":
        raise ValidationError("product images must use the governed linux/amd64 platform")
    if document.get("registry") != "ghcr.io/zpcaiai/elmpay":
        raise ValidationError("product image registry is not the governed repository")
    if document.get("runtimeUser") != 10001:
        raise ValidationError("product images must use uid 10001")
    context = require_mapping(document.get("contextPolicy"), "contextPolicy")
    require_exact_keys(
        context,
        required={"dockerignore", "dockerignoreDigest", "mode"},
        optional=set(),
        field="contextPolicy",
    )
    if context != {
        "dockerignore": ".dockerignore",
        "dockerignoreDigest": CANONICAL_DOCKERIGNORE_DIGEST,
        "mode": "EXACT_ALLOWLIST",
    }:
        raise ValidationError("product Docker context policy is not the exact allowlist")
    build = require_mapping(document.get("buildEngine"), "buildEngine")
    require_exact_keys(
        build,
        required={
            "name", "versionInputEnvironment", "executableDigestInputEnvironment",
            "output", "network", "reproducibleTimestamps",
        },
        optional=set(),
        field="buildEngine",
    )
    if build != {
        "name": "docker-buildx",
        "versionInputEnvironment": "ELMPAY_BUILDX_VERSION",
        "executableDigestInputEnvironment": "ELMPAY_DOCKER_CLI_SHA256",
        "output": "oci",
        "network": "none",
        "reproducibleTimestamps": True,
    }:
        raise ValidationError("product OCI build engine must be reproducible and network isolated")
    publication = require_mapping(document.get("publicationTool"), "publicationTool")
    if publication != {
        "name": "skopeo",
        "versionInputEnvironment": "ELMPAY_SKOPEO_VERSION",
        "executableDigestInputEnvironment": "ELMPAY_SKOPEO_SHA256",
        "preserveDigests": True,
    }:
        raise ValidationError("product OCI publication must use digest-preserving pinned Skopeo")
    bases = require_list(document.get("baseImages"), "baseImages")
    if not bases:
        raise ValidationError("at least one release-input base image is required")
    for index, raw in enumerate(bases):
        base = require_mapping(raw, f"baseImages[{index}]")
        require_exact_keys(
            base,
            required={"id", "inputEnvironment", "runtimeExecutable", "requiredPaths"},
            optional=set(),
            field=f"baseImages[{index}]",
        )
        require_text(base.get("id"), f"baseImages[{index}].id")
        environment = require_text(base.get("inputEnvironment"), "base image inputEnvironment")
        if ENVIRONMENT_NAME.fullmatch(environment) is None:
            raise ValidationError("base image input must use a dedicated ELMPAY environment name")
        executable = require_text(base.get("runtimeExecutable"), "base runtimeExecutable")
        if ABSOLUTE_EXECUTABLE.fullmatch(executable) is None:
            raise ValidationError("base runtimeExecutable must be an absolute normalized path")
        paths = require_list(base.get("requiredPaths"), "base requiredPaths")
        if not paths or executable not in paths or len(set(paths)) != len(paths) or any(
            not isinstance(path, str) or ABSOLUTE_EXECUTABLE.fullmatch(path) is None
            for path in paths
        ):
            raise ValidationError("base requiredPaths must uniquely include its runtime executable")
    if bases != [
        {
            "id": "java25-runtime",
            "inputEnvironment": "ELMPAY_JAVA25_RUNTIME_BASE_IMAGE",
            "runtimeExecutable": "/opt/java/openjdk/bin/java",
            "requiredPaths": ["/bin/sh", "/opt/java/openjdk/bin/java"],
        },
        {
            "id": "node24-runtime",
            "inputEnvironment": "ELMPAY_NODE24_RUNTIME_BASE_IMAGE",
            "runtimeExecutable": "/usr/local/bin/node",
            "requiredPaths": ["/usr/local/bin/node"],
        },
        {
            "id": "node24-postgres18-client-runtime",
            "inputEnvironment": "ELMPAY_NODE24_POSTGRES18_RUNTIME_BASE_IMAGE",
            "runtimeExecutable": "/usr/local/bin/node",
            "requiredPaths": ["/usr/local/bin/node", "/usr/bin/psql"],
        },
    ]:
        raise ValidationError("product base runtime contracts are not the exact reviewed set")
    evidence = require_mapping(document.get("evidence"), "evidence")
    require_exact_keys(
        evidence,
        required={
            "sbomFormat", "sbomCoverage", "sbomPredicateType",
            "provenancePredicateType", "signatureScheme", "signatureTool",
            "scanTool", "scanPolicy", "admissionPolicy", "missingAction",
        },
        optional=set(),
        field="product image evidence",
    )
    scan_tool = require_mapping(evidence.get("scanTool"), "product image scanTool")
    if scan_tool != {
        "name": "trivy",
        "versionInputEnvironment": "ELMPAY_TRIVY_VERSION",
        "executableDigestInputEnvironment": "ELMPAY_TRIVY_SHA256",
        "cacheDirectoryEnvironment": "ELMPAY_TRIVY_CACHE_DIR",
        "databaseDigestInputEnvironment": "ELMPAY_TRIVY_DB_SHA256",
    }:
        raise ValidationError("product image scan tool inputs must be exact release inputs")
    signature_tool = require_mapping(
        evidence.get("signatureTool"), "product image signatureTool"
    )
    if signature_tool != {
        "name": "cosign",
        "versionInputEnvironment": "ELMPAY_COSIGN_VERSION",
        "executableDigestInputEnvironment": "ELMPAY_COSIGN_SHA256",
    }:
        raise ValidationError("product image signer must be version and digest pinned")
    expected_evidence = {
        "sbomFormat": "CycloneDX-1.6-json",
        "sbomCoverage": "FULL_IMAGE_PACKAGES",
        "sbomPredicateType": "https://cyclonedx.org/bom",
        "provenancePredicateType": "https://slsa.dev/provenance/v1",
        "signatureScheme": "Sigstore-keyless",
        "signatureTool": signature_tool,
        "scanTool": scan_tool,
        "scanPolicy": "platform/compliance/vulnerability-policy.json",
        "admissionPolicy": "platform/kubernetes/image-admission-policy.json",
        "missingAction": "BLOCK_RELEASE",
    }
    if evidence != expected_evidence:
        raise ValidationError("product image evidence policy is incomplete or fail-open")


def validate_admission_policy(document: Mapping[str, Any]) -> None:
    require_exact_keys(
        document,
        required={
            "schemaVersion", "mode", "allowedRepositoryPrefix", "requiredImageManifest",
            "signature", "attestations", "workload", "externalControllerRequired",
            "missingOrUnknownAction",
        },
        optional=set(),
        field="image admission policy",
    )
    if document.get("schemaVersion") != 1 or document.get("mode") != "ENFORCE":
        raise ValidationError("image admission policy must be schema v1 ENFORCE")
    if document.get("allowedRepositoryPrefix") != "ghcr.io/zpcaiai/elmpay/" \
            or document.get("requiredImageManifest") != str(PRODUCT_MANIFEST_PATH):
        raise ValidationError("image admission repository/manifest is not exact")
    signature = require_mapping(document.get("signature"), "admission signature")
    if signature != {
        "scheme": "Sigstore-keyless",
        "issuer": "https://token.actions.githubusercontent.com",
        "workflowIdentity": (
            "https://github.com/zpcaiai/elmpay/.github/workflows/ci.yml@refs/heads/main"
        ),
        "transparencyLogRequired": True,
    }:
        raise ValidationError("image admission signature identity must be exact and transparent")
    attestations = require_mapping(document.get("attestations"), "admission attestations")
    if attestations != {
        "provenancePredicateType": "https://slsa.dev/provenance/v1",
        "sbomFormat": "CycloneDX-1.6-json",
        "exactImageSubjectRequired": True,
        "vulnerabilityScanRequired": True,
    }:
        raise ValidationError("image admission attestations must bind provenance, SBOM and scan")
    workload = require_mapping(document.get("workload"), "admission workload")
    expected_workload = {
        "digestPinned": True,
        "runAsUser": 10001,
        "runAsNonRoot": True,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "dropAllCapabilities": True,
        "seccompRuntimeDefault": True,
        "serviceAccountToken": False,
    }
    if workload != expected_workload:
        raise ValidationError("image admission workload policy is incomplete")
    if document.get("externalControllerRequired") is not True \
            or document.get("missingOrUnknownAction") != "DENY":
        raise ValidationError("missing external admission execution must deny")


def resolve_base_images(
    document: Mapping[str, Any], environment: Mapping[str, str]
) -> dict[str, str]:
    """Resolve base images only from exact digest-pinned release inputs."""

    validate_manifest_shape(document)
    result: dict[str, str] = {}
    for raw in require_list(document.get("baseImages"), "baseImages"):
        base = require_mapping(raw, "base image")
        name = require_text(base.get("id"), "base image.id")
        variable = require_text(base.get("inputEnvironment"), "base image.inputEnvironment")
        reference = environment.get(variable, "")
        if IMAGE_PATTERN.fullmatch(reference) is None or reference.endswith(ZERO_DIGEST):
            raise ValidationError(f"base image release input is missing or not digest-pinned: {variable}")
        result[name] = reference
    return result


def validate_product_release_index(
    product_manifest: Mapping[str, Any],
    admission_policy: Mapping[str, Any],
    index: Mapping[str, Any],
    release_manifest: Mapping[str, Any],
) -> None:
    """Bind final OCI evidence to the exact signed release manifest."""

    manifest_digest = product_image_manifest_digest(product_manifest)
    policy_digest = admission_policy_digest(admission_policy)
    require_exact_keys(
        index,
        required={
            "schemaVersion", "productImageManifestDigest", "admissionPolicyDigest",
            "sourceCommit", "artifactDigest", "targetPlatform", "evidenceToolchain",
            "buildIndexDigest", "scanIndexDigest", "publicationIndexDigest",
            "signatureIndexDigest", "images",
        },
        optional=set(),
        field="product release index",
    )
    if index.get("schemaVersion") != 1:
        raise ValidationError("product release index schemaVersion must be 1")
    if index.get("productImageManifestDigest") != manifest_digest:
        raise ValidationError("product release index manifest digest mismatch")
    if index.get("admissionPolicyDigest") != policy_digest:
        raise ValidationError("product release index admission policy digest mismatch")
    if index.get("targetPlatform") != product_manifest.get("targetPlatform"):
        raise ValidationError("product release target platform mismatch")
    for field in (
        "buildIndexDigest", "scanIndexDigest", "publicationIndexDigest",
        "signatureIndexDigest",
    ):
        value = index.get(field)
        if not isinstance(value, str) or DIGEST.fullmatch(value) is None \
                or value == ZERO_DIGEST:
            raise ValidationError(f"product release {field} is invalid")
    toolchain = require_mapping(index.get("evidenceToolchain"), "evidenceToolchain")
    require_exact_keys(
        toolchain,
        required={"build", "scan", "scanDatabaseDigest", "publish", "sign"},
        optional=set(),
        field="evidenceToolchain",
    )
    for field, expected_name in (
        ("build", "docker-buildx"), ("scan", "trivy"),
        ("publish", "skopeo"), ("sign", "cosign")
    ):
        tool = require_mapping(toolchain.get(field), f"evidenceToolchain.{field}")
        require_exact_keys(
            tool,
            required={"name", "version", "executableDigest"},
            optional=set(),
            field=f"evidenceToolchain.{field}",
        )
        digest = tool.get("executableDigest")
        if tool.get("name") != expected_name \
                or not isinstance(tool.get("version"), str) or not tool["version"].strip() \
                or not isinstance(digest, str) or DIGEST.fullmatch(digest) is None \
                or digest == ZERO_DIGEST:
            raise ValidationError(f"product release {field} tool evidence is invalid")
    database_digest = toolchain.get("scanDatabaseDigest")
    if not isinstance(database_digest, str) or DIGEST.fullmatch(database_digest) is None \
            or database_digest == ZERO_DIGEST:
        raise ValidationError("product release scan database digest is invalid")
    commit = require_text(index.get("sourceCommit"), "product release sourceCommit")
    artifact = require_text(index.get("artifactDigest"), "product release artifactDigest")
    if COMMIT.fullmatch(commit) is None or commit != release_manifest.get("commitSha"):
        raise ValidationError("product release source commit mismatch")
    if DIGEST.fullmatch(artifact) is None or artifact != release_manifest.get("artifactDigest"):
        raise ValidationError("product release artifact digest mismatch")
    if release_manifest.get("productImageManifestDigest") != manifest_digest:
        raise ValidationError("signed release does not bind the product image manifest")
    if release_manifest.get("imageAdmissionPolicyDigest") != policy_digest:
        raise ValidationError("signed release does not bind the image admission policy")
    if release_manifest.get("productImageIndexDigest") != sha256_json(index):
        raise ValidationError("signed release does not bind the product release index")

    planned = {
        require_text(value.get("name"), "product image.name")
        for value in (
            require_mapping(raw, "product image")
            for raw in require_list(product_manifest.get("images"), "product images")
        )
    }
    release_images = require_mapping(release_manifest.get("images"), "release images")
    raw_images = require_list(index.get("images"), "product release images")
    if len(raw_images) != len(planned):
        raise ValidationError("product release image inventory is incomplete")
    observed: set[str] = set()
    registry = require_text(product_manifest.get("registry"), "product registry")
    for position, raw in enumerate(raw_images):
        image = require_mapping(raw, f"product release images[{position}]")
        require_exact_keys(
            image,
            required={
                "name", "reference", "imageDigest", "baseImage", "artifactDigest",
                "containerfileDigest", "runtimeInspectionDigest", "sbomDigest",
                "sbomAttestedPredicateDigest",
                "provenanceDigest", "provenanceAttestedPredicateDigest", "scanReportDigest",
                "signatureBundleDigest", "status",
            },
            optional=set(),
            field=f"product release images[{position}]",
        )
        name = require_text(image.get("name"), "product release image.name")
        if name in observed or name not in planned:
            raise ValidationError("product release image name is duplicate or unknown")
        observed.add(name)
        image_digest = require_text(image.get("imageDigest"), "imageDigest")
        reference = require_text(image.get("reference"), "image reference")
        expected_reference = f"{registry}/{name}@sha256:{image_digest}"
        if DIGEST.fullmatch(image_digest) is None or image_digest == ZERO_DIGEST \
                or reference != expected_reference or IMAGE_PATTERN.fullmatch(reference) is None:
            raise ValidationError("product image reference/digest is invalid")
        if release_images.get(name) != reference:
            raise ValidationError("signed release image set differs from product release index")
        base = require_text(image.get("baseImage"), "baseImage")
        if IMAGE_PATTERN.fullmatch(base) is None or base.endswith(ZERO_DIGEST):
            raise ValidationError("product image base is not an exact non-placeholder digest")
        for field in (
            "artifactDigest", "containerfileDigest", "runtimeInspectionDigest",
            "sbomDigest", "provenanceDigest",
            "sbomAttestedPredicateDigest", "provenanceAttestedPredicateDigest",
            "scanReportDigest", "signatureBundleDigest",
        ):
            value = image.get(field)
            if not isinstance(value, str) or DIGEST.fullmatch(value) is None \
                    or value == ZERO_DIGEST:
                raise ValidationError(f"product image {field} is invalid")
        if image.get("status") != "SIGNED_SCANNED_VERIFIED":
            raise ValidationError("product image execution evidence is missing or unresolved")
    if observed != planned or set(release_images) != planned:
        raise ValidationError("signed release image inventory must exactly match all workloads")


def _validate_image_source(
    root: Path,
    image: Mapping[str, Any],
    base_images: Mapping[str, Mapping[str, Any]],
    build_source: str,
    generated_build: str,
) -> None:
    require_exact_keys(
        image,
        required={
            "name", "kind", "context", "containerfile", "baseImage", "sourcePath",
            "artifactPath", "includedPaths", "prepareCommand", "launcher", "entrypoint",
            "mainClasses", "containerfileContractDigest",
        },
        optional={"mainClassFile", "mainClassAllowlist"},
        field="product image",
    )
    name = require_text(image.get("name"), "product image.name")
    kind = image.get("kind")
    if kind not in {"java-install-dist", "node-source"}:
        raise ValidationError(f"{name} product image kind is unsupported")
    if image.get("context") != ".":
        raise ValidationError(f"{name} build context must be the exact repository root")
    base_name = require_text(image.get("baseImage"), f"{name}.baseImage")
    base = base_images.get(base_name)
    if base is None:
        raise ValidationError(f"{name} references an unknown base image input")
    source_relative = Path(require_text(image.get("sourcePath"), f"{name}.sourcePath"))
    artifact_relative = Path(require_text(image.get("artifactPath"), f"{name}.artifactPath"))
    included = [
        Path(require_text(value, f"{name}.includedPaths"))
        for value in require_list(image.get("includedPaths"), f"{name}.includedPaths")
    ]
    if not included or len(included) != len(set(included)):
        raise ValidationError(f"{name} includedPaths must be non-empty and unique")
    containerfile_relative = Path(require_text(image.get("containerfile"), f"{name}.containerfile"))
    containerfile_path = _read_regular(root, containerfile_relative, f"{name} Containerfile")
    source = _repository_path(root, source_relative, f"{name} source")
    if not source.is_dir():
        raise ValidationError(f"{name} source must be a directory")
    if artifact_relative.is_absolute() or ".." in artifact_relative.parts:
        raise ValidationError(f"{name} artifactPath must stay within the repository")
    launcher = require_text(image.get("launcher"), f"{name}.launcher")
    entrypoint = require_text(image.get("entrypoint"), f"{name}.entrypoint")
    if ABSOLUTE_EXECUTABLE.fullmatch(launcher) is None or entrypoint != launcher:
        raise ValidationError(f"{name} launcher/entrypoint must be one exact absolute executable")
    containerfile = containerfile_path.read_text(encoding="utf-8")
    _validate_containerfile_contract(
        containerfile_relative, containerfile,
        require_text(
            image.get("containerfileContractDigest"),
            f"{name}.containerfileContractDigest",
        ),
    )

    command = require_list(image.get("prepareCommand"), f"{name}.prepareCommand")
    classes = require_list(image.get("mainClasses"), f"{name}.mainClasses")
    if kind == "java-install-dist":
        expected_task_path = ":" + str(source_relative).replace("/", ":") + ":installDist"
        if command != ["./gradlew", "--no-daemon", expected_task_path]:
            raise ValidationError(f"{name} installDist command is not exact")
        if artifact_relative != source_relative / "build" / "install" / source_relative.name:
            raise ValidationError(f"{name} installDist artifact path is inconsistent")
        main_file_relative = Path(require_text(
            image.get("mainClassFile"), f"{name}.mainClassFile"
        ))
        allowlist_relative = Path(require_text(
            image.get("mainClassAllowlist"), f"{name}.mainClassAllowlist"
        ))
        if included != [artifact_relative, main_file_relative, allowlist_relative]:
            raise ValidationError(
                f"{name} Java image must include only installDist and immutable main-class policy"
            )
        if launcher != "/opt/elmpay/bin/java-main" or base.get("runtimeExecutable") \
                != "/opt/java/openjdk/bin/java":
            raise ValidationError(f"{name} Java runtime layout is inconsistent")
        if not classes or len(classes) != len(set(classes)) or any(
            not isinstance(value, str) or MAIN_CLASS.fullmatch(value) is None for value in classes
        ):
            raise ValidationError(f"{name} Java mainClasses are invalid")
        main_file = _read_regular(root, main_file_relative, f"{name} default main class")
        allowlist_file = _read_regular(
            root, allowlist_relative, f"{name} main-class allowlist"
        )
        if main_file.read_text(encoding="utf-8") != classes[0] + "\n" \
                or allowlist_file.read_text(encoding="utf-8") \
                != "".join(f"{value}\n" for value in classes):
            raise ValidationError(f"{name} immutable main-class files differ from the manifest")
        for marker in (
            "ARG MAIN_CLASS_FILE", "ARG MAIN_CLASS_ALLOWLIST",
            "${MAIN_CLASS_FILE} /opt/elmpay/etc/default-main-class",
            "${MAIN_CLASS_ALLOWLIST} /opt/elmpay/etc/allowed-main-classes",
        ):
            if marker not in containerfile:
                raise ValidationError(f"{name} Containerfile does not embed its main-class policy")
        project_marker = f'project(\":{str(source_relative).replace("/", ":")}\")'
        default_marker = f'mainClass.set(\"{classes[0]}\")'
        for text, field in ((build_source, "build generator"), (generated_build, "generated build")):
            project_at = text.find(project_marker)
            main_at = text.find(default_marker, project_at if project_at >= 0 else 0)
            if project_at < 0 or main_at < project_at:
                raise ValidationError(f"{name} application/installDist is absent from {field}")
        for main_class in classes:
            class_file = source_relative / "src/main/java" / Path(
                *main_class.split(".")
            ).with_suffix(".java")
            source_file = _read_regular(root, class_file, f"{name} main class")
            if "public static void main" not in source_file.read_text(encoding="utf-8"):
                raise ValidationError(f"{name} declared main class is not executable")
    else:
        if command or classes or "mainClassFile" in image or "mainClassAllowlist" in image:
            raise ValidationError(f"{name} Node image must not invent a build or Java main class")
        package_path = source_relative / "package.json"
        if artifact_relative != source_relative or package_path not in included \
                or any(path != source_relative and source_relative not in path.parents
                       for path in included):
            raise ValidationError(f"{name} Node includedPaths escape the application source")
        package = json.loads(_read_regular(root, package_path, f"{name} package").read_text(
            encoding="utf-8"
        ))
        if any(package.get(field) not in (None, {}) for field in (
            "dependencies", "devDependencies", "optionalDependencies", "bundledDependencies"
        )):
            raise ValidationError(f"{name} product image cannot include undeclared Node dependencies")
        expected_start = "node src/main.mjs" if name == "admin-web" else "node src/server.mjs"
        if require_mapping(package.get("scripts"), "package scripts").get("start") != expected_start:
            raise ValidationError(f"{name} start command differs from its image entrypoint")
        required_runtime_paths = set(require_list(base.get("requiredPaths"), "base requiredPaths"))
        if name == "admin-web" and "/usr/bin/psql" not in required_runtime_paths:
            raise ValidationError("admin-web base image contract must include the PostgreSQL client")


def _repository_path(root: Path, relative: Path, field: str) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValidationError(f"{field} must be a normalized repository-relative path")
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValidationError(f"{field} cannot traverse a symlink")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"{field} is missing") from exc
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValidationError(f"{field} escapes the repository")
    return resolved


def _validate_containerfile_contract(
    relative: Path, content: str, declared_digest: str
) -> None:
    """Accept only byte-for-byte reviewed Containerfiles.

    This is deliberately stronger than looking for individual instructions: a
    second stage, COPY/ADD, RUN (including secret mounts), remote source or
    alternate ENTRYPOINT changes the digest and is rejected before BuildKit
    receives the repository-root context.
    """

    normalized = relative.as_posix()
    expected = CANONICAL_CONTAINERFILE_DIGESTS.get(normalized)
    observed = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if expected is None or declared_digest != expected or observed != expected:
        raise ValidationError(
            f"{normalized} differs from the exact reviewed instruction/copy contract"
        )


def _read_regular(root: Path, relative: Path, field: str) -> Path:
    path = _repository_path(root, relative, field)
    if not path.is_file() or path.is_symlink():
        raise ValidationError(f"{field} must be a regular non-symlink file")
    return path


__all__ = [
    "ADMISSION_POLICY_PATH",
    "CANONICAL_JAVA_LAUNCHER_DIGEST",
    "PRODUCT_MANIFEST_PATH",
    "admission_policy_digest",
    "product_image_manifest_digest",
    "resolve_base_images",
    "validate_admission_policy",
    "validate_product_image_manifest",
    "validate_product_release_index",
]
