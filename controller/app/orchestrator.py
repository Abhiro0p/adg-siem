from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from kubernetes import client, config

from .models import LureDeployment
from .state import StateStore


class Orchestrator:
    async def deploy(
        self, lure_type: str, subnet: str, ttl_seconds: int, metadata: Dict[str, Any]
    ) -> LureDeployment:
        raise NotImplementedError

    async def teardown(self, lure: LureDeployment) -> None:
        raise NotImplementedError


class DryRunOrchestrator(Orchestrator):
    def __init__(self, store: StateStore) -> None:
        self.store = store

    async def deploy(
        self, lure_type: str, subnet: str, ttl_seconds: int, metadata: Dict[str, Any]
    ) -> LureDeployment:
        lure = LureDeployment(
            lure_id=str(uuid.uuid4()),
            lure_type=lure_type,
            subnet=subnet,
            hostname=f"{lure_type}-{uuid.uuid4().hex[:6]}",
            created_at=datetime.now(timezone.utc),
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        self.store.add_lure(lure)
        return lure

    async def teardown(self, lure: LureDeployment) -> None:
        self.store.remove_lure(lure.lure_id)


class KubernetesOrchestrator(Orchestrator):
    def __init__(self, store: StateStore, namespace: str = "honeypots") -> None:
        config.load_incluster_config()
        self.namespace = namespace
        self.apps = client.AppsV1Api()
        self.core = client.CoreV1Api()
        self.store = store

    async def deploy(
        self, lure_type: str, subnet: str, ttl_seconds: int, metadata: Dict[str, Any]
    ) -> LureDeployment:
        lure = LureDeployment(
            lure_id=str(uuid.uuid4()),
            lure_type=lure_type,
            subnet=subnet,
            hostname=f"{lure_type}-{uuid.uuid4().hex[:6]}",
            created_at=datetime.now(timezone.utc),
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        deployment = client.V1Deployment(
            metadata=client.V1ObjectMeta(name=lure.hostname, labels={"app": lure_type}),
            spec=client.V1DeploymentSpec(
                replicas=1,
                selector=client.V1LabelSelector(
                    match_labels={"app": lure_type, "lure": lure.hostname}
                ),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": lure_type, "lure": lure.hostname}),
                    spec=client.V1PodSpec(
                        containers=[
                            client.V1Container(
                                name=lure_type,
                                image=metadata.get("image", f"adg/{lure_type}:latest"),
                                ports=[
                                    client.V1ContainerPort(
                                        container_port=metadata.get("port", 22)
                                    )
                                ],
                            )
                        ]
                    ),
                ),
            ),
        )
        self.apps.create_namespaced_deployment(self.namespace, deployment)
        self.store.add_lure(lure)
        return lure

    async def teardown(self, lure: LureDeployment) -> None:
        self.apps.delete_namespaced_deployment(lure.hostname, self.namespace)
        self.store.remove_lure(lure.lure_id)
