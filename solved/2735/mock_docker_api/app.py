import json
import uuid
from pathlib import Path

from flask import Flask, Response, abort

app = Flask(__name__)

FLAG_PATH = Path("/host_flag/flag.txt")
containers = {}


def jresp(payload, status=200):
    return Response(
        json.dumps(payload, separators=(",", ":")),
        status=status,
        mimetype="application/json",
    )


@app.route("/version", methods=["GET"])
def version():
    return jresp(
        {
            "Platform": {"Name": "Docker Engine - Community"},
            "ApiVersion": "1.41",
            "Version": "20.10.24-mock",
        }
    )


@app.route("/images/create", methods=["POST"])
def images_create():
    return Response("Status: Image is up to date for alpine:latest\n", mimetype="text/plain")


@app.route("/containers/create", methods=["POST"])
def containers_create():
    container_id = uuid.uuid4().hex
    containers[container_id] = {"started": False}
    return jresp({"Id": container_id, "Warnings": []}, status=201)


@app.route("/containers/<container_id>/start", methods=["POST"])
def container_start(container_id):
    if container_id not in containers:
        abort(404)
    containers[container_id]["started"] = True
    return Response(status=204)


@app.route("/containers/<container_id>/logs", methods=["GET"])
def container_logs(container_id):
    if container_id not in containers:
        abort(404)
    if not containers[container_id]["started"]:
        return Response("", mimetype="text/plain")

    flag = FLAG_PATH.read_text(encoding="utf-8").strip()
    return Response(flag + "\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2375)
