import json
import time
from pathlib import Path
import httpx

ENDPOINT = "https://pentest-ground.com:5013/graphql"


def gql(client, query, variables=None):
    started = time.perf_counter()
    try:
        response = client.post(ENDPOINT, json={"query": query, "variables": variables or {}})
        payload = response.json()
        return {
            "status": response.status_code,
            "elapsed": round(time.perf_counter() - started, 4),
            "size": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "json": payload,
            "error": None,
        }
    except Exception as exc:
        return {"status": 0, "elapsed": round(time.perf_counter() - started, 4), "size": 0, "content_type": "", "json": {}, "error": str(exc)}


def main():
    introspection_query = """
    query SafeSchema {
      __schema {
        queryType {
          fields {
            name
            args { name }
          }
        }
      }
    }
    """
    typename_query = "{ __typename }"
    with httpx.Client(timeout=45, follow_redirects=True, headers={"User-Agent": "APISecurityPlatform-IndependentVerification/1.0"}) as client:
        schema = gql(client, introspection_query)
        typename = gql(client, typename_query)

    fields = schema.get("json", {}).get("data", {}).get("__schema", {}).get("queryType", {}).get("fields", [])
    result = {
        "endpoint": ENDPOINT,
        "introspection": {
            "status": schema["status"],
            "elapsed": schema["elapsed"],
            "size": schema["size"],
            "error": schema["error"],
            "field_names": [field.get("name") for field in fields],
            "field_count": len(fields),
            "has_errors": bool(schema.get("json", {}).get("errors")),
        },
        "typename": {
            "status": typename["status"],
            "elapsed": typename["elapsed"],
            "size": typename["size"],
            "error": typename["error"],
            "json": typename.get("json", {}),
        },
    }
    Path("tests/dvga_manual_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
