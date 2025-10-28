r"""
2. Pruebas de regresión que validen la no existencia de la inyección SQL en la
funcionalidad de visualizar facturas. Implementadas mediante PyTest.


- Diseñadas para ejecutarse contra el backend real en ejecución.
- En la rama con mitigaciones (p4tests) deben PASAR.
- En la rama con vulnerabilidades sin mitigar (main-copy) deberían FALLAR
  por errores 500, demoras anómalas o expansión indebida de resultados.

Configurado según variables de entorno:
(Asegurarse estar corriendo el backend de la rama correcta antes de ejecutar)

En Branch p4tests (con mitigaciones):
- BACKEND_URL: http://localhost:3000
- JWT_SECRET: "default_secret"
- USER_ID: "1"

En Branch main-copy (sin mitigaciones):
- BACKEND_URL: http://localhost:5000
- JWT_SECRET: "secreto_super_seguro"
- USER_ID: "1"

Esto es asi porque al realizar las mitigaciones se cambiaron cosas del .env

Opcionales:
- REQUEST_TIMEOUT: timeout por request en segundos (default: 3.0)
- TIME_THRESHOLD: umbral de tiempo para detectar posibles time-based (default: 1.8)

Como ejecutar (Windows):
- Crear entorno e instalar dependencias de test:
    python -m venv .venv
    .venv/Scripts/activate
    pip install pytest requests

- Ejecutar Pytest:
    set BACKEND_URL=http://localhost: (3000 o 5000 según rama)
    set USER_ID=1
    pytest -q tests\security\test_invoices_sql_injection.py (o la ruta correcta segun donde se ejecute)
"""
import base64, hmac, hashlib, json, os, time, pytest, requests
from typing import Any, Dict, Optional, Sequence, Tuple


# Configuración a partir de las variables de entorno
BASE_URL = os.getenv("BACKEND_URL", "http://localhost:5000").rstrip("/")
JWT_SECRET = os.getenv("JWT_SECRET", "secreto_super_seguro")
USER_ID = os.getenv("USER_ID", "1")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "3.0"))
TIME_THRESHOLD = float(os.getenv("TIME_THRESHOLD", "1.8"))

# Endpoint de facturas
INVOICES_ENDPOINT = "/invoices"


def b64url(data: bytes) -> str:
    """Codifica en Base64 URL-safe sin padding final. (=)

    - Usa base64.urlsafe_b64encode.
    - Remueve '=' al final para cumplir con el formato de JWT.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_hs256(payload: Dict[str, Any], secret: str) -> str:
    """Crea un JWT HS256 sin dependencias externas (PyJWT), usando stdlib.
    Sólo para pruebas: no incluye "exp"; agrega alg, typ y firma.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = b64url(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def auth_headers() -> Dict[str, str]:
    """Genera el header de Authorization: Bearer <JWT> para el usuario de prueba.

    - FIrma un JWT HS256 con el USER_ID y JWT_SECRET.
    - Devuelve el header para las requests.
    """
    token = jwt_hs256({"id": USER_ID}, JWT_SECRET)
    return {"Authorization": f"Bearer {token}"}


def url(path: str) -> str:
    """ Construye la URL completa.
    """
    return BASE_URL + path


def get_invoices(params: Optional[Dict[str, Any]] = None) -> Tuple[requests.Response, float]:
    """Realiza GET al endpoint de facturas midiendo la latencia.

    Args:
        params: diccionario de query params (status, operator, etc.)

    Returns:
        (resp, elapsed): respuesta HTTP y tiempo transcurrido.
    """
    start = time.time()
    resp = requests.get(
        url(INVOICES_ENDPOINT),
        headers=auth_headers(),
        params=params or {},
        timeout=REQUEST_TIMEOUT,
    )
    elapsed = time.time() - start
    return resp, elapsed


def try_parse_list_json(resp: requests.Response) -> Optional[Sequence[Any]]:
    """Intenta extraer una lista de facturas de la respuesta JSON.

    Soporta:
    - Respuesta como lista directa: [...]
    - Objeto con contenedor: { "invoices": [...] } o { "data": [...] } o { "results": [...] }

    Returns:
        La secuencia de facturas si pudo extraerse, None en caso contrario.
    """

    try:
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Algunos controladores devuelven { invoices: [...] } o { data: [...] }
            for key in ("invoices", "data", "results"):
                val = data.get(key)
                if isinstance(val, list):
                    return val
    except Exception:
        pass
    return None


# Payloads típicos de inyección en campo status y/o operador
STATUS_INJECTION_PAYLOADS = [
    "paid' OR '1'='1",
    "unpaid' OR '1'='1",
    "paid'; SELECT pg_sleep(2)--",
    "x' UNION SELECT NULL--",
]

OPERATOR_INJECTION_PAYLOADS = [
    "or 1=1",
    "' OR '1'='1",
    "; SELECT pg_sleep(2)--",
]


@pytest.fixture(scope="module")
def total_invoices_for_user() -> Optional[int]:
    """Obtiene un baseline opcional del total de facturas del usuario autenticado.

    - Se usa para comprobar que un payload malicioso no expande los resultados.
    - Si el endpoint no devuelve 200 o la forma no es parseable, devuelve None.
    """
    resp, _ = get_invoices()
    if resp.status_code != 200:
        return None
    data = try_parse_list_json(resp)
    return len(data) if isinstance(data, list) else None


@pytest.mark.parametrize("payload", STATUS_INJECTION_PAYLOADS)
def test_invoices_status_is_not_sql_injectable(payload: str, total_invoices_for_user: Optional[int]):
    """Verifica que el parámetro 'status' no es vulnerable a inyección SQL.
    """

    resp, elapsed = get_invoices({"status": payload})

    # 1) No error de servidor
    assert resp.status_code not in (500, 503), f"500 con payload status={payload}"

    # 2) No inyección basada en tiempo
    assert elapsed < TIME_THRESHOLD, f"Lento ({elapsed:.2f}s) con status={payload}"

    # 3) Si se puede parsear la lista, no debe exceder el total del usuario
    if total_invoices_for_user is not None and resp.status_code == 200:
        data = try_parse_list_json(resp)
        if isinstance(data, list):
            assert len(data) <= total_invoices_for_user, (
                f"Posible inyección: resultados {len(data)} > total {total_invoices_for_user}"
            )


@pytest.mark.parametrize("payload", OPERATOR_INJECTION_PAYLOADS)
def test_invoices_operator_is_not_sql_injectable(payload: str, total_invoices_for_user: Optional[int]):
    """Verifica que el parámetro 'operator' no es vulnerable a inyección SQL.
    """

    # El servicio valida allowedOps y aplica '=' si no es válido
    resp, elapsed = get_invoices({"status": "paid", "operator": payload})

    assert resp.status_code not in (500, 503), f"500 con operator={payload}"
    assert elapsed < TIME_THRESHOLD, f"Lento ({elapsed:.2f}s) con operator={payload}"

    if total_invoices_for_user is not None and resp.status_code == 200:
        data = try_parse_list_json(resp)
        if isinstance(data, list):
            assert len(data) <= total_invoices_for_user, (
                f"Posible inyección: operator alteró tamaño ({len(data)} > {total_invoices_for_user})"
            )


def test_no_sql_error_leakage_in_response_body():
    """Comprobar que no se filtran detalles de SQL/ORM en respuestas de error.
    """

    # Probar que no se filtran detalles de SQL/ORM en respuestas de error
    payload = "'; DROP TABLE invoices; --"
    resp, _ = get_invoices({"status": payload})

    assert resp.status_code in (200, 400, 404, 422), "Estado inesperado para payload malicioso"

    text = resp.text.lower()
    leaked_markers = ["syntax error", "sql", "psql", "postgres", "pg_", "knex", "sqlite"]
    assert not any(m in text for m in leaked_markers), "Detalles de SQL filtrados al cliente"