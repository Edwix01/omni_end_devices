#!/usr/bin/env python3
"""
Cliente de automatización para la ONT Huawei EG8145V5 (y firmwares similares).

Basado en el análisis de un HAR real capturado en la interfaz web del equipo.

Hallazgos clave del firmware:
  - NO usa cookies. La sesión queda atada a la IP de origen del cliente
    (por eso el script debe correr siempre desde la misma máquina/IP que
    hace login).
  - El login requiere un token anti-CSRF de un solo uso, obtenido de
    /asp/GetRandCount.asp, que se envía en el POST a /login.cgi.
  - Cada página autenticada (index.asp, mainpage.asp, deviceinfo.asp, etc.)
    trae un token distinto embebido como <input type="hidden" name="onttoken">.
    Ese token hay que reenviarlo como x.X_HW_Token en cualquier POST que
    se haga "desde" esa página.
  - Las respuestas de datos NO son JSON: son fragmentos de JavaScript con
    arrays tipo `new USERDevice("a","b",...)`. Los strings vienen con
    caracteres escapados estilo \\x2e (equivalente a un '.'), por eso hay
    que "desescapar" antes de parsear.

USO RÁPIDO:
    python3 management_ont.py --host 192.168.18.1 --user YOUR_USER --password 'YOUR_PASSWORD' status
    python3 management_ont.py --host 192.168.18.1 --user YOUR_USER --password 'YOUR_PASSWORD' devices

Por seguridad, en vez de pasar la clave por línea de comandos puedes
exportarla como variable de entorno:
    export ONT_PASSWORD='YOUR_PASSWORD'
    python3 management_ont.py --host 192.168.18.1 --user YOUR_USER devices
"""

import argparse
import base64
import os
import re
import sys
from dataclasses import dataclass

import requests


def unescape_js_hex(text: str) -> str:
    """Convierte escapes estilo \\x2e (usados por este firmware dentro de
    strings JS) a su caracter real."""
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), text)


def extract_quoted_args(call_body: str):
    """Dado el contenido entre paréntesis de un `new Foo("a","b",...)`,
    devuelve la lista de argumentos entre comillas, ya desescapados."""
    raw_args = re.findall(r'"((?:[^"\\]|\\.)*)"', call_body)
    return [unescape_js_hex(a) for a in raw_args]


class OntSessionError(RuntimeError):
    pass


@dataclass
class LanDevice:
    ip: str
    mac: str
    hostname: str
    port_type: str
    status: str
    device_type: str


class HuaweiOnt:
    """Cliente mínimo para login y lectura de estado de una ONT Huawei
    con este mismo firmware (familia EG8xxx / HG8xxx con interfaz
    Cuscss/CustomApp)."""

    def __init__(self, host: str, username: str, password: str, timeout: int = 10, verbose: bool = False):
        self.base_url = f"http://{host}"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        # El firmware no usa cookies, pero mantenemos una Session de
        # requests igual por keep-alive/headers comunes.
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (compatible; ont-automation-script/1.0)",
                "X-Requested-With": "XMLHttpRequest",
            }
        )

    def _log(self, *args):
        if self.verbose:
            print("[debug]", *args, file=sys.stderr)

    def _get_random_token(self) -> str:
        url = f"{self.base_url}/asp/GetRandCount.asp"
        r = self.session.post(url, headers={"Referer": f"{self.base_url}/"}, timeout=self.timeout)
        r.raise_for_status()
        # El servidor no manda charset en el Content-Type, así que requests
        # cae a Latin-1 por default y descuadra el BOM UTF-8. Forzamos utf-8.
        r.encoding = "utf-8"
        token = r.text.strip().lstrip("\ufeff")
        self._log("rand token:", token)
        return token

    def login(self) -> None:
        rand_token = self._get_random_token()

        # El firmware sólo ofusca la clave en base64 (no es un hash real).
        encoded_password = base64.b64encode(self.password.encode()).decode()

        payload = {
            "UserName": self.username,
            "PassWord": encoded_password,
            "Language": "english",
            "x.X_HW_Token": rand_token,
        }
        self._log(
            f"payload -> UserName={self.username!r} "
            f"PassWord(b64, len={len(encoded_password)})={encoded_password[:4]}...{encoded_password[-4:]} "
            f"token={rand_token!r}"
        )
        r = self.session.post(
            f"{self.base_url}/login.cgi",
            data=payload,
            headers={
                "Referer": f"{self.base_url}/",
                "Origin": self.base_url,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=self.timeout,
        )
        r.raise_for_status()
        r.encoding = "utf-8"
        self._log("login status:", r.status_code)
        self._log("login body:", r.text[:500])
        if "index.asp" not in r.text:
            snippet = r.text.strip()[:400] or "(cuerpo vacío)"
            raise OntSessionError(
                "El login no redirigió a index.asp como se esperaba.\n"
                "Esto suele pasar cuando YA hay una sesión activa (por ejemplo "
                "el navegador donde capturaste el HAR sigue logueado) o cuando "
                "usuario/clave son incorrectos.\n"
                f"Respuesta cruda del equipo:\n---\n{snippet}\n---"
            )
        self._log("login OK")

    def _fetch_page_and_token(self, path: str) -> str:
        """Descarga una página autenticada y devuelve el token 'onttoken'
        embebido en ella (necesario para los POST de esa sección)."""
        r = self.session.get(f"{self.base_url}{path}", timeout=self.timeout)
        r.raise_for_status()
        r.encoding = "utf-8"
        m = re.search(r'name="onttoken"[^>]*value="([^"]+)"', r.text)
        if not m:
            raise OntSessionError(
                f"No se encontró onttoken en {path}; ¿sigues logueado? "
                "La sesión pudo expirar o cambió de IP."
            )
        token = m.group(1)
        self._log(f"onttoken en {path}:", token)
        return token

    def get_wan_status(self) -> str:
        """Devuelve el texto crudo (JS) con el estado de las conexiones WAN.
        Incluye IP pública, estado de conexión, etc."""
        token = self._fetch_page_and_token("/CustomApp/mainpage.asp")
        r = self.session.post(
            f"{self.base_url}/html/bbsp/common/getwanlist.asp",
            data={"x.X_HW_Token": token},
            headers={"Referer": f"{self.base_url}/CustomApp/mainpage.asp"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        r.encoding = "utf-8"
        return unescape_js_hex(r.text)

    def get_lan_devices(self):
        """Devuelve la lista de dispositivos conectados (LAN + WiFi) como
        objetos LanDevice."""
        # Esta página no exige token en el POST (se vio así en el HAR),
        # pero de todas formas nos aseguramos de estar en una página
        # autenticada primero.
        self._fetch_page_and_token("/CustomApp/mainpage.asp")
        r = self.session.post(
            f"{self.base_url}/html/bbsp/common/GetLanUserDevInfo.asp",
            headers={"Referer": f"{self.base_url}/CustomApp/mainpage.asp"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        r.encoding = "utf-8"
        text = r.text

        devices = []
        for call in re.findall(r"new USERDevice\(([^)]*)\)", text):
            args = extract_quoted_args(call)
            # Orden según la definición: Domain,IpAddr,MacAddr,Port,IpType,
            # DevType,DevStatus,PortType,Time,HostName,IPv4Enabled,...
            if len(args) < 10:
                continue
            devices.append(
                LanDevice(
                    ip=args[1],
                    mac=args[2],
                    hostname=args[9] or "--",
                    port_type=args[7],
                    status=args[6],
                    device_type=args[5],
                )
            )
        return devices

    def set_wifi_2g_enabled(self, enabled: bool) -> None:
        """Prende/apaga el radio WiFi de 2.4GHz.

        Detectado capturando el toggle en Configuración WiFi -> Básica.
        La página que da el token es WlanBasic.asp?2G y el endpoint que
        aplica el cambio es set.cgi con x.Enable / y.Enable.
        """
        token = self._fetch_page_and_token("/html/amp/wlanbasic/WlanBasic.asp?2G")
        flag = "1" if enabled else "0"
        # OJO: no usamos params=, porque requests le hace percent-encoding
        # a las '/' dentro de RequestFile (quedan como %2F) y el firmware
        # responde 404 con eso. El navegador manda las barras literales,
        # así que armamos la query string a mano.
        url = (
            f"{self.base_url}/html/amp/wlanbasic/set.cgi"
            "?x=InternetGatewayDevice.X_HW_DEBUG.AMP.SetWifiCoverEnable"
            "&y=InternetGatewayDevice.LANDevice.1.WiFi.Radio.1"
            "&RequestFile=html/amp/wlanbasic/WlanBasic.asp"
        )
        r = self.session.post(
            url,
            data={
                "x.Enable": flag,
                "x.RadioInst": "1",
                "y.Enable": flag,
                "x.X_HW_Token": token,
            },
            headers={"Referer": f"{self.base_url}/html/amp/wlanbasic/WlanBasic.asp?2G"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        self._log(f"set_wifi_2g_enabled({enabled}) -> status {r.status_code}")


def main():
    parser = argparse.ArgumentParser(description="Automatización de ONT Huawei (EG8145V5 y similares)")
    parser.add_argument("--host", default="192.168.18.1", help="IP de la ONT (default: 192.168.18.1)")
    parser.add_argument("--user", required=True, help="Usuario de la interfaz web")
    parser.add_argument(
        "--password",
        default=os.environ.get("ONT_PASSWORD"),
        help="Clave (o exporta ONT_PASSWORD en vez de pasarla aquí)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Muestra detalles de cada request")
    parser.add_argument(
        "action",
        choices=["status", "devices", "wifi2g-on", "wifi2g-off"],
        help="Qué información consultar o acción a ejecutar",
    )
    args = parser.parse_args()

    if not args.password:
        parser.error("Falta la clave: usa --password o exporta ONT_PASSWORD")

    ont = HuaweiOnt(args.host, args.user, args.password, verbose=args.verbose)

    try:
        ont.login()

        if args.action == "status":
            raw = ont.get_wan_status()
            print(raw)

        elif args.action == "devices":
            devices = ont.get_lan_devices()
            if not devices:
                print("No se encontraron dispositivos (o el parser necesita ajuste).")
            for d in devices:
                print(f"{d.ip:<16} {d.mac:<18} {d.hostname:<25} {d.port_type:<8} {d.status}")

        elif args.action == "wifi2g-on":
            ont.set_wifi_2g_enabled(True)
            print("WiFi 2.4GHz encendido.")

        elif args.action == "wifi2g-off":
            ont.set_wifi_2g_enabled(False)
            print("WiFi 2.4GHz apagado.")

    except OntSessionError as e:
        print(f"Error de sesión: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Error de red hablando con la ONT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()