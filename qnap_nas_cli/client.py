import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, Optional

from .config import Config
from .errors import AuthenticationError, CompatibilityError, QtsError


AUTH_PATH = "/cgi-bin/authLogin.cgi"
LOGOUT_PATH = "/cgi-bin/authLogout.cgi"


def _xml_text(root: ET.Element, tag: str) -> Optional[str]:
    node = root.find(".//{}".format(tag))
    return None if node is None else (node.text or "").strip()


class QtsClient:
    def __init__(self, config: Config):
        self.config = config.validate()
        self.sid = None  # type: Optional[str]
        self._ssl_context = ssl.create_default_context()
        if config.insecure:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def _open(self, request: urllib.request.Request) -> bytes:
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout, context=self._ssl_context) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read(512).decode("utf-8", "replace").replace("\n", " ")
            raise QtsError("QTS 回傳 HTTP {}：{}".format(exc.code, body or "空白回應")) from exc
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason:
                reason += "（請安裝可信憑證；僅在受信任區網暫時使用 --insecure）"
            raise QtsError("無法連線至 NAS：{}".format(reason)) from exc

    def login(self, password: str, security_code: Optional[str] = None) -> str:
        if not password:
            raise AuthenticationError("密碼不可為空")
        fields = {
            "user": self.config.username,
            "pwd": base64.b64encode(password.encode("utf-8")).decode("ascii"),
            "serviceKey": "1",
            "client_app": "qnap-nas-cli",
        }
        if security_code:
            fields["security_code"] = security_code
            fields["dont_verify_2sv_again"] = "0"
        body = urllib.parse.urlencode(fields).encode("ascii")
        request = urllib.request.Request(
            self.config.origin + AUTH_PATH,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "qnap-nas-cli/0.1"},
        )
        raw = self._open(request)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise CompatibilityError("QTS 登入回應不是預期的 XML") from exc
        if _xml_text(root, "authPassed") != "1":
            needs_2fa = _xml_text(root, "need_2_step_verification") == "1" or _xml_text(root, "need_2sv") == "1"
            if needs_2fa and not security_code:
                raise AuthenticationError("QTS 帳號需要 2FA；請設定當下的 QTS_SECURITY_CODE 後重試")
            if needs_2fa and security_code:
                raise AuthenticationError("QTS 2FA 驗證失敗；請確認驗證碼與 NAS 時間")
            code = _xml_text(root, "errorValue") or "unknown"
            raise AuthenticationError("QTS 登入失敗（errorValue={}）".format(code))
        sid = _xml_text(root, "authSid")
        if not sid:
            raise CompatibilityError("QTS 表示登入成功，但沒有回傳 authSid")
        self.sid = sid
        return sid

    def logout(self) -> None:
        if not self.sid:
            return
        try:
            self.get(LOGOUT_PATH, {}, include_sid=True)
        except QtsError:
            pass
        finally:
            self.sid = None

    def get(self, path: str, params: Dict[str, str], include_sid: bool = True) -> bytes:
        query = dict(params)
        if include_sid:
            if not self.sid:
                raise AuthenticationError("尚未登入 QTS")
            query["sid"] = self.sid
        url = self.config.origin + path + "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, headers={"User-Agent": "qnap-nas-cli/0.1"})
        return self._open(request)

    def get_xml(self, path: str, params: Dict[str, str]) -> ET.Element:
        raw = self.get(path, params)
        try:
            return ET.fromstring(raw)
        except ET.ParseError as exc:
            raise CompatibilityError("{} 回應不是預期的 XML".format(path)) from exc

    def get_json(self, path: str, params: Dict[str, str]):
        raw = self.get(path, params)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CompatibilityError("{} 回應不是預期的 JSON".format(path)) from exc

    def __enter__(self) -> "QtsClient":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.logout()
