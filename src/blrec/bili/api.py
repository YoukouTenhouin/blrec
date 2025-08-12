import asyncio
import hashlib
import time
from abc import ABC
from datetime import datetime
from typing import Any, Dict, Final, List, Mapping, Optional
from urllib.parse import urlencode

import aiohttp
from loguru import logger
from tenacity import retry, stop_after_delay, wait_exponential

from .exceptions import ApiRequestError
from . import wbi
from .typing import JsonResponse, QualityNumber, ResponseData

# 添加验证码处理的导入
try:
    import bili_ticket_gt_python
    HAS_CAPTCHA_SOLVER = True
except ImportError:
    HAS_CAPTCHA_SOLVER = False
    logger.warning("bili_ticket_gt_python not installed, captcha solving disabled")

__all__ = 'AppApi', 'WebApi'


BASE_HEADERS: Final = {
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en;q=0.3,en-US;q=0.2',  # noqa
    'Accept': 'application/json, text/plain, */*',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Origin': 'https://live.bilibili.com',
    'Pragma': 'no-cache',
    'Referer': 'https://live.bilibili.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',  # noqa
}


class BaseApi(ABC):
    def __init__(
        self,
        session: aiohttp.ClientSession,
        headers: Optional[Dict[str, str]] = None,
        *,
        room_id: Optional[int] = None,
    ):
        self._logger = logger.bind(room_id=room_id or '')

        self.base_api_urls: List[str] = ['https://api.bilibili.com']
        self.base_live_api_urls: List[str] = ['https://api.live.bilibili.com']
        self.base_play_info_api_urls: List[str] = ['https://api.live.bilibili.com']

        self._session = session
        self.headers = headers or {}
        self.timeout = 10
        
        # 添加gaia_vtoken管理
        self._gaia_vtoken: Optional[str] = None

    @property
    def headers(self) -> Dict[str, str]:
        return self._headers

    @headers.setter
    def headers(self, value: Dict[str, str]) -> None:
        self._headers = {**BASE_HEADERS, **value}
        # 如果你有类似的cookie处理逻辑，可以在这里添加
        # cookie = self._headers.get('Cookie', '')
        # self._uid = extract_uid_from_cookie(cookie) or 0
        # self._buvid = extract_buvid_from_cookie(cookie) or ''

    @staticmethod
    def _check_response(json_res: JsonResponse) -> None:
        if json_res['code'] != 0:
            raise ApiRequestError(
                json_res['code'], json_res.get('message') or json_res.get('msg') or ''
            )

    async def _handle_v_voucher_verification(
        self, 
        v_voucher: str, 
        csrf_token: Optional[str] = None
    ) -> Optional[str]:
        """处理v_voucher验证流程，返回gaia_vtoken"""
        if not HAS_CAPTCHA_SOLVER:
            self._logger.error("Cannot handle v_voucher verification: bili_ticket_gt_python not available")
            return None
            
        try:
            # 步骤1: 申请captcha
            register_url = "https://api.bilibili.com/x/gaia-vgate/v1/register"
            register_data = {"v_voucher": v_voucher}
            if csrf_token:
                register_data["csrf"] = csrf_token
                
            async with self._session.post(
                register_url, 
                data=register_data,
                headers=self.headers
            ) as resp:
                register_result = await resp.json()
                
            if register_result['code'] != 0:
                self._logger.error(f"Failed to register v_voucher: {register_result}")
                return None
                
            captcha_data = register_result['data']
            if not captcha_data.get('geetest'):
                self._logger.error("Cannot solve this type of risk control through captcha")
                return None
                
            token = captcha_data['token']
            gt = captcha_data['geetest']['gt']
            challenge = captcha_data['geetest']['challenge']
            
            self._logger.info(f"Got captcha challenge: {challenge}")
            
            # 步骤2: 解决验证码
            click = bili_ticket_gt_python.ClickPy()
            validate = click.simple_match_retry(gt, challenge)
            seccode = f"{validate}|jordan"
            
            self._logger.info("Captcha solved successfully")
            
            # 步骤3: 获取gaia_vtoken
            validate_url = "https://api.bilibili.com/x/gaia-vgate/v1/validate"
            validate_data = {
                "challenge": challenge,
                "token": token,
                "validate": validate,
                "seccode": seccode
            }
            if csrf_token:
                validate_data["csrf"] = csrf_token
                
            async with self._session.post(
                validate_url,
                data=validate_data,
                headers=self.headers
            ) as resp:
                validate_result = await resp.json()
                
            if validate_result['code'] != 0:
                self._logger.error(f"Failed to validate captcha: {validate_result}")
                return None
                
            if validate_result['data']['is_valid'] != 1:
                self._logger.error("Captcha validation failed")
                return None
                
            gaia_vtoken = validate_result['data']['grisk_id']
            self._logger.info(f"Got gaia_vtoken: {gaia_vtoken}")
            return gaia_vtoken
            
        except Exception as e:
            self._logger.error(f"Error in v_voucher verification: {e}")
            return None

    def _extract_csrf_token(self) -> Optional[str]:
        """从headers的Cookie中提取csrf token (bili_jct)"""
        try:
            cookie_header = self._headers.get('Cookie', '')
            if not cookie_header:
                return None
                
            # 解析cookie字符串
            import re
            match = re.search(r'bili_jct=([^;]+)', cookie_header)
            if match:
                return match.group(1)
        except Exception as e:
            self._logger.debug(f"Failed to extract csrf token: {e}")
        return None

    def _add_gaia_vtoken_to_headers(self, gaia_vtoken: str) -> None:
        """将gaia_vtoken添加到headers的Cookie中"""
        try:
            current_cookie = self._headers.get('Cookie', '')
            
            # 检查是否已经存在x-bili-gaia-vtoken
            if 'x-bili-gaia-vtoken=' in current_cookie:
                # 替换现有的token
                import re
                pattern = r'x-bili-gaia-vtoken=[^;]*;?'
                current_cookie = re.sub(pattern, '', current_cookie)
                current_cookie = current_cookie.rstrip('; ')
            
            # 添加新的token
            if current_cookie:
                if not current_cookie.endswith(';'):
                    current_cookie += ';'
                current_cookie += f' x-bili-gaia-vtoken={gaia_vtoken}'
            else:
                current_cookie = f'x-bili-gaia-vtoken={gaia_vtoken}'
            
            # 更新headers
            self._headers['Cookie'] = current_cookie
            self._logger.debug(f"Added gaia_vtoken to Cookie header")
            
        except Exception as e:
            self._logger.error(f"Failed to add gaia_vtoken to headers: {e}")

    # @retry(reraise=True, stop=stop_after_delay(5), wait=wait_exponential(0.1))
    async def _get_json_res(self, *args: Any, **kwds: Any) -> JsonResponse:
        should_check_response = kwds.pop('check_response', True)
        
        # 如果有gaia_vtoken，添加到URL参数中
        if self._gaia_vtoken:
            params = kwds.get('params', {})
            if isinstance(params, dict):
                params = {**params, 'gaia_vtoken': self._gaia_vtoken}
                kwds['params'] = params
        
        kwds = {'timeout': self.timeout, 'headers': self.headers, **kwds}
        
        try:
            async with self._session.get(*args, **kwds) as res:
                self._logger.trace('Request: {}', res.request_info)
                response_text = await res.text()
                self._logger.trace('Response: {}', response_text)
                
                try:
                    json_res = await res.json()
                except aiohttp.ContentTypeError:
                    self._logger.debug(f'Response text: {response_text[:200]}')
                    raise
                    
                if should_check_response:
                    self._check_response(json_res)
                return json_res
                
        except ApiRequestError as e:
            # 处理-352风控错误
            if e.code == -352:
                self._logger.warning("Hit risk control (-352), attempting v_voucher verification")
                
                # 尝试从响应中获取v_voucher
                v_voucher = None
                
                # 重新发起请求获取完整响应信息
                try:
                    async with self._session.get(*args, **kwds) as res:
                        json_res = await res.json()
                        
                        # 优先从响应体的data中获取v_voucher
                        if 'data' in json_res and isinstance(json_res['data'], dict):
                            v_voucher = json_res['data'].get('v_voucher')
                        
                        # 如果响应体中没有，尝试从响应头获取
                        if not v_voucher:
                            v_voucher_header = res.headers.get('X-Bili-Gaia-Vvoucher') or res.headers.get('x-bili-gaia-vvoucher')
                            if v_voucher_header:
                                v_voucher = v_voucher_header
                                
                except Exception as inner_e:
                    self._logger.debug(f"Failed to get v_voucher from response: {inner_e}")
                
                if v_voucher:
                    self._logger.info(f"Found v_voucher: {v_voucher}")
                    csrf_token = self._extract_csrf_token()
                    gaia_vtoken = await self._handle_v_voucher_verification(v_voucher, csrf_token)
                    
                    if gaia_vtoken:
                        self._gaia_vtoken = gaia_vtoken
                        self._add_gaia_vtoken_to_headers(gaia_vtoken)
                        
                        # 重新尝试原始请求
                        self._logger.info("Retrying original request with gaia_vtoken")
                        
                        # 添加gaia_vtoken到参数
                        params = kwds.get('params', {})
                        if isinstance(params, dict):
                            params = {**params, 'gaia_vtoken': gaia_vtoken}
                            kwds['params'] = params
                        
                        async with self._session.get(*args, **kwds) as res:
                            json_res = await res.json()
                            if should_check_response:
                                self._check_response(json_res)
                            return json_res
                    else:
                        self._logger.error("Failed to get gaia_vtoken, cannot bypass risk control")
                else:
                    self._logger.error("No v_voucher found in response, cannot handle risk control")
            
            raise

    async def _get_json(
        self, base_urls: List[str], path: str, *args: Any, **kwds: Any
    ) -> JsonResponse:
        if not base_urls:
            raise ValueError('No base urls')
        exception = None
        for base_url in base_urls:
            url = base_url + path
            try:
                return await self._get_json_res(url, *args, **kwds)
            except Exception as exc:
                exception = exc
                self._logger.trace('Failed to get json from {}: {}', url, repr(exc))
        else:
            assert exception is not None
            raise exception

    async def _get_jsons_concurrently(
        self, base_urls: List[str], path: str, *args: Any, **kwds: Any
    ) -> List[JsonResponse]:
        if not base_urls:
            raise ValueError('No base urls')
        urls = [base_url + path for base_url in base_urls]
        aws = (self._get_json_res(url, *args, **kwds) for url in urls)
        results = await asyncio.gather(*aws, return_exceptions=True)
        exceptions = []
        json_responses = []
        for idx, item in enumerate(results):
            if isinstance(item, Exception):
                self._logger.trace(
                    'Failed to get json from {}: {}', urls[idx], repr(item)
                )
                exceptions.append(item)
            elif isinstance(item, dict):
                json_responses.append(item)
            else:
                self._logger.trace('{}', repr(item))
        if not json_responses:
            raise exceptions[0]
        return json_responses


class AppApi(BaseApi):
    # taken from https://github.com/SocialSisterYi/bilibili-API-collect/blob/master/other/API_sign.md  # noqa
    _appkey = '1d8b6e7d45233436'
    _appsec = '560c52ccd288fed045859ed18bffd973'

    _app_headers = {
        'User-Agent': 'Mozilla/5.0 BiliDroid/6.64.0 (bbcallen@gmail.com) os/android model/Unknown mobi_app/android build/6640400 channel/bili innerVer/6640400 osVer/6.0.1 network/2',  # noqa
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
    }

    @property
    def headers(self) -> Dict[str, str]:
        return self._headers

    @headers.setter
    def headers(self, value: Dict[str, str]) -> None:
        self._headers = {**value, **self._app_headers}

    @classmethod
    def signed(cls, params: Mapping[str, Any]) -> Dict[str, Any]:
        if isinstance(params, Mapping):
            params = dict(sorted({**params, 'appkey': cls._appkey}.items()))
        else:
            raise ValueError(type(params))
        query = urlencode(params, doseq=True)
        sign = hashlib.md5((query + cls._appsec).encode()).hexdigest()
        params.update(sign=sign)
        return params

    async def get_room_play_infos(
        self,
        room_id: int,
        qn: QualityNumber = 10000,
        *,
        only_video: bool = False,
        only_audio: bool = False,
    ) -> List[ResponseData]:
        path = '/xlive/app-room/v2/index/getRoomPlayInfo'
        params = self.signed(
            {
                'actionKey': 'appkey',
                'build': '6640400',
                'channel': 'bili',
                'codec': '0,1',  # 0: avc, 1: hevc
                'device': 'android',
                'device_name': 'Unknown',
                'disable_rcmd': '0',
                'dolby': '1',
                'format': '0,1,2',  # 0: flv, 1: ts, 2: fmp4
                'free_type': '0',
                'http': '1',
                'mask': '0',
                'mobi_app': 'android',
                'need_hdr': '0',
                'no_playurl': '0',
                'only_audio': '1' if only_audio else '0',
                'only_video': '1' if only_video else '0',
                'platform': 'android',
                'play_type': '0',
                'protocol': '0,1',
                'qn': qn,
                'room_id': room_id,
                'ts': int(datetime.utcnow().timestamp()),
            }
        )
        json_responses = await self._get_jsons_concurrently(
            self.base_play_info_api_urls, path, params=params
        )
        return [r['data'] for r in json_responses]

    async def get_info_by_room(self, room_id: int) -> ResponseData:
        path = '/xlive/app-room/v1/index/getInfoByRoom'
        params = self.signed(
            {
                'actionKey': 'appkey',
                'build': '6640400',
                'channel': 'bili',
                'device': 'android',
                'mobi_app': 'android',
                'platform': 'android',
                'room_id': room_id,
                'ts': int(datetime.utcnow().timestamp()),
            }
        )
        json_res = await self._get_json(self.base_live_api_urls, path, params=params)
        return json_res['data']

    async def get_user_info(self, uid: int) -> ResponseData:
        base_api_urls = ['https://app.bilibili.com']
        path = '/x/v2/space'
        params = self.signed(
            {
                'build': '6640400',
                'channel': 'bili',
                'mobi_app': 'android',
                'platform': 'android',
                'ts': int(datetime.utcnow().timestamp()),
                'vmid': uid,
            }
        )
        json_res = await self._get_json(base_api_urls, path, params=params)
        return json_res['data']

    async def get_danmu_info(self, room_id: int) -> ResponseData:
        path = '/xlive/app-room/v1/index/getDanmuInfo'
        params = self.signed(
            {
                'actionKey': 'appkey',
                'build': '6640400',
                'channel': 'bili',
                'device': 'android',
                'mobi_app': 'android',
                'platform': 'android',
                'room_id': room_id,
                'ts': int(datetime.utcnow().timestamp()),
            }
        )
        json_res = await self._get_json(self.base_live_api_urls, path, params=params)
        return json_res['data']


class WebApi(BaseApi):
    _wbi_key = wbi.make_key(
        img_key="7cd084941338484aae1ad9425b84077c",
        sub_key="4932caff0ff746eab6f01bf08b70ac45",
    )
    _wbi_key_mtime = 0.0

    @retry(reraise=True, stop=stop_after_delay(20), wait=wait_exponential(0.1))
    async def _get_json_res(
        self, url: str, with_wbi: bool = False, *args: Any, **kwds: Any
    ) -> JsonResponse:
        if with_wbi:
            key = self.__class__._wbi_key
            ts = int(datetime.now().timestamp())
            params = list(kwds.pop("params").items())
            
            # 如果有gaia_vtoken，添加到wbi签名的参数中
            if self._gaia_vtoken:
                params.append(('gaia_vtoken', self._gaia_vtoken))
                
            query = wbi.build_query(key, ts, params)
            url = f'{url}?{query}'

        try:
            return await super()._get_json_res(url, *args, **kwds)
        except ApiRequestError as e:
            if e.code == -352 and time.monotonic() - self.__class__._wbi_key_mtime > 60:
                await self._update_wbi_key()
            raise

    async def room_init(self, room_id: int) -> ResponseData:
        path = '/room/v1/Room/room_init'
        params = {'id': room_id}
        json_res = await self._get_json(self.base_live_api_urls, path, params=params)
        return json_res['data']

    async def get_room_play_infos(
        self, room_id: int, qn: QualityNumber = 10000
    ) -> List[ResponseData]:
        path = '/xlive/web-room/v2/index/getRoomPlayInfo'
        params = {
            'room_id': room_id,
            'protocol': '0,1',
            'format': '0,1,2',
            'codec': '0,1',
            'qn': qn,
            'platform': 'web',
            'ptype': 8,
        }
        json_responses = await self._get_jsons_concurrently(
            self.base_play_info_api_urls, path, with_wbi=True, params=params
        )
        return [r['data'] for r in json_responses]

    async def get_info_by_room(self, room_id: int) -> ResponseData:
        path = '/xlive/web-room/v1/index/getInfoByRoom'
        params = {'room_id': room_id}
        json_res = await self._get_json(
            self.base_live_api_urls, path, with_wbi=True, params=params
        )
        return json_res['data']

    async def get_info(self, room_id: int) -> ResponseData:
        path = '/room/v1/Room/get_info'
        params = {'room_id': room_id}
        json_res = await self._get_json(self.base_live_api_urls, path, params=params)
        return json_res['data']

    async def get_timestamp(self) -> int:
        path = '/av/v1/Time/getTimestamp'
        params = {'platform': 'pc'}
        json_res = await self._get_json(self.base_live_api_urls, path, params=params)
        return json_res['data']['timestamp']

    async def get_user_info(self, uid: int) -> ResponseData:
        path = '/x/space/wbi/acc/info'
        params = {'mid': uid}
        json_res = await self._get_json(
            self.base_api_urls, path, with_wbi=True, params=params
        )
        return json_res['data']

    async def get_danmu_info(self, room_id: int) -> ResponseData:
        path = '/xlive/web-room/v1/index/getDanmuInfo'
        params = {'id': room_id}
        json_res = await self._get_json(
            self.base_live_api_urls, path, with_wbi=True, params=params
        )
        return json_res['data']

    async def get_nav(self) -> ResponseData:
        path = '/x/web-interface/nav'
        json_res = await self._get_json(self.base_api_urls, path, check_response=False)
        return json_res

    async def _update_wbi_key(self) -> None:
        nav = await self.get_nav()
        img_key = wbi.extract_key(nav['data']['wbi_img']['img_url'])
        sub_key = wbi.extract_key(nav['data']['wbi_img']['sub_url'])
        self.__class__._wbi_key = wbi.make_key(img_key, sub_key)
        self.__class__._wbi_key_mtime = time.monotonic()