import asyncio, sys
import json
import os
import random
import string
import time
from curl_cffi.requests import AsyncSession
from loguru import logger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
from tenacity import retry, wait_fixed, stop_after_attempt, retry_if_result

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")
old_tokens = []
inviteCodesList = []
inviteTime = 0
setTimes = 0


def returnFalse(_):
    return False


retry_pamars = {
    'wait': wait_fixed(2),
    'stop': stop_after_attempt(7),
    'retry': retry_if_result(lambda x: x is False),
    'retry_error_callback': returnFalse
}


class GoogleV2:
    def __init__(self, userToken):
        self.userToken = userToken
        self.client = AsyncSession(timeout=120)
        self.taskId = None

    async def nocaptcha(self):
        try:
            headers = {
                'User-Token': self.userToken,
                'Developer-Id': 'dwBf1P'
            }
            json_data = {
                "referer": "https://nebx.io",
                "sitekey": "6LcqEzMqAAAAAH0rnqHOElnkzZUv_yXsi_AOis7t",
                "size": "normal",
                "title": "Nebx",
            }
            res = await self.client.post('http://api.nocaptcha.io/api/wanda/recaptcha/universal', headers=headers, json=json_data)
            if res.json()['status'] == 1:
                return res.json()['data']['token']
            return None
        except Exception as e:
            return None

    async def createTaskcapsolver(self):
        json_data = {
            "clientKey": self.userToken,
            "appId": "69AE5D43-F131-433D-92C8-0947B2CF150A",
            "task": {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteKey": "6LcqEzMqAAAAAH0rnqHOElnkzZUv_yXsi_AOis7t",
                "websiteURL": "https://nebx.io"
            }
        }
        for _ in range(3):
            try:
                response = await self.client.post('https://api.capsolver.com/createTask', json=json_data)
                if response.json()['errorId'] == 0:
                    self.taskId = response.json()['taskId']
                    return True
            except:
                pass
        return False

    async def capsolver(self):
        if not await self.createTaskcapsolver():
            return None
        json_data = {
            "clientKey": self.userToken,
            "taskId": self.taskId
        }
        for _ in range(30):
            try:
                response = await self.client.post('https://api.capsolver.com/getTaskResult', json=json_data)
                if response.json()['errorId'] == 0 and response.json()['status'] == 'ready':
                    return response.json()['solution']['gRecaptchaResponse']
                elif response.json()['errorId'] == 1:
                    return None
            except:
                pass
            await asyncio.sleep(3)
        return None


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "x.com",
            "origin": "https://x.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120)
        self.auth_code = None

    async def get_auth_code(self, client_id, state, code_challenge):
        try:
            params = {
                'code_challenge': code_challenge,
                'code_challenge_method': 'plain',
                'client_id': client_id,
                'redirect_uri': 'https://nebx.io/login',
                'response_type': 'code',
                'scope': 'tweet.read users.read follows.read',
                'state': state
            }
            response = await self.Twitter.get('https://twitter.com/i/api/2/oauth2/authorize', params=params)
            if "code" in response.json() and response.json()["code"] == 353:
                self.Twitter.headers.update({"x-csrf-token": response.cookies["ct0"]})
                return await self.get_auth_code(client_id, state, code_challenge)
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.get_auth_code(client_id, state, code_challenge)
            elif 'auth_code' in response.json():
                self.auth_code = response.json()['auth_code']
                return True
            logger.error(f'{self.auth_token} 获取auth_code失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self, client_id, state, code_challenge):
        try:
            if not await self.get_auth_code(client_id, state, code_challenge):
                return False
            data = {
                'approval': 'true',
                'code': self.auth_code,
            }
            response = await self.Twitter.post('https://twitter.com/i/api/2/oauth2/authorize', data=data)
            if 'redirect_uri' in response.text:
                return True
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.twitter_authorize(client_id, state, code_challenge)
            logger.error(f'{self.auth_token}  推特授权失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特授权异常：{e}')
            return False

    async def follow(self, user_id):
        global old_tokens
        try:
            data = {
                'include_profile_interstitial_type': 1,
                'include_blocking': 1,
                'include_blocked_by': 1,
                'include_followed_by': 1,
                'include_want_retweets': 1,
                'include_mute_edge': 1,
                'include_can_dm': 1,
                'include_can_media_tag': 1,
                'include_ext_is_blue_verified': 1,
                'include_ext_verified_type': 1,
                'include_ext_profile_image_shape': 1,
                'skip_status': 1,
                'user_id': user_id
            }
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            res = await self.Twitter.post('https://twitter.com/i/api/1.1/friendships/create.json', data=data, headers=headers)
            if res.status_code == 200:
                return True
            elif "errors" in res.json():
                if res.json()["errors"][0]["code"] == 353:
                    self.Twitter.headers.update({"x-csrf-token": res.cookies["ct0"]})
                    return await self.follow(user_id)
                elif res.json()["errors"][0]["code"] == 32 or res.json()["errors"][0]["code"] == 64:
                    logger.error(f'{self.auth_token}  账号被封 剔除')
                    old_tokens.remove(self.auth_token)
                elif res.json()["errors"][0]["code"] == 326:
                    logger.error(f'{self.auth_token}  账号被锁定 剔除')
                    old_tokens.remove(self.auth_token)
                elif res.json()["errors"][0]["code"] == 344:
                    logger.error(f'{self.auth_token}  账号关注限制 剔除')
                    old_tokens.remove(self.auth_token)
                return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特关注异常：{e}')
            return False


class Nebx:
    def __init__(self, accounts, google_platform, google_userToken, nstproxy_Channel, nstproxy_Password):
        self.token = 'cfcd208495d565ef66e7dff9f98764da-8bb56c77b9dded9f82d6b9ccc6dde965-ae26fe5b4ce38925e6f13a7167fed3ea'
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Origin": "https://nebx.io",
            "Referer": "https://nebx.io/",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
        }
        session = ''.join(random.choices(string.digits + string.ascii_letters, k=10))
        self.nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_0m-s_{session}:{nstproxy_Password}@gate.nstproxy.io:24125"
        self.client = AsyncSession(timeout=120, headers=headers, impersonate="chrome120", proxy=self.nstproxy)
        self.Twitter = Twitter(accounts[4])
        self.Google = GoogleV2(google_userToken)
        self.auth_token, self.google_platform, self.inviteCode = accounts[4], google_platform, None
        self.uuid, self.clientId, self.state, self.googleCode = None, None, None, None
        self.userId = accounts[-2].split('-')[0]

    def encode(self, info):
        encodeKey = self.client.headers.get('Authorization').split('-')[0].replace('Bearer ', '')[:16]
        key = encodeKey.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, key)
        padded_text = pad(info.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted).decode('utf-8')

    def decode(self, info):
        decodeKey = self.client.headers.get('Authorization').split('-')[2][:16]
        key = decodeKey.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, key)
        decrypted = unpad(cipher.decrypt(binascii.unhexlify(info)), AES.block_size)
        return decrypted.decode('utf-8')

    async def follow(self):
        try:
            logger.info(f'{self.auth_token}  开始刷推特关注')
            if len(old_tokens) < 8:
                logger.error(f'{self.auth_token}  老号数量不够8')
                return False
            times = 0
            for old_token in old_tokens:
                if await Twitter(old_token).follow(self.userId):
                    times += 1
                    if times == 8:
                        return True
            else:
                logger.error(f'{self.auth_token}  推特关注{times}, 未达到8')
                return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特关注异常：{e}')
            return False

    @retry(**retry_pamars)
    async def get_auth_code(self):
        try:
            if self.googleCode is None:
                if self.google_platform == 1:
                    self.googleCode = await self.Google.nocaptcha()
                elif self.google_platform == 2:
                    self.googleCode = await self.Google.capsolver()
                if self.googleCode is None:
                    logger.error(f'{self.auth_token}  获取谷歌验证码失败')
                    return False
            uuid = int(time.time() * 1000)
            info = {
                "googleCode": self.googleCode,
                "uuid": uuid
            }
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.get(f'https://apiv1.nebx.io/login/xauth_url?sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                clientId = resdata['clientId']
                state = resdata['url'].split('state=')[1].split('&')[0]
                code_challenge = resdata['url'].split('code_challenge=')[1].split('&')[0]
                if await self.Twitter.twitter_authorize(clientId, state, code_challenge):
                    logger.success(f'{self.auth_token}  推特授权成功')
                    self.uuid, self.clientId, self.state = uuid, clientId, state
                    return True
                else:
                    logger.error(f'{self.auth_token}  推特授权失败')
                    return False
            elif 'google verification failed' in res.text:
                self.googleCode = None
                return False
            logger.error(f'{self.auth_token}  获取推特授权链接失败===网页返回错误{res.status_code} {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  获取推特授权链接异常：{e}')
            return False

    @retry(**retry_pamars)
    async def login(self):
        global inviteCodesList
        self.inviteCode = inviteCodesList[0]
        try:
            info = {
                "state": self.state,
                "code": self.Twitter.auth_code,
                "clientId": self.clientId,
                "googleCode": self.googleCode,
                "inviteCode": self.inviteCode,
                "uuid": self.uuid
            }
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://apiv1.nebx.io/login/sign_in', data=f'sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                if 'token' in resdata:
                    with open('登录成功.txt', 'a') as f:
                        f.write(f'{self.auth_token}----{self.token}\n')
                    self.token = resdata['token']
                    self.client.headers.update({"Authorization": f"Bearer {self.token}"})
                    return True
            logger.error(f'{self.auth_token}  登录失败===网页返回错误{res.status_code} {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  登录异常：{e}')
            return False

    @retry(**retry_pamars)
    async def check(self):
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://apiv1.nebx.io/user/check', data=f'sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                score = resdata['score']
                logger.success(f'{self.auth_token}  积分{score}')
                return True
            logger.error(f'{self.auth_token}  检测积分失败===网页返回错误{res.status_code} {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  登检测积分异常：{e}')
            return False

    @retry(**retry_pamars)
    async def receive(self):
        global inviteTime, inviteCodesList, setTimes
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://apiv1.nebx.io/user/check_award', data=f'sign={self.encode(info)}')
            if res.status_code == 200:
                inviteTime += 1
                logger.success(f'{self.auth_token}  领取积分成功 {self.inviteCode} 邀请 {inviteTime}/{setTimes}')
                if inviteTime == setTimes:
                    inviteTime = 0
                    inviteCodesList = inviteCodesList[1:]
                    logger.info(f'{self.auth_token}  邀请码{self.inviteCode}已达到设定次数, 更换下一个邀请码{inviteCodesList[0]}')
                with open('领取成功.txt', 'a') as f:
                    f.write(f'{self.auth_token}----{self.token}\n')
                return True
            elif res.text == 'Already received the reward':
                logger.error(f'{self.auth_token}  已被领取过')
                with open('登录成功.txt', 'a') as f:
                    f.write(f'{self.auth_token}----{self.token}\n')
                return True
            logger.error(f'{self.auth_token}  领取积分失败===网页返回错误{res.status_code} {res.text}')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  领取积分异常：{e}')
            return False


async def do(semaphore, accounts, google_platform, google_userToken, nstproxy_Channel, nstproxy_Password):
    async with semaphore:
        nebx = Nebx(accounts, google_platform, google_userToken, nstproxy_Channel, nstproxy_Password)
        if await nebx.follow():
            if await nebx.get_auth_code() and await nebx.login():
                if await nebx.check() and await nebx.receive():
                    return True
            else:
                with open('未跑成功.txt', 'a') as f:
                    f.write(f"{'----'.join(accounts)}\n")


async def main(filePath, oldfilePath, tread, inviteCodes, times, google_platform, google_userToken, nstproxy_Channel, nstproxy_Password):
    semaphore = asyncio.Semaphore(int(tread))
    os.system(f"title 小号：{os.path.basename(filePath)}  老号：{os.path.basename(oldfilePath)}")
    global old_tokens, inviteCodesList, setTimes
    with open(oldfilePath, 'r') as f:
        old_tokens = [line.strip() for line in f]
    inviteCodesList = inviteCodes.split(',')
    inviteCodesList = [code.strip() for code in inviteCodesList if len(code.strip()) != 0]
    setTimes = int(times)
    try:
        with open(f'领取成功.txt', 'r') as f:
            received = set(line.strip().split('----')[0] for line in f)
    except:
        with open(f'领取成功.txt', 'w'):
            received = set()
    try:
        with open(f'登录成功.txt', 'r') as f:
            received.union(set(line.strip().split('----')[0] for line in f))
    except:
        with open(f'登录成功.txt', 'w'):
            pass

    with open(filePath, 'r') as f:
        task = [do(semaphore, accounts.split('----'), google_platform, google_userToken, nstproxy_Channel, nstproxy_Password) for accounts in f if accounts.split('----')[4] not in received]
    await asyncio.gather(*task)


def menu():
    _filePath = input("请输入账户文件路径(hdd.cm购买格式)：").strip()
    print("老号用来关注小号，有几十个就行")
    _oldfilePath = input("请输入老号文件路径(只需要auth_token)：").strip()
    _tread = input("请输入并发数：").strip()
    _inviteCodes = input("请输入大号邀请码(多个用,割开)：").strip()
    _times = input("请输入每个邀请码使用次数(实际一般会比这个多)：").strip()
    _nstproxy_Channel = input('请输入nstproxy_通道ID:').strip()
    _nstproxy_Password = input('请输入nstproxy_密码:').strip()
    _google_platform = input('使用nocaptcha请输入1，使用capsolver请输入2:').strip()
    _google_platform = int(_google_platform)
    if _google_platform == 1:
        _google_userToken = input('请输入nocaptcha的ApiKey:').strip()
    elif _google_platform == 2:
        _google_userToken = input('请输入capsolver的ApiKey:').strip()
    else:
        print('输入错误')
        return
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main(_filePath, _oldfilePath, _tread, _inviteCodes, _times, _google_platform, _google_userToken, _nstproxy_Channel, _nstproxy_Password))


if __name__ == '__main__':
    _info = '''如果出现Failed to connect to twitter, com port，是网络问题，自己想办法，不行国外VPS
        代理平台：注册充值，创建频道
        nstproxy注册链接：https://app.nstproxy.com/register?i=7JunWz
        谷歌验证码平台，二选一，注册充值
        capsolver注册链接（这个便宜）：https://dashboard.capsolver.com/passport/register?inviteCode=-6bvop_IGgaT
        nocaptcha注册链接（这个快）：https://www.nocaptcha.io/register?c=dwBf1P 
    '''
    print(_info)
    print('hdd.cm 推特低至1毛5')
    print('hdd.cm 推特低至1毛5')
    print('会用用，不会用算了，不提供技术支持')
    print('会用用，不会用算了，不提供技术支持')
    print('会用用，不会用算了，不提供技术支持')
    while True:
        menu()
