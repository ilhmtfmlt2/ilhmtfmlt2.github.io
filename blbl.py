import qrcode
import os
import time
import requests
import json
import urllib.parse
import hashlib
from datetime import datetime, timedelta
import random
import subprocess
import sys
import logging

# 定义URL列表
URL_LIST = {
    'checkTasks': 'https://api.bilibili.com/x/member/web/exp/reward',
    'watchVideo': 'https://api.bilibili.com/x/click-interface/web/heartbeat',
    'shareVideo': 'https://api.biliapi.net/x/share/finish',
    'dynamic': 'https://api.bilibili.com/x/polymer/web-dynamic/v1/feed/all',
    'videoProperty': 'https://api.bilibili.com/x/player/pagelist',
    'auth_code': 'https://passport.bilibili.com/x/passport-tv-login/qrcode/auth_code',
    'poll': 'https://passport.bilibili.com/x/passport-tv-login/qrcode/poll',
}

APPKEY = '4409e2ce8ffd12b8'
APPSEC = '59b43e04ad6965f34319062b478f83dd'

# 配置用户代理
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/125.0.0.0 Safari/537.36")

# 最大重试次数
MAX_RETRIES = 3

# 配置日志
logging.basicConfig(
    level=logging.INFO,  # 可以根据需要调整日志级别
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),  # 输出到控制台
        logging.FileHandler("script.log", encoding='utf-8')  # 输出到文件
    ]
)

logger = logging.getLogger(__name__)

def tvsign(params, appkey=APPKEY, appsec=APPSEC):
    """
    为请求参数进行 API 签名
    """
    params.update({'appkey': appkey})
    params = dict(sorted(params.items()))  # 重排序参数 key
    query = urllib.parse.urlencode(params)  # 序列化参数
    sign = hashlib.md5((query + appsec).encode()).hexdigest()  # 计算 API 签名
    params.update({'sign': sign})
    return params

def show_qrcode(qr_url):
    """使用 qrcode 库在终端显示二维码"""
    def generate_qrcode(data):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

    generate_qrcode(qr_url)  # 生成二维码

def login(session):
    """
    处理扫码登录，获取 access_key 和 cookies
    """
    # 获取二维码
    try:
        loginInfo = session.post(
            URL_LIST['auth_code'],
            params=tvsign({
                'local_id': '0',
                'ts': int(time.time())
            }),
            headers={
                "user-agent": USER_AGENT
            },
            timeout=10
        ).json()
    except requests.exceptions.RequestException as e:
        logger.error(f'请求获取二维码失败: {e}')
        return False

    if loginInfo.get('code') != 0:
        logger.error(f"获取二维码失败: {loginInfo.get('message')}")
        return False

    # 生成二维码
    logger.info("请使用哔哩哔哩 TV 端扫描以下二维码以登录：")
    show_qrcode(loginInfo['data']['url'])

    # 轮询二维码状态
    poll_attempts = 0
    max_polls = 60  # Max 60 attempts (e.g., 5 minutes with 5 sec interval)
    while poll_attempts < max_polls:
        try:
            pollInfo = session.post(
                URL_LIST['poll'],
                params=tvsign({
                    'auth_code': loginInfo['data']['auth_code'],
                    'local_id': '0',
                    'ts': int(time.time())
                }),
                headers={
                    "user-agent": USER_AGENT
                },
                timeout=10
            ).json()
        except requests.exceptions.RequestException as e:
            logger.error(f'请求轮询二维码状态失败: {e}')
            return False

        if pollInfo.get('code') == 0:
            loginData = pollInfo['data']
            break
        elif pollInfo.get('code') == -3:
            logger.error('API 校验密匙错误')
            return False
        elif pollInfo.get('code') == -400:
            logger.error('请求错误')
            return False
        elif pollInfo.get('code') == 86038:
            logger.error('二维码已失效')
            return False
        elif pollInfo.get('code') == 86039:
            logger.info('等待用户扫描二维码...')
            time.sleep(5)
            poll_attempts += 1
        else:
            logger.error(f"未知错误: {pollInfo.get('code')}")
            return False
    else:
        logger.error('轮询二维码状态超时，登录失败。')
        return False

    expiry_time = time.time() + int(loginData['expires_in'])
    expiry_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiry_time))
    logger.info(f"登录成功, 有效期至 {expiry_str}")

    saveInfo = {
        'update_time': int(time.time() * 1000 + 0.5),
        'token_info': loginData['token_info'],
        'cookie_info': loginData['cookie_info']
    }

    try:
        with open('info.json', 'w+', encoding='utf-8') as f:
            json.dump(saveInfo, f, ensure_ascii=False, separators=(',', ':'))
            logger.info("登录信息已保存至 info.json")
        return True
    except Exception as e:
        logger.error(f'保存登录信息失败: {e}')
        return False

def load_info():
    if not os.path.exists('info.json'):
        return None
    try:
        with open('info.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error('无法读取 info.json，请确保已成功登录。')
        return None

def parse_cookies(cookie_info):
    cookies = {}
    for cookie in cookie_info.get('cookies', []):
        key = cookie.get('name')
        value = cookie.get('value')
        if key and value:
            cookies[key] = value
    return cookies

def get_expiry_time():
    date = datetime.utcnow() + timedelta(days=1)
    date = date.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(date.timestamp())

def check_tasks(session, csrftoken):
    logger.info('正在检查任务列表...')
    try:
        headers = {
            'User-Agent': session.headers.get('User-Agent', ''),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Referer': 'https://t.bilibili.com/',
            'Origin': 'https://t.bilibili.com',
            'X-CSRF-TOKEN': csrftoken,
        }
        response = session.get(URL_LIST['checkTasks'], headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error(f'检查任务失败，状态码: {response.status_code}')
            return {}

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error('checkTasks 返回的不是有效的 JSON 数据。')
            return {}

        if not data or 'data' not in data:
            logger.error('checkTasks 返回数据异常。')
            return {}

        # 提取任务信息
        share_task = data['data'].get('share', False)
        watch_task = data['data'].get('watch', False)
        return {'share': share_task, 'watch': watch_task}
    except Exception as e:
        logger.error(f'检查任务时发生错误: {e}')
        return {}

def grab_video(session, csrftoken):
    logger.info('正在抓取视频...')
    video_prop = []

    try:
        headers = {
            'User-Agent': session.headers.get('User-Agent', ''),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Referer': 'https://t.bilibili.com/',
            'Origin': 'https://t.bilibili.com',
            'X-CSRF-TOKEN': csrftoken,
        }
        params_dynamic = {
            'timezone_offset': '-480',
            'type': 'video',
            'page': '1'
        }
        response = session.get(URL_LIST['dynamic'], params=params_dynamic, headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error(f'抓取动态失败，状态码: {response.status_code}')
            return []

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error('dynamic 返回的不是有效的 JSON 数据。')
            return []

        items = data.get('data', {}).get('items', [])
        if not items:
            logger.error('动态列表为空或数据格式异常。')
            return []

        first_item = items[0]
        modules = first_item.get('modules', {})
        major = modules.get('module_dynamic', {}).get('major', {}).get('archive', {})
        title = major.get('title', '未知标题')
        aid = major.get('aid')
        bvid = major.get('bvid')
        cid = None

        if not aid or not bvid:
            logger.error('缺少 aid 或 bvid。')
            return []

        # 获取 cid
        params_video_prop = {
            'bvid': bvid,
            'jsonp': 'jsonp'
        }
        response = session.get(URL_LIST['videoProperty'], params=params_video_prop, headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error(f'获取视频属性失败，状态码: {response.status_code}')
            return []

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error('videoProperty 返回的不是有效的 JSON 数据。')
            return []

        if data.get('code') != 0:
            logger.error(f"videoProperty 请求失败: {data.get('message')}")
            return []

        cid = data.get('data', [{}])[0].get('cid')
        if not cid:
            logger.error('获取 cid 失败。')
            return []

        video_prop = [aid, bvid, cid, title]
        logger.info(f'获取到视频: {title}')
        return video_prop

    except Exception as e:
        logger.error(f'抓取视频时发生错误: {e}')
        return []

def share_video(session, video_prop, access_key, mid, csrftoken, expiry_timestamp):
    if not access_key:
        logger.error('缺少 access_key, 无法分享视频')
        return

    aid, bvid, cid, title = video_prop
    logger.info(f'正在分享视频: {title}')

    # 生成 share_session_id
    share_session_id = f'6609bb15-ac05-4118-8f12-cb{int(time.time())}'

    # 生成签名
    body_params = {
        'access_key': access_key,  # 使用 access_token 代替
        'appkey': APPKEY,
        'build': '7082000',
        'c_locale': 'zh_CN',
        'channel': 'bili',
        'disable_rcmd': '0',
        'from_spmid': 'dt.dt.video.0',
        'mobi_app': 'android',
        'oid': aid,
        'panel_type': '1',
        'platform': 'android',
        's_locale': 'zh_CN',
        'share_channel': 'biliDynamic',
        'share_id': 'main.ugc-video-detail.0.0.pv',
        'share_origin': 'vinfo_share',
        'share_session_id': share_session_id,
        'sid': cid,
        'spm_id': 'main.ugc-video-detail.0.0',
        'statistics': '{"appId":1,"platform":3,"version":"8.29.1","abtest":""}',
        'success': 'true',
        'ts': str(int(time.time())),
    }

    body_string = urllib.parse.urlencode(body_params)
    sign = hashlib.md5((body_string + '560c52ccd288fed045859ed18bffd973').encode('utf-8')).hexdigest()
    body_params['sign'] = sign
    body_encoded = urllib.parse.urlencode(body_params)

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'User-Agent': session.headers.get('User-Agent', ''),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Referer': 'https://t.bilibili.com/',
        'Origin': 'https://t.bilibili.com',
        'X-CSRF-TOKEN': csrftoken,
    }

    try:
        response = session.post(URL_LIST['shareVideo'], data=body_encoded, headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error(f'分享视频失败，状态码: {response.status_code}')
            return

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error('shareVideo 返回的不是有效的 JSON 数据。')
            return

        if data.get('code') == 0:
            toast = data.get('data', {}).get('toast')
            if toast:
                logger.info(toast)
            else:
                logger.info('分享视频任务成功完成')
            # 设置 shareVideoDone 为 True
            session.cookies.set('shareVideoDone', 'true', domain='.bilibili.com', path='/', expires=expiry_timestamp)
        else:
            message = data.get('message', '未知错误')
            logger.error(f"分享视频失败: {message}")
    except Exception as e:
        logger.error(f'分享视频时发生错误: {e}')

def watch_video(session, video_prop, mid, csrftoken, expiry_timestamp):
    aid, bvid, cid, title = video_prop
    logger.info(f'正在观看视频: {title}')

    body = {
        'aid': aid,
        'cid': cid,
        'bvid': bvid,
        'mid': mid,
        'csrf': csrftoken,
        'played_time': '11',
        'real_played_time': '12',
        'realtime': '11',
        'start_ts': str(int(time.time())),
        'type': '3',
        'dt': '2',
        'play_type': '2',
        'from_spmid': '444.41.list.card_archive.click',
        'spmid': '333.788.0.0',
        'auto_continued_play': '0',
        'refer_url': 'https://t.bilibili.com/?tab=video',
        'bsource': ''
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': session.headers.get('User-Agent', ''),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Referer': 'https://t.bilibili.com/',
        'Origin': 'https://t.bilibili.com',
        'X-CSRF-TOKEN': csrftoken,
    }

    try:
        response = session.post(URL_LIST['watchVideo'], data=urllib.parse.urlencode(body), headers=headers, timeout=10)

        if response.status_code != 200:
            logger.error(f'观看视频失败，状态码: {response.status_code}')
            return

        try:
            data = response.json()
        except json.JSONDecodeError:
            logger.error('watchVideo 返回的不是有效的 JSON 数据。')
            return

        if data.get('code') == 0:
            logger.info('观看视频任务成功完成！')
            # 设置 watchVideoDone 为 True
            session.cookies.set('watchVideoDone', 'true', domain='.bilibili.com', path='/', expires=expiry_timestamp)
        else:
            message = data.get('message', '未知错误')
            logger.error(f"观看视频任务失败: {message}")
    except Exception as e:
        logger.error(f'观看视频时发生错误: {e}')

def execute_tasks(session, access_key, mid, csrftoken, expiry_timestamp):
    # 检查任务
    tasks = check_tasks(session, csrftoken)
    task_list = {
        'share': tasks.get('share', False),
        'watch': tasks.get('watch', False)
    }

    logger.info(
        f'任务状态: 分享任务 - {"未完成" if not task_list["share"] else "已完成"}, '
        f'观看任务 - {"未完成" if not task_list["watch"] else "已完成"}'
    )

    if task_list['share'] and task_list['watch']:
        logger.info('所有任务已经完成！')
        return True  # 任务已完成

    # 抓取视频
    video_prop = grab_video(session, csrftoken)
    if not video_prop:
        logger.warning('未能获取视频信息，准备重试...')
        return False  # 表示需要重试

    # 完成观看视频任务
    if not task_list['watch']:
        delay = random.uniform(0, 100)  # 随机延迟，最大延迟100秒
        logger.info(f'等待 {delay:.2f} 秒后开始观看视频...')
        time.sleep(delay)
        watch_video(session, video_prop, mid, csrftoken, expiry_timestamp)
    else:
        logger.info('观看视频任务已经完成！')

    # 完成分享视频任务
    if not task_list['share']:
        # 不再获取 access_key，直接使用 access_token
        if not access_key or access_key == 'null':
            logger.error('access_key 无效，无法分享视频')
            return False  # 表示需要重试
        delay = random.uniform(0, 100)  # 随机延迟，最大延迟100秒
        logger.info(f'等待 {delay:.2f} 秒后开始分享视频...')
        time.sleep(delay)
        share_video(session, video_prop, access_key, mid, csrftoken, expiry_timestamp)
    else:
        logger.info('分享视频任务已经完成！')

    return True  # 任务执行完成

def retry_refresh_and_retry_task(session):
    """
    调用 refresh.py 并重试任务
    """
    global retry_count
    if retry_count >= MAX_RETRIES:
        logger.error(f'已达到最大重试次数 ({MAX_RETRIES})，不再重试。')
        return False

    logger.info('尝试调用 refresh.py 来修复账号...')
    try:
        # 调用 refresh.py，假设它位于同一目录下
        result = subprocess.run([sys.executable, 'refresh.py'], capture_output=True, text=True)
        logger.info(f'refresh.py 输出: {result.stdout.strip()}')
        if result.returncode != 0:
            logger.error(f'调用 refresh.py 失败: {result.stderr.strip()}')
            return False
    except Exception as e:
        logger.error(f'调用 refresh.py 时发生异常: {e}')
        return False

    # 重置登录信息
    logger.info('重新加载登录信息...')
    info = load_info()
    if not info:
        logger.error('重新加载登录信息失败。')
        return False

    token_info = info.get('token_info', {})
    cookie_info = info.get('cookie_info', {})
    access_token = token_info.get('access_token')
    mid = token_info.get('mid')

    if not access_token or not mid:
        logger.error('access_token 或 mid 不存在，请确保已成功登录。')
        return False

    # 解析 Cookies
    cookies = parse_cookies(cookie_info)
    csrftoken = cookies.get('bili_jct')

    if not csrftoken:
        logger.error('bili_jct (csrf) 不存在，请确保已成功登录。')
        return False

    # 使用 access_token 作为 access_key
    access_key = access_token  # 修改此处

    # 设置 Cookies
    session.cookies.update(cookies)

    # 设置记录性 Cookies 过期时间
    expiry_timestamp = get_expiry_time()

    # 增加重试计数
    retry_count += 1

    logger.info('重试执行任务...')
    return True

def main():
    global retry_count
    retry_count = 0  # 初始化重试计数

    while retry_count <= MAX_RETRIES:
        # 初始化会话
        session = requests.Session()
        session.headers.update({
            "user-agent": USER_AGENT
        })

        # 检查是否存在 info.json
        info = load_info()

        if not info:
            logger.info("未检测到登录信息。")
            # 自动进行登录
            logger.info("开始登录...")
            success = login(session)
            if not success:
                logger.error("登录失败，脚本终止。")
                return
            # 重新加载 info.json
            info = load_info()
            if not info:
                logger.error("登录信息加载失败，脚本终止。")
                return

        token_info = info.get('token_info', {})
        cookie_info = info.get('cookie_info', {})
        access_token = token_info.get('access_token')
        mid = token_info.get('mid')

        if not access_token or not mid:
            logger.error('access_token 或 mid 不存在，请确保已成功登录。')
            # 尝试调用 refresh.py 并重试
            if not retry_refresh_and_retry_task(session):
                logger.error("无法获取有效的 access_token 或 mid，脚本终止。")
                return
            else:
                continue  # 重试后重新开始循环

        # 解析 Cookies
        cookies = parse_cookies(cookie_info)
        csrftoken = cookies.get('bili_jct')

        if not csrftoken:
            logger.error('bili_jct (csrf) 不存在，请确保已成功登录。')
            # 尝试调用 refresh.py 并重试
            if not retry_refresh_and_retry_task(session):
                logger.error("无法获取有效的 csrf，脚本终止。")
                return
            else:
                continue  # 重试后重新开始循环

        # 使用 access_token 作为 access_key
        access_key = access_token  # 修改此处

        # 设置 Cookies
        session.cookies.update(cookies)

        # 设置记录性 Cookies 过期时间
        expiry_timestamp = get_expiry_time()

        # 执行任务
        success = execute_tasks(session, access_key, mid, csrftoken, expiry_timestamp)
        if success:
            logger.info('任务执行完毕。')
            break  # 成功执行完任务，退出循环
        else:
            logger.warning('任务执行失败，准备重试...')
            if not retry_refresh_and_retry_task(session):
                logger.error("重试失败，脚本终止。")
                return
            # 如果重试成功，继续循环

    else:
        logger.error(f'已达到最大重试次数 ({MAX_RETRIES})，脚本终止。')

if __name__ == "__main__":
    main()
