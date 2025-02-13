import requests
import json
from util import *
import random
from loguru import logger
from fake_useragent import UserAgent
from web3 import Web3
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from eth_account.messages import encode_defunct
from threading import Lock
from functools import *
from eth_account.signers.local import LocalAccount
import jwt
from apscheduler.schedulers.blocking import BlockingScheduler




class Config():
    def __init__(self,path='./config.json'):
        self.path=path
        self.config=self.load_config()
        self.accounts=self.load_accounts()
        self._lock = Lock()
    def load_config(self):
        with open(self.path,'r') as f:
            config=json.load(f)
        for key in config:
            setattr(self,key,config[key])
        return config
    def load_accounts(self):
        try:
            df=pd.read_csv(self.account_path)
        except:
            df=pd.read_csv(self.account_path,encoding='gbk')
        df=df.fillna(False).replace('False',None).replace('True',True)
        return df.to_dict('records') 
    def save_accounts(self):
        with self._lock:
            df=pd.DataFrame(self.accounts)
            df.to_csv(self.account_path,index=False)
    def get_random_invite_code(self):
        register_account=[i.get('invitationCode') for i in self.accounts if i.get('invitationCode') and i.get('bind_x')][:10]+[self.invite_code for i in range(10)]
        if not register_account:
            return self.invite_code
        return random.choice(register_account)

class TakerBot():

    def __init__(self,account,config:Config):
        self.account=account
        self.proxies = {
            "http": config.proxy,
            "https": config.proxy,
        }
        self.web3 = Web3(Web3.HTTPProvider(config.rpc_url,request_kwargs={"proxies": self.proxies}))
        self.RETRY_INTERVAL=config.RETRY_INTERVAL
        if not self.web3.is_connected():
            logger.warning("无法连接到 Taker 节点,重试中...")
            time.sleep(self.RETRY_INTERVAL)
            self.__init__(account,config)
        self.chain_id = config.chain_id
        self.session=requests.session()
        
        self.ua=UserAgent()
        self.headers={
            'Accept': 'application/json, text/plain, */*',
            'Origin': 'https://earn.taker.xyz',
            'Pragma': 'no-cache',
            'Referer': 'https://earn.taker.xyz/',
            'User-Agent': self.ua.chrome,
        }
        self.session.headers=self.headers
        self.session.proxies=self.proxies
        self.account=account
        self.config=config
        self.wallet:LocalAccount=self.web3.eth.account.from_key(self.account.get("private_key"))
    def get_sign(self, private_key, msg):
        # 账户信息
        # 使用web3.py编码消息
        message_encoded = encode_defunct(text=msg)
        # 签名消息
        signed_message = self.web3.eth.account.sign_message(
            message_encoded, private_key=private_key
        ).signature.hex()
        if '0x' not in signed_message:
            signed_message = '0x' + signed_message
        # 打印签名的消息
        return signed_message
    # 写一个函数检查jwttoken的过期时间
    def check_jwt_exp(self, token):
        if not token:
            return False
        # 解析JWT
        payload = jwt.decode(token, options={"verify_signature": False})
        # 获取过期时间
        exp = payload.get('exp')
        # 当前时间
        now = int(time.time())
        # 检查过期时间
        if exp and exp < now:
            return False
        return True
    def login(self):
        def get_nonce():
            json_data = {
                'walletAddress': self.wallet.address,
            }
            response = self.session.post('https://lightmining-api.taker.xyz/wallet/generateNonce', json=json_data)
            data=self._handle_response(response)
            nonce=data.get('data',{}).get('nonce')
            return nonce
        def get_user_info():
            response = self.session.get('https://lightmining-api.taker.xyz/user/getUserInfo')
            data=self._handle_response(response)
            return data.get('data',{})
        token=self.account.get('token')
        if token and self.check_jwt_exp(token):
            logger.info(f"账户:{self.wallet.address},token复用")
        else:
            if not self.account.get('registed'):
                logger.warning(f"账户:{self.wallet.address},未注册,注册中...")
                nonce=get_nonce()
                json_data = {
                    'address': self.wallet.address,
                    'signature': self.get_sign(self.wallet.key, nonce),
                    "invitationCode":self.config.get_random_invite_code(),
                    'message': nonce,
                }
            else:
                logger.warning(f"账户:{self.wallet.address},token失效,登录中...")
                nonce=get_nonce()
                json_data = {
                    'address': self.wallet.address,
                    'signature': self.get_sign(self.wallet.key, nonce),
                    # "invitationCode":self.config.get_random_invite_code(),
                    'message': nonce,
                }
                
            response = self.session.post('https://lightmining-api.taker.xyz/wallet/login', json=json_data)
            data=self._handle_response(response)
            token=data.get('data',{}).get('token')
            if not self.account.get('registed'):
                self.account['registed']=True
                self.config.save_accounts()
            self.account['token']=token
            self.config.save_accounts()
        self.session.headers.update({
            'Authorization': 'Bearer '+token
        })
        userinfo=get_user_info()
        self.account.update(userinfo)
        self.config.save_accounts()
        logger.success(f"登录成功,账户:{self.wallet.address}")
    def connect_x(self,url="https://twitter.com/i/oauth2/authorize?response_type=code&client_id=d1E1aFNaS0xVc2swaVhFaVltQlY6MTpjaQ&redirect_uri=https%3A%2F%2Fearn.taker.xyz%2Fbind%2Fx&scope=tweet.read+users.read+follows.read&state=state&code_challenge=challenge&code_challenge_method=plain"):
        assert self.account.get('registed'),"账户未注册"
        assert self.account.get('x_token'),"x_token为空"
        if self.account.get('bind_x'):
            return
        def submit_connect_x(oauth_token):
            json_data = {
                'code': oauth_token,
                'redirectUri': 'https://earn.taker.xyz/bind/x',
                'bindType': 'x',
            }
            response = self.session.post('https://lightmining-api.taker.xyz/odyssey/bind/mediaAccount', json=json_data)
            data=self._handle_response(response)
            msg=data.get('msg')
            self.account['bind_x']=True
            self.config.save_accounts()
            logger.success(f"账户:{self.wallet.address},{msg},x绑定成功")
        xauth=XAuth(self.account.get('x_token'))
        oauth_token=xauth.oauth2(url)
        submit_connect_x(oauth_token)
    def mining(self):
        assert self.account.get('registed'),"账户未注册"
        assert  self.account.get('bind_x'),"x未绑定"
        def get_last_mining_time():
            response = self.session.get('https://lightmining-api.taker.xyz/assignment/totalMiningTime')
            data=self._handle_response(response)
            return data.get('data',{}).get('lastMiningTime')
        def start_mining():
            response = self.session.post('https://lightmining-api.taker.xyz/assignment/startMining')
            data=self._handle_response(response)
            msg=data.get('msg')
            if not self.account.get('mining_first'):
                self.account['mining_first']=True
                self.config.save_accounts()
            logger.success(f"账户:{self.wallet.address},{msg},开始挖矿")
        def start_mining_by_contract(abi,address):
            contract=self.web3.eth.contract(address=address,abi=abi)
            tx=contract.functions.active().build_transaction({
                'from': self.wallet.address,
                'gas': 200000,
                'gasPrice': self.web3.eth.gas_price,
                'nonce': self.web3.eth.get_transaction_count(self.wallet.address), 
            })
            signed_txn = self.wallet.sign_transaction(tx)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt.status == 1:
                logger.success(f"账户:{self.wallet.address},合约:{address},开始挖矿")
                start_mining()
            else:
                logger.error(f"账户:{self.wallet.address},合约:{address},开始挖矿失败,原因:{receipt}")
        assert self.account.get('registed'),"账户未注册"
        last_mining_time=get_last_mining_time()
        can_mining=is_24_hours_away(last_mining_time)
        if can_mining:
            address='0xB3eFE5105b835E5Dd9D206445Dbd66DF24b912AB'
            abi=json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"address","name":"target","type":"address"}],"name":"AddressEmptyCode","type":"error"},{"inputs":[{"internalType":"address","name":"implementation","type":"address"}],"name":"ERC1967InvalidImplementation","type":"error"},{"inputs":[],"name":"ERC1967NonPayable","type":"error"},{"inputs":[],"name":"FailedInnerCall","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"inputs":[],"name":"UUPSUnauthorizedCallContext","type":"error"},{"inputs":[{"internalType":"bytes32","name":"slot","type":"bytes32"}],"name":"UUPSUnsupportedProxiableUUID","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":true,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"Active","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"implementation","type":"address"}],"name":"Upgraded","type":"event"},{"inputs":[],"name":"UPGRADE_INTERFACE_VERSION","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"active","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"}],"name":"getUserActiveLogs","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"initialOwner","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"proxiableUUID","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newImplementation","type":"address"},{"internalType":"bytes","name":"data","type":"bytes"}],"name":"upgradeToAndCall","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"userActiveLogs","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"userLastActiveTime","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"users","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"usersLength","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]')
            if not self.account.get('mining_first'):
                start_mining()
            else:
                start_mining_by_contract(abi,address)
        else:
            logger.warning(f"账户:{self.wallet.address},24小时内已挖矿")
    def get_task(self):
        assert self.account.get('registed'),"账户未注册"
        assert  self.account.get('bind_x'),"x未绑定"
        response = self.session.post('https://lightmining-api.taker.xyz/assignment/list')
        data=self._handle_response(response)
        tasks=[task for task in data.get('data',[]) if not task.get('done') and task.get('assignmentId') not in [2,3,6,7,8,9,10,11,12]]
        if not tasks:
            logger.warning(f"账户:{self.wallet.address},无未完成任务")
            return []
        return tasks
    def done_tasks(self):
        def done_task(task):
            assignmentId=task.get('assignmentId')
            if task.get('cfVerify'):
                if not self.config.cf_task:
                    return 
                cf_token=get_cf_token(self.config.site,self.config.sitekey,method=self.config.cf_api_method,url=self.config.cf_api_url,authToken=self.config.cf_api_key)
                json_data = {
                    'assignmentId': assignmentId,
                    'verifyResp': cf_token,
                }
            else:
                json_data = {
                    'assignmentId': assignmentId,
                }
            response = self.session.post('https://lightmining-api.taker.xyz/assignment/do', json=json_data)
            data=self._handle_response(response)
            msg=data.get('msg')
            logger.success(f"账户:{self.wallet.address},完成任务:{assignmentId},{msg}")
        assert self.account.get('registed'),"账户未注册"
        assert  self.account.get('bind_x'),"x未绑定"
        task_list=self.get_task()
        if not task_list:
            return
        for task in task_list:
            try:
                done_task(task)  
            except Exception as e:
                logger.error(f"账户:{self.wallet.address},完成任务:{task.get('assignmentId')}失败,{e}")
            time.sleep(3)

    def _handle_response(self, response: requests.Response, retry_func=None) -> None:
        """处理响应状态"""
        try:
            response.raise_for_status()
            data=response.json()
            if data.get('code')!=200:
                raise Exception(f"执行异常：{data.get('msg')}")
            return data
        # 抛出代理错误
        except requests.exceptions.ProxyError as e:
            logger.warning(f"代理错误: {e},重试中...")
            time.sleep(self.config.RETRY_INTERVAL)
            if retry_func:
                return retry_func()
        except Exception as e:
            raise Exception(f"请求过程中发生错误: {e}")

class TakerBotManager():
    def __init__(self,config:Config):
        self.config=config
        self.accounts=config.accounts
    def run_single(self,account):
        bot=TakerBot(account,config)
        bot.login()
        bot.connect_x()
        try:
            bot.mining()
        except Exception as e:
            logger.error(f"账户:{bot.wallet.address},挖矿失败,{e}")
        bot.done_tasks()
    def run(self):
        with ThreadPoolExecutor(max_workers=self.config.max_worker) as executor:
            futures = [executor.submit(self.run_single, account) for account in self.accounts]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"执行过程中发生错误: {e}")
    
if __name__ == '__main__':
    config=Config()
    manager=TakerBotManager(config)
    manager.run()
    # 执行后每过24小时执行一次
    scheduler = BlockingScheduler()
    scheduler.add_job(manager.run, 'interval', hours=24)
    scheduler.start()