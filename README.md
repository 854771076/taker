## TakerBot

使用说明

0.环境

python>=3.8

1.修改配置

将account.simple.csv 改名为 account.csv，并添加相应数据

将config.simple.json 改名为 config.json，并修改相应配置

```json
{
    "site":"https://earn.taker.xyz/",
    "sitekey":"0x4AAAAAAA4ve7ZW4oTHaChP",
    //有cf_api服务才启用
    "cf_task":false,
    "cf_api_url":"http://127.0.0.1:3000/cf-clearance-scraper",
    "cf_api_key":null,
    "cf_api_method":"turnstile-min",
    "RETRY_INTERVAL":3,
    "RETRY_COUNT":3,
    "rpc_url":"https://rpc-mainnet.taker.xyz/",
    //ip代理
    "proxy":"http://xxx:xxx@xxx:xxx",
    "chain_id":1125,
    "account_path":"./account.csv",
    "invite_code":"邀请码",
    "max_worker":10

}
```

2.安装python依赖

`pip install -r requirements.txt`

3.启动

`python bot.py`
