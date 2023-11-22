# 一个简单实用类似JWT的token
借鉴gtoken思路 在此感谢gtoken
使用方法
一、gf框架
    TokenObj :=NewGtoken("admin")
    token,err:= TokenObj.Generate(ctx,"用户名或者ID","用户数据")