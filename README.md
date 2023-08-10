# glados-checkin-ql

### 适配青龙面板

### 自动化签到

**注册方法**
1. 注册GLaDOS(注册地址在 https://github.com/glados-network/GLaDOS 实时更新)

成功后输入邀请码:DMEV9-19W1H-59R0V-B3P3X 激活

2. 通过 https://glados.space/landing/DMEV9-19W1H-59R0V-B3P3X 注册, 自动填写激活

3. 通过 https://dmev9-19w1h-59r0v-b3p3x.glados.space , 自动填写激活


**脚本地址** 
```text
ql repo https://github.com/wxmbaci/glados-checkin-ql.git "glados_checkin"
```
---
**变量声明**

```shell
变量名: GLADOS_CK 参数: glados cookie


变量名: QL_PORT 参数: 端口号(int) 
# 修改过面板端口的人才需要填写 默认 5700 
# 是本地的端口 不是 Docker 映射出去的端口! 如果你映射参数是 8888:5700 仍然填写5700

```

---
参考
[https://github.com/Zy143L/wskey](https://github.com/Zy143L/wskey)
