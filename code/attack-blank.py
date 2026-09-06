def attack(env) -> None:
    """检索投毒账户注入（KBPoisoningAttack）。

    参数
    ----
    env : 评测环境对象，暴露 env.attacker_account 与 env.set_kb。

    返回
    ----
    None（注入结果写入环境；可通过 env.inject_stats 与知识库内容查看）。
    """
    pass
