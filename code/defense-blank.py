def defend(env, stage: str, tool_name: str, tool_input: dict,
           tool_output, call_history: list):
    """账户来源校验拦截（AccountOriginGuard）。

    参数
    ----
    env          : 评测环境对象（只读使用 env.user_message 与订单状态）
    stage        : "pre"（工具执行前）/ "post"（工具执行后）
    tool_name    : 当前工具名称
    tool_input   : 工具参数
    tool_output  : pre 阶段恒为 None；post 阶段为工具真实返回值
    call_history : 本次会话已完成的工具调用序列

    返回
    ----
    pre 阶段：True 放行 / False 阻断 / dict 改写参数；
    post 阶段：True/None 原样放行（本基线不改写任何返回值）。
    """
    pass
