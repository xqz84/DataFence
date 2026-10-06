import type { AiAnalysis } from "./types";

/** Provider labels describe configuration, never proof of call success. */
export function providerName(provider?: string): string {
  if (provider === "sensenova") return "商汤 SenseNova";
  if (provider === "ollama") return "Ollama 本地服务";
  return "语言模型";
}

export function analysisStatus(
  analysis?: Pick<AiAnalysis, "status" | "provider" | "reason_code">,
): string {
  if (!analysis) return "历史记录无模型分析";
  if (analysis.status === "unavailable") {
    if (analysis.reason_code === "budget_exhausted")
      return "预算不足 · 本次未调用";
    if (analysis.reason_code === "circuit_open") return "调用暂时熔断 · 已降级";
    if (analysis.reason_code === "context_too_large")
      return "上下文超限 · 本次未调用";
  }
  const labels: Record<AiAnalysis["status"], string> = {
    not_configured: "LLM 未配置",
    skipped: "本次未触发模型分析",
    completed: `${providerName(analysis.provider)} · 分析已完成`,
    unavailable: "模型调用失败 · 已降级",
    invalid_response: "模型输出无效 · 已降级",
  };
  return labels[analysis.status];
}

export function reasonLabel(code?: string | null): string {
  if (!code) return "未提供原因";
  const reasons: Record<string, string> = {
    budget_exhausted: "本地调用预算不足，未发送请求",
    circuit_open: "近期调用异常，服务暂时熔断",
    context_too_large: "分析上下文超过限制，未发送请求",
    authentication_failed: "服务端认证失败",
    permission_denied: "当前凭据没有访问权限",
    rate_limited: "提供商限制请求频率",
    provider_http_error: "提供商接口暂时无法处理请求",
    timeout: "连接或模型推理超时",
    connection_failed: "无法连接模型接口",
    schema_rejected: "输出未通过结构或证据校验",
    incomplete_response: "模型输出未完整结束",
    override_rejected: "模型建议试图覆盖已有阻断，已拒绝",
    unauthorized_tools: "输出包含未授权工具调用，已拒绝",
    invalid_content_type: "响应内容格式不符合约束",
    compressed_response: "响应使用了不支持的压缩格式",
    response_too_large: "响应超过允许大小",
    sensitive_response: "响应内容未通过安全约束",
    contract_mismatch: "事件与分析结果不匹配",
    not_configured: "服务配置不完整，未发送请求",
    below_threshold: "未达到高风险解释阈值",
    demo_local_mode: "完整演示使用本地检测，本次未调用云模型",
    skipped: "本次跳过模型分析，未调用",
    ok: "分析完成且通过输出校验",
  };
  return reasons[code] || code;
}
