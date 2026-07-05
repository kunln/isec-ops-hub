/**
 * Agent 描述在界面上的本地化展示。
 * - description：英文，用于委派提示、工具上下文等（与 SKILL.md 等默认英文约定一致）
 * - descriptionCn：中文，用于中文界面展示
 */

function isChineseLocale(language?: string): boolean {
  if (!language) return false;
  return language.toLowerCase().replace('_', '-').startsWith('zh');
}

export function getAgentDisplayDescription(
  agent: { description?: string; descriptionCn?: string } | null | undefined,
  language?: string,
): string {
  if (!agent) return '';
  const en = (agent.description ?? '').trim();
  const cn = (agent.descriptionCn ?? '').trim();
  return isChineseLocale(language) ? (cn || en) : (en || cn);
}
