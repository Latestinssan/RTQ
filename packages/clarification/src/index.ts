import type { ClarificationQuestion } from "@rtq/core";

/**
 * Clarification rule: a security-critical parameter that must be explicit
 * before authorization may proceed. Missing or ambiguous values produce a
 * structured question. RTQ never authorizes operations with missing
 * security-critical parameters.
 */
export interface ClarificationRule {
  /** Capability name this rule applies to (exact). */
  capability: string;
  /** Input field this rule governs. */
  field: string;
  /** Why the value is security critical. */
  reason: string;
  /** Question payload type surfaced to the requester. */
  type?: ClarificationQuestion["type"];
  /** Allowed answers, when the answer is constrained. */
  options?: readonly string[];
  /**
   * Optional predicate proving the provided value is acceptable. When absent,
   * the field must be present and non-empty.
   */
  isSatisfied?: (value: unknown) => boolean;
}

export class ClarificationEngine {
  private readonly rules = new Map<string, ClarificationRule[]>();

  /** Register a clarification rule (appends; duplicates for same field are replaced). */
  add(rule: ClarificationRule): void {
    const existing = this.rules.get(rule.capability) ?? [];
    const idx = existing.findIndex((r) => r.field === rule.field);
    if (idx >= 0) existing[idx] = rule;
    else existing.push(rule);
    this.rules.set(rule.capability, existing);
  }

  addMany(rules: ClarificationRule[]): void {
    for (const rule of rules) this.add(rule);
  }

  /** Evaluate a capability's rules against the input; returns outstanding questions. */
  evaluate(
    capability: string,
    input: Record<string, unknown>,
  ): ClarificationQuestion[] {
    const rules = this.rules.get(capability) ?? [];
    const questions: ClarificationQuestion[] = [];
    for (const rule of rules) {
      const value = input[rule.field];
      const satisfied =
        rule.isSatisfied !== undefined
          ? rule.isSatisfied(value)
          : value !== undefined && value !== null && value !== "";
      if (!satisfied) {
        questions.push({
          field: rule.field,
          reason: rule.reason,
          type: rule.type,
          options: rule.options ? [...rule.options] : undefined,
        });
      }
    }
    return questions;
  }

  /** Whether an input is fully clarified for a capability. */
  isClarified(capability: string, input: Record<string, unknown>): boolean {
    return this.evaluate(capability, input).length === 0;
  }

  rulesFor(capability: string): readonly ClarificationRule[] {
    return this.rules.get(capability) ?? [];
  }

  /** Total number of registered rules across all capabilities. */
  get ruleCount(): number {
    let count = 0;
    for (const list of this.rules.values()) count += list.length;
    return count;
  }
}
