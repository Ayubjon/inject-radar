// Detection rules for prompt-injection patterns. Each rule matches against the
// NORMALIZED text (lowercased, de-obfuscated by src/normalize.js), so patterns
// are written in lowercase ASCII. Rules are intentionally conservative to keep
// false positives low; tune weights to shift the aggregate score.

export const SEVERITY_WEIGHT = {
  low: 8,
  medium: 15,
  high: 25,
  critical: 40,
};

/**
 * @typedef {Object} Rule
 * @property {string} id
 * @property {string} category
 * @property {'low'|'medium'|'high'|'critical'} severity
 * @property {RegExp} pattern
 * @property {string} description
 */

/** @type {Rule[]} */
export const RULES = [
  // --- instruction override -------------------------------------------------
  {
    id: 'override.ignore-previous',
    category: 'instruction-override',
    severity: 'high',
    pattern: /\b(ignore|disregard|forget)\b[^.]{0,40}\b(previous|prior|above|earlier|all)\b[^.]{0,30}\b(instruction|instructions|prompt|prompts|message|messages|direction|directions|rule|rules|context)\b/,
    description: 'Attempts to discard earlier instructions or context.',
  },
  {
    id: 'override.new-instructions',
    category: 'instruction-override',
    severity: 'medium',
    pattern: /\b(new|updated|real|actual)\s+(instructions?|rules?|task|directive)s?\s*[:\-]/,
    description: 'Introduces a competing set of "new" instructions.',
  },
  {
    id: 'override.from-now-on',
    category: 'instruction-override',
    severity: 'low',
    pattern: /\bfrom now on\b[^.]{0,40}\b(you|respond|answer|ignore|only)\b/,
    description: 'Redefines future behavior ("from now on you ...").',
  },

  // --- role-play / jailbreak ------------------------------------------------
  {
    id: 'jailbreak.persona',
    category: 'jailbreak',
    severity: 'high',
    pattern: /\byou are (now )?(dan\b|do anything now|an? (unrestricted|unfiltered|uncensored|jailbroken))/,
    description: 'Classic persona-swap jailbreak (DAN / unrestricted AI).',
  },
  {
    id: 'jailbreak.developer-mode',
    category: 'jailbreak',
    severity: 'high',
    pattern: /\b(enable|enter|activate|turn on)\b[^.]{0,20}\bdeveloper mode\b/,
    description: 'Requests a fictitious unrestricted "developer mode".',
  },
  {
    id: 'jailbreak.pretend',
    category: 'jailbreak',
    severity: 'medium',
    pattern: /\b(pretend|imagine|roleplay|role-play|act as)\b[^.]{0,40}\b(no (rules|restrictions|limits|filters)|unrestricted|jailbroken|without (any )?(rules|restrictions|limits|filters|guidelines))\b/,
    description: 'Role-play framing used to escape guardrails.',
  },

  // --- refusal suppression --------------------------------------------------
  {
    id: 'suppress.no-refuse',
    category: 'refusal-suppression',
    severity: 'medium',
    pattern: /\b(do not|don't|never|you (must|can)not)\b[^.]{0,20}\b(refuse|decline|warn|apolog\w*|say no)\b/,
    description: 'Pressures the model to never refuse or warn.',
  },
  {
    id: 'suppress.bypass-safety',
    category: 'refusal-suppression',
    severity: 'high',
    pattern: /\b(bypass|disable|ignore|turn off|remove)\b[^.]{0,25}\b(safety|content (policy|filter)|filters?|guidelines?|guardrails?|restrictions?|moderation|ethics?|ethical)\b/,
    description: 'Asks to disable safety / content filters.',
  },

  // --- system prompt leak ---------------------------------------------------
  {
    id: 'leak.reveal-system-prompt',
    category: 'system-prompt-leak',
    severity: 'high',
    pattern: /\b(reveal|show|print|repeat|output|display|reproduce|tell me|give me)\b[^.]{0,30}\b(system prompt|initial prompt|original prompt|your (instructions|prompt|rules)|prompt above|the prompt)\b/,
    description: 'Tries to extract the hidden system prompt.',
  },
  {
    id: 'leak.repeat-above',
    category: 'system-prompt-leak',
    severity: 'high',
    pattern: /\brepeat\b[^.]{0,20}\b(the )?(words?|text|everything|content)\b[^.]{0,15}\b(above|before|prior)\b/,
    description: 'Asks the model to echo prior hidden context verbatim.',
  },

  // --- data exfiltration ----------------------------------------------------
  {
    id: 'exfil.send-to',
    category: 'exfiltration',
    severity: 'critical',
    pattern: /\b(send|post|upload|exfiltrate|forward|leak|email)\b[^.]{0,40}\b(to )?(https?:\/\/|http\b|api key|secret|password|token|credential)/,
    description: 'Instructs sending secrets or data to an external destination.',
  },
  {
    id: 'exfil.include-secret',
    category: 'exfiltration',
    severity: 'high',
    pattern: /\b(include|append|attach|embed|reveal)\b[^.]{0,25}\b(api[ _-]?key|secret|password|access token|bearer token|private key)\b/,
    description: 'Requests embedding secrets in the response.',
  },

  // --- tool / code execution abuse -----------------------------------------
  {
    id: 'exec.shell',
    category: 'code-execution',
    severity: 'critical',
    pattern: /(\brm\s+-rf\b|\bcurl\b[^|]{0,80}\|\s*(sh|bash)\b|\b(os\.system|subprocess\.(run|popen|call)|child_process|eval\()|>\s*\/dev\/null)/,
    description: 'Embeds shell / code-execution payloads.',
  },
  {
    id: 'exec.run-command',
    category: 'code-execution',
    severity: 'medium',
    pattern: /\b(run|execute|exec)\b[^.]{0,25}\b(the following|this|below|command|shell|script|code)\b/,
    description: 'Asks the model/agent to run arbitrary commands.',
  },

  // --- delimiter / control-token injection ----------------------------------
  {
    id: 'inject.control-tokens',
    category: 'delimiter-injection',
    severity: 'high',
    pattern: /<\|(im_start|im_end|system|endoftext|assistant|user)\|>|<\/?system>|\[\/?(system|inst)\]|\bend of (system )?prompt\b/,
    description: 'Injects chat control tokens or fake role delimiters.',
  },

  // --- encoding-based smuggling --------------------------------------------
  {
    id: 'encode.respond-in-base64',
    category: 'obfuscation',
    severity: 'medium',
    pattern: /\b(decode|respond|reply|answer|encode)\b[^.]{0,25}\b(in |the following |this )?base64\b/,
    description: 'Uses base64 to smuggle or hide instructions.',
  },
];

export default RULES;
