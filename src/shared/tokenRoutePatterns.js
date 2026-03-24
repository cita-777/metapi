let nextNodeId = 1;

function createNode(type, fields = {}) {
  return {
    id: nextNodeId++,
    type,
    ...fields,
  };
}

function isDigitCharacter(ch) {
  if (!ch) return false;
  const code = ch.charCodeAt(0);
  return code >= 48 && code <= 57;
}

function readRegexQuantifierLength(pattern, startIndex) {
  const ch = pattern[startIndex];
  if (ch === '*' || ch === '+' || ch === '?') return 1;
  if (ch !== '{') return 0;

  let index = startIndex + 1;
  let sawDigit = false;
  while (index < pattern.length && isDigitCharacter(pattern[index])) {
    sawDigit = true;
    index += 1;
  }
  if (!sawDigit) return 0;
  if (pattern[index] === ',') {
    index += 1;
    while (index < pattern.length && isDigitCharacter(pattern[index])) {
      index += 1;
    }
  }
  if (pattern[index] !== '}') return 0;
  return index - startIndex + 1;
}

function isAllowedSafeRegexCharacter(ch) {
  if (!ch) return false;
  const code = ch.charCodeAt(0);
  const isLowerAlpha = code >= 97 && code <= 122;
  const isUpperAlpha = code >= 65 && code <= 90;
  const isDigit = code >= 48 && code <= 57;
  if (isLowerAlpha || isUpperAlpha || isDigit) return true;
  return ' .^$|()[]{}+*?\\:_/-'.includes(ch);
}

function hasUnsafeRegexBackreference(body) {
  for (let index = 0; index < body.length; index += 1) {
    if (body[index] !== '\\') continue;
    const prev = index > 0 ? body[index - 1] : '';
    const next = body[index + 1];
    if (prev !== '\\' && isDigitCharacter(next) && next !== '0') {
      return true;
    }
  }
  return false;
}

function isSafeRegexPatternBody(body) {
  if (!body || body.length > 256) return false;
  for (const ch of body) {
    if (!isAllowedSafeRegexCharacter(ch)) return false;
  }
  if (
    body.includes('(?=')
    || body.includes('(?!')
    || body.includes('(?<=')
    || body.includes('(?<!')
    || body.includes('(?<')
  ) {
    return false;
  }
  if (hasUnsafeRegexBackreference(body)) {
    return false;
  }

  const groupStack = [];
  let escaped = false;
  let inCharClass = false;
  for (let index = 0; index < body.length; index += 1) {
    const ch = body[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      const next = body[index + 1];
      if (!next) return false;
      if (/[a-z]/i.test(next) && next !== 'd') {
        return false;
      }
      escaped = true;
      continue;
    }
    if (inCharClass) {
      if (ch === ']') inCharClass = false;
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    if (ch === '(') {
      if (body[index + 1] === '?') {
        return false;
      }
      groupStack.push({ hasInnerQuantifier: false, hasAlternation: false });
      continue;
    }
    if (ch === '|') {
      if (groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasAlternation = true;
      }
      continue;
    }
    if (ch === ')') {
      const group = groupStack.pop();
      if (!group) return false;
      const quantifierLength = readRegexQuantifierLength(body, index + 1);
      if (quantifierLength > 0 && (group.hasInnerQuantifier || group.hasAlternation)) {
        return false;
      }
      const parent = groupStack[groupStack.length - 1];
      if (parent && (group.hasInnerQuantifier || quantifierLength > 0)) {
        parent.hasInnerQuantifier = true;
      }
      continue;
    }
    const quantifierLength = readRegexQuantifierLength(body, index);
    if (quantifierLength > 0) {
      if (groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasInnerQuantifier = true;
      }
      index += quantifierLength - 1;
    }
  }
  return !escaped && !inCharClass && groupStack.length === 0;
}

function matchesGlobPattern(model, pattern) {
  let modelIndex = 0;
  let patternIndex = 0;
  let starIndex = -1;
  let matchIndex = 0;

  while (modelIndex < model.length) {
    const patternChar = pattern[patternIndex];
    const modelChar = model[modelIndex];
    if (patternChar === '*' ) {
      starIndex = patternIndex;
      matchIndex = modelIndex;
      patternIndex += 1;
      continue;
    }
    if (patternChar === '?' || patternChar === modelChar) {
      patternIndex += 1;
      modelIndex += 1;
      continue;
    }
    if (starIndex === -1) {
      return false;
    }
    patternIndex = starIndex + 1;
    matchIndex += 1;
    modelIndex = matchIndex;
  }

  while (pattern[patternIndex] === '*') {
    patternIndex += 1;
  }

  return patternIndex === pattern.length;
}

function toArraySet(values) {
  const unique = [];
  for (const value of values) {
    if (!unique.includes(value)) unique.push(value);
  }
  return unique;
}

function parseCharClassChar(body, state) {
  const ch = body[state.index];
  if (ch === '\\') {
    state.index += 1;
    const escaped = body[state.index];
    if (!escaped) throw new Error('invalid escape');
    state.index += 1;
    if (escaped === 'd') return { kind: 'digit' };
    return { kind: 'char', value: escaped };
  }
  if (!ch) throw new Error('invalid char class');
  state.index += 1;
  return { kind: 'char', value: ch };
}

function parseCharClass(body, state) {
  state.index += 1;
  let negated = false;
  if (body[state.index] === '^') {
    negated = true;
    state.index += 1;
  }

  const entries = [];
  while (state.index < body.length && body[state.index] !== ']') {
    const start = parseCharClassChar(body, state);
    if (body[state.index] === '-' && body[state.index + 1] && body[state.index + 1] !== ']') {
      state.index += 1;
      const end = parseCharClassChar(body, state);
      entries.push({ kind: 'range', start, end });
      continue;
    }
    entries.push(start);
  }

  if (body[state.index] !== ']' || entries.length === 0) {
    throw new Error('invalid character class');
  }
  state.index += 1;
  return createNode('charclass', { negated, entries });
}

function parseAtom(body, state) {
  const ch = body[state.index];
  if (!ch) throw new Error('unexpected end');

  if (ch === '(') {
    state.index += 1;
    const group = parseExpression(body, state, ')');
    if (body[state.index] !== ')') {
      throw new Error('missing )');
    }
    state.index += 1;
    return group;
  }
  if (ch === '[') {
    return parseCharClass(body, state);
  }
  if (ch === '.') {
    state.index += 1;
    return createNode('any');
  }
  if (ch === '\\') {
    state.index += 1;
    const escaped = body[state.index];
    if (!escaped) throw new Error('invalid escape');
    state.index += 1;
    if (escaped === 'd') {
      return createNode('digit');
    }
    return createNode('literal', { value: escaped });
  }

  state.index += 1;
  return createNode('literal', { value: ch });
}

function parseQuantifier(body, state) {
  const ch = body[state.index];
  if (ch === '*') {
    state.index += 1;
    return { min: 0, max: Infinity };
  }
  if (ch === '+') {
    state.index += 1;
    return { min: 1, max: Infinity };
  }
  if (ch === '?') {
    state.index += 1;
    return { min: 0, max: 1 };
  }
  if (ch !== '{') return null;

  let index = state.index + 1;
  let minText = '';
  while (index < body.length && isDigitCharacter(body[index])) {
    minText += body[index];
    index += 1;
  }
  if (!minText) return null;

  let max = Number.parseInt(minText, 10);
  if (body[index] === ',') {
    index += 1;
    let maxText = '';
    while (index < body.length && isDigitCharacter(body[index])) {
      maxText += body[index];
      index += 1;
    }
    max = maxText ? Number.parseInt(maxText, 10) : Infinity;
  }
  if (body[index] !== '}') return null;
  state.index = index + 1;
  return {
    min: Number.parseInt(minText, 10),
    max,
  };
}

function parseTerm(body, state) {
  const atom = parseAtom(body, state);
  const quantifier = parseQuantifier(body, state);
  if (!quantifier) return atom;
  return createNode('repeat', {
    atom,
    min: quantifier.min,
    max: quantifier.max,
  });
}

function parseSequence(body, state, stopChar) {
  const terms = [];
  while (state.index < body.length) {
    const ch = body[state.index];
    if (ch === '|' || ch === stopChar) break;
    terms.push(parseTerm(body, state));
  }
  if (terms.length === 0) {
    return createNode('empty');
  }
  if (terms.length === 1) return terms[0];
  return createNode('sequence', { terms });
}

function parseExpression(body, state, stopChar = '') {
  const branches = [parseSequence(body, state, stopChar)];
  while (state.index < body.length && body[state.index] === '|') {
    state.index += 1;
    branches.push(parseSequence(body, state, stopChar));
  }
  if (branches.length === 1) return branches[0];
  return createNode('alternation', { branches });
}

function charMatchesCharClassEntry(entry, ch) {
  if (entry.kind === 'digit') return isDigitCharacter(ch);
  if (entry.kind === 'char') return ch === entry.value;
  if (entry.kind === 'range') {
    if (entry.start.kind !== 'char' || entry.end.kind !== 'char') {
      return false;
    }
    const code = ch.charCodeAt(0);
    return code >= entry.start.value.charCodeAt(0) && code <= entry.end.value.charCodeAt(0);
  }
  return false;
}

function matchNode(node, value, position, cache) {
  const cacheKey = `${node.id}:${position}`;
  const cached = cache.get(cacheKey);
  if (cache.has(cacheKey)) return cached;

  let result = [];
  switch (node.type) {
    case 'empty':
      result = [position];
      break;
    case 'literal':
      result = value.startsWith(node.value, position) ? [position + node.value.length] : [];
      break;
    case 'any':
      result = position < value.length ? [position + 1] : [];
      break;
    case 'digit':
      result = position < value.length && isDigitCharacter(value[position]) ? [position + 1] : [];
      break;
    case 'charclass': {
      if (position < value.length) {
        const matched = node.entries.some((entry) => charMatchesCharClassEntry(entry, value[position]));
        if ((matched && !node.negated) || (!matched && node.negated)) {
          result = [position + 1];
        }
      }
      break;
    }
    case 'sequence': {
      let positions = [position];
      for (const term of node.terms) {
        const nextPositions = [];
        for (const current of positions) {
          nextPositions.push(...matchNode(term, value, current, cache));
        }
        positions = toArraySet(nextPositions);
        if (positions.length === 0) break;
      }
      result = positions;
      break;
    }
    case 'alternation': {
      const positions = [];
      for (const branch of node.branches) {
        positions.push(...matchNode(branch, value, position, cache));
      }
      result = toArraySet(positions);
      break;
    }
    case 'repeat': {
      let results = node.min === 0 ? [position] : [];
      let frontier = [position];
      const maxRepeat = Number.isFinite(node.max) ? node.max : (value.length - position + 1);
      for (let count = 1; count <= maxRepeat; count += 1) {
        const nextPositions = [];
        for (const current of frontier) {
          const ends = matchNode(node.atom, value, current, cache);
          for (const end of ends) {
            if (end !== current) nextPositions.push(end);
          }
        }
        frontier = toArraySet(nextPositions);
        if (frontier.length === 0) break;
        if (count >= node.min) {
          results = toArraySet([...results, ...frontier]);
        }
      }
      result = results;
      break;
    }
    default:
      result = [];
      break;
  }

  cache.set(cacheKey, result);
  return result;
}

function compileSafeRegexPattern(body) {
  nextNodeId = 1;
  const anchoredStart = body.startsWith('^');
  const anchoredEnd = body.endsWith('$') && body[body.length - 2] !== '\\';
  const normalizedBody = body
    .slice(anchoredStart ? 1 : 0, anchoredEnd ? -1 : body.length)
    .trim();
  const state = { index: 0 };
  const root = parseExpression(normalizedBody, state);
  if (state.index !== normalizedBody.length) {
    throw new Error('unsupported regex syntax');
  }

  return {
    test(value) {
      const starts = anchoredStart
        ? [0]
        : Array.from({ length: value.length + 1 }, (_, index) => index);
      for (const start of starts) {
        const ends = matchNode(root, value, start, new Map());
        if (!anchoredEnd && ends.length > 0) return true;
        if (anchoredEnd && ends.includes(value.length)) return true;
      }
      return false;
    },
  };
}

const matchCache = new Map();
const MATCH_CACHE_LIMIT = 4000;

export function isTokenRouteRegexPattern(pattern) {
  return pattern.trim().toLowerCase().startsWith('re:');
}

export function isExactTokenRouteModelPattern(pattern) {
  const normalized = pattern.trim();
  if (!normalized) return false;
  if (isTokenRouteRegexPattern(normalized)) return false;
  return !/[\*\?]/.test(normalized);
}

export function parseTokenRouteRegexPattern(pattern) {
  if (!isTokenRouteRegexPattern(pattern)) {
    return { regex: null, error: null };
  }
  const body = pattern.trim().slice(3).trim();
  if (!body) {
    return { regex: null, error: 're: 后缺少正则表达式' };
  }
  if (!isSafeRegexPatternBody(body)) {
    return { regex: null, error: '出于安全原因不支持该正则表达式' };
  }
  try {
    return {
      regex: compileSafeRegexPattern(body),
      error: null,
    };
  } catch (error) {
    return { regex: null, error: error?.message || '无效正则' };
  }
}

export function matchesTokenRouteModelPattern(model, pattern) {
  const normalized = (pattern || '').trim();
  if (!normalized) return false;
  if (normalized === model) return true;

  const cacheKey = `${model}\0${normalized}`;
  const cached = matchCache.get(cacheKey);
  if (cached !== undefined) return cached;

  let result;
  if (isTokenRouteRegexPattern(normalized)) {
    const parsed = parseTokenRouteRegexPattern(normalized);
    result = !!parsed.regex && parsed.regex.test(model);
  } else {
    result = matchesGlobPattern(model, normalized);
  }

  if (matchCache.size >= MATCH_CACHE_LIMIT) {
    matchCache.clear();
  }
  matchCache.set(cacheKey, result);
  return result;
}
