// Mirrors the correctness and readability rules of bitsentry-monorepo's scripts/eslint/create-config.mjs; edit both together.
import sonarjs from "eslint-plugin-sonarjs";
import unicorn from "eslint-plugin-unicorn";

// Correctness: catch dead code, lost error causes, and impossible control flow.
const correctnessRules = {
  "array-callback-return": "error",
  "default-case-last": "error",
  "no-constructor-return": "error",
  "no-empty": "error",
  "no-self-compare": "error",
  "no-sequences": "error",
  "no-throw-literal": "error",
  "no-unmodified-loop-condition": "error",
  "no-unreachable-loop": "error",
  "no-useless-assignment": "error",
  "no-useless-catch": "error",
  "preserve-caught-error": "error",
  "prefer-promise-reject-errors": "error",
  radix: "error",
  "require-yield": "error",
  "@typescript-eslint/no-loop-func": "error",
  "@typescript-eslint/no-non-null-assertion": "error",
  "@typescript-eslint/no-unused-vars": [
    "error",
    {
      argsIgnorePattern: "^_",
      caughtErrors: "none",
      destructuredArrayIgnorePattern: "^_",
      ignoreRestSiblings: true,
      varsIgnorePattern: "^_",
    },
  ],
  "unicorn/error-message": "error",
  "unicorn/no-instanceof-array": "error",
  "unicorn/prefer-number-properties": "error",
  "unicorn/throw-new-error": "error",
};

// Readability: one obvious way to express a branch, loop, or lookup.
const readabilityRules = {
  "no-case-declarations": "error",
  "no-else-return": "error",
  "no-implicit-coercion": "error",
  "no-lonely-if": "error",
  "no-return-assign": "error",
  "no-unneeded-ternary": "error",
  "no-useless-computed-key": "error",
  "no-useless-concat": "error",
  "no-useless-escape": "error",
  "no-useless-rename": "error",
  "no-useless-return": "error",
  "object-shorthand": "error",
  "prefer-arrow-callback": ["error", { allowNamedFunctions: true }],
  "prefer-const": "error",
  "prefer-exponentiation-operator": "error",
  "prefer-object-spread": "error",
  "@typescript-eslint/consistent-generic-constructors": "error",
  "@typescript-eslint/default-param-last": "error",
  "@typescript-eslint/no-confusing-non-null-assertion": "error",
  "@typescript-eslint/no-empty-object-type": "error",
  "@typescript-eslint/no-inferrable-types": "error",
  "@typescript-eslint/no-useless-empty-export": "error",
  "@typescript-eslint/prefer-for-of": "error",
  "@typescript-eslint/prefer-function-type": "error",
  "sonarjs/cognitive-complexity": ["error", 15],
  "sonarjs/no-nested-conditional": "error",
  "unicorn/no-unnecessary-boolean-comparison": "error",
  "unicorn/no-unreadable-iife": "error",
  "unicorn/no-useless-boolean-cast": "error",
  "unicorn/no-useless-fallback-in-spread": "error",
  "unicorn/no-useless-promise-resolve-reject": "error",
  "unicorn/no-useless-switch-case": "error",
  "unicorn/no-zero-fractions": "error",
  "unicorn/prefer-array-find": "error",
  "unicorn/prefer-array-flat": "error",
  "unicorn/prefer-array-flat-map": "error",
  "unicorn/prefer-array-index-of": "error",
  "unicorn/prefer-array-some": "error",
  "unicorn/prefer-date-now": "error",
  "unicorn/prefer-default-parameters": "error",
  "unicorn/prefer-else-if": "error",
  "unicorn/prefer-includes": "error",
  "unicorn/prefer-logical-operator-over-ternary": "error",
  "unicorn/prefer-optional-catch-binding": "error",
  "unicorn/prefer-regexp-test": "error",
  "unicorn/prefer-single-call": "error",
  "unicorn/prefer-string-slice": "error",
  "unicorn/prefer-string-starts-ends-with": "error",
};

/** The shared correctness and readability rules for TypeScript files; tests may use non-null assertions. */
export function readabilityConfigs({
  files = ["**/*.{ts,tsx,mts,cts}"],
  testFiles = [
    "**/*.{spec,test}.{ts,tsx,mts,cts}",
    "**/{test,tests,__tests__}/**/*.{ts,tsx,mts,cts}",
  ],
} = {}) {
  return [
    {
      files,
      plugins: { sonarjs, unicorn },
      rules: { ...correctnessRules, ...readabilityRules },
    },
    {
      files: testFiles,
      rules: { "@typescript-eslint/no-non-null-assertion": "off" },
    },
  ];
}
