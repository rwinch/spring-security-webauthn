import globals from "globals";
import eslintConfigPrettier from "eslint-plugin-prettier/recommended";

export default [
  {
    ignores: ["dist/*"],
  },
  {
    files: ["lib/**/*.js"],
    languageOptions: {
      sourceType: "module",
      globals: {
        ...globals.browser,
        gobalThis: "readonly",
      },
    },
  },
  {
    files: ["test/**/*.js"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.mocha,
        ...globals.chai,
        ...globals.nodeBuiltin,
      },
    },
  },
  eslintConfigPrettier,
];
