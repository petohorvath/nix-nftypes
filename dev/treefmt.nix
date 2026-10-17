{
  programs = {
    nixfmt.enable = true;
    deadnix = {
      enable = true;
      # Attrset patterns without `...`, such as the DSL builders' arguments,
      # declare which arguments a function accepts; `--edit` would drop the
      # unused names and reject callers that pass them.
      no-lambda-pattern-names = true;
    };
    actionlint.enable = true;
    prettier = {
      enable = true;
      settings = {
        proseWrap = "preserve";
        printWidth = 100;
      };
    };
    shfmt.enable = true;
    shellcheck.enable = true;
    ruff-format.enable = true;
    ruff-check.enable = true;
  };
}
