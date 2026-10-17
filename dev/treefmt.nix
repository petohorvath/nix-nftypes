{
  programs = {
    nixfmt.enable = true;
    deadnix = {
      enable = true;
      # The DSL builders rely on argument patterns without `...`, which
      # reject unnamed arguments; `--edit` would drop the unused names.
      no-lambda-pattern-names = true;
    };
    actionlint.enable = true;
    prettier.enable = true;
    shfmt.enable = true;
    shellcheck.enable = true;
    ruff-format.enable = true;
    ruff-check.enable = true;
  };
}
