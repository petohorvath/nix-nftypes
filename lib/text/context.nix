/*
  Render-context threaded through every text renderer.

  Fields:
    depth       — current indentation depth (in `indentUnit`s).
    pretty      — when true, emit newlines between statements/objects and
                  indent brace bodies. When false, emit a compact form
                  (single-line per command, `; ` between statements).
    block       — when true, object headers omit the `<family> <table>`
                  scope prefix (the enclosing `table { ... }` block
                  implies it). Used by toTextBlock to render the inside
                  of a table block. Default false preserves the
                  imperative-form behavior of toText/toTextPretty.
    parentPrec  — operator precedence of the enclosing expression. Used by
                  binary-op renderers to decide whether to parenthesize.
                  Higher number = tighter binding. 0 means "top level, no
                  parens needed".
    family      — the family of the rule whose statements are rendering,
                  or null outside a rule. NAT checks it against its own.
*/
{ lib }:

let
  indentUnit = "  ";

  mkCtx =
    {
      pretty ? true,
      block ? false,
      depth ? 0,
      parentPrec ? 0,
      family ? null,
    }:
    {
      inherit
        pretty
        block
        depth
        family
        parentPrec
        ;
    };

  withDepth = ctx: ctx // { depth = ctx.depth + 1; };
  withPrec = prec: ctx: ctx // { parentPrec = prec; };
  resetPrec = ctx: ctx // { parentPrec = 0; };
  withFamily = family: ctx: ctx // { inherit family; };

  # Indentation string for the current depth. Empty in compact mode.
  indent = ctx: if ctx.pretty then lib.strings.replicate ctx.depth indentUnit else "";
in
{
  inherit
    indent
    indentUnit
    mkCtx
    resetPrec
    withDepth
    withFamily
    withPrec
    ;
}
